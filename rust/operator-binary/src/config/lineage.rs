//! Resolves `spec.clusterConfig.lineage` into everything the coordinator needs to run the
//! Trino [OpenLineage](https://openlineage.io/) event listener.
//!
//! Trino ships the OpenLineage event listener as a **core** plugin, so nothing needs to be added
//! to the image; the listener runs on the **coordinator only**. This module produces:
//!
//! * the connection-derived `event-listener.properties` settings (transport type/URL, namespace
//!   and — when authentication is configured — the bearer-token reference),
//! * the Kubernetes [`Volume`]s/[`VolumeMount`]s for the backend CA certificate and the token
//!   Secret, and
//! * the init-container commands that import a `SecretClass` CA into the client truststore.
//!
//! The reusable OpenLineage CRD types (`OpenLineageConnectionSpec`, `InlineConnectionOrReference`,
//! `OpenLineageConfig`) live in [`stackable_operator::crd::openlineage`]; this module only holds the
//! Trino-specific wiring around them.

use std::collections::BTreeMap;

use snafu::{ResultExt, Snafu};
use stackable_operator::{
    client::Client,
    commons::tls_verification::{
        CaCert, TlsClientDetails, TlsClientDetailsError, TlsServerVerification, TlsVerification,
    },
    crd::openlineage::{
        self,
        v1alpha1::{OpenLineageConfig, OpenLineageTransport},
    },
    k8s_openapi::api::core::v1::{SecretVolumeSource, Volume, VolumeMount},
};

use crate::{
    controller::build::command,
    crd::{OPENLINEAGE_AUTH_SECRET_KEY, STACKABLE_CLIENT_TLS_DIR},
};

/// Directory the OpenLineage bearer-token Secret is mounted at on the coordinator. Referenced from
/// the `api-key` property via Trino's `${file:...}` secret placeholder (resolved at startup by
/// `config-utils template`, see [`crate::controller::build::command::container_trino_args`]).
const STACKABLE_OPENLINEAGE_AUTH_DIR: &str = "/stackable/openlineage_auth";

/// Name of the token Secret volume mounted on the coordinator.
const OPENLINEAGE_AUTH_VOLUME_NAME: &str = "openlineage-auth";

// --- `event-listener.properties` keys, see the OpenLineage usage guide ---
// The Trino OpenLineage event listener uses the fixed `openlineage-event-listener.` property prefix
// regardless of the file name. `event-listener.name=openlineage` selects the plugin.

/// Selects the event listener plugin.
pub const EVENT_LISTENER_NAME_KEY: &str = "event-listener.name";
/// The value selecting the OpenLineage event listener plugin.
pub const EVENT_LISTENER_NAME_OPENLINEAGE: &str = "openlineage";
/// OpenLineage transport type key (we always use the HTTP transport).
pub const OPENLINEAGE_TRANSPORT_TYPE_KEY: &str = "openlineage-event-listener.transport.type";
/// The OpenLineage HTTP transport type value.
pub const OPENLINEAGE_TRANSPORT_TYPE_HTTP: &str = "HTTP";
/// OpenLineage HTTP transport base URL key (scheme/host/port of the backend).
pub const OPENLINEAGE_TRANSPORT_URL_KEY: &str = "openlineage-event-listener.transport.url";
/// OpenLineage HTTP transport endpoint path key, set from the connection's `path`.
pub const OPENLINEAGE_TRANSPORT_ENDPOINT_KEY: &str =
    "openlineage-event-listener.transport.endpoint";
/// OpenLineage HTTP transport bearer-token (API key) key. Only set when authentication is
/// configured; the value is a `${file:...}` reference so the token never enters the ConfigMap.
pub const OPENLINEAGE_TRANSPORT_API_KEY_KEY: &str = "openlineage-event-listener.transport.api-key";
/// The OpenLineage namespace lineage is reported under.
pub const OPENLINEAGE_NAMESPACE_KEY: &str = "openlineage-event-listener.namespace";
/// Format for the emitted OpenLineage job name. Set from `spec.clusterConfig.lineage.jobName`.
/// Accepts an arbitrary string with optional `$QUERY_ID`, `$USER`, `$SOURCE` and `$CLIENT_IP`
/// substitution variables (Trino defaults to `$QUERY_ID` when unset).
pub const OPENLINEAGE_JOB_NAME_FORMAT_KEY: &str = "openlineage-event-listener.job.name-format";
/// The URI identifying this Trino cluster in emitted lineage. Computed from the coordinator service
/// at ConfigMap-build time (see [`crate::controller::build::properties::event_listener_properties`]).
pub const OPENLINEAGE_TRINO_URI_KEY: &str = "openlineage-event-listener.trino.uri";

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("failed to resolve the OpenLineage connection"))]
    ResolveConnection {
        source: openlineage::v1alpha1::OpenLineageError,
    },

    #[snafu(display(
        "failed to build volumes and mounts for the OpenLineage backend TLS CA certificate"
    ))]
    TlsVolumesAndMounts { source: TlsClientDetailsError },
}

/// Everything the coordinator needs to run the OpenLineage event listener, resolved from
/// `spec.clusterConfig.lineage` during the dereference step.
#[derive(Clone, Debug)]
pub struct ResolvedLineageConfig {
    /// Connection-derived `event-listener.properties` entries. The cluster-dependent `trino.uri`
    /// is added later by the properties builder.
    pub properties: BTreeMap<String, String>,

    /// Volumes for the backend CA certificate and (when authenticated) the token Secret.
    pub volumes: Vec<Volume>,

    /// Volume mounts matching [`Self::volumes`], to be added to the coordinator container.
    pub volume_mounts: Vec<VolumeMount>,

    /// Commands run in the coordinator prepare container to import a `SecretClass` CA into the
    /// client truststore.
    pub init_container_extra_start_commands: Vec<String>,
}

impl ResolvedLineageConfig {
    /// Resolves the OpenLineage connection (inline or referenced), backend TLS trust and (optional)
    /// authentication into the coordinator-side configuration.
    pub async fn from_config(
        lineage: &OpenLineageConfig,
        client: &Client,
        namespace: &str,
    ) -> Result<Self, Error> {
        let mut properties = BTreeMap::new();
        let mut volumes = Vec::new();
        let mut volume_mounts = Vec::new();
        let mut init_container_extra_start_commands = Vec::new();

        let connection = lineage
            .connection
            .clone()
            .resolve(client, namespace)
            .await
            .context(ResolveConnectionSnafu)?;

        let OpenLineageTransport::Http(http) = &connection.transport;

        properties.insert(
            EVENT_LISTENER_NAME_KEY.to_string(),
            EVENT_LISTENER_NAME_OPENLINEAGE.to_string(),
        );
        properties.insert(
            OPENLINEAGE_TRANSPORT_TYPE_KEY.to_string(),
            OPENLINEAGE_TRANSPORT_TYPE_HTTP.to_string(),
        );
        properties.insert(
            OPENLINEAGE_TRANSPORT_URL_KEY.to_string(),
            http.transport_url(),
        );
        properties.insert(
            OPENLINEAGE_TRANSPORT_ENDPOINT_KEY.to_string(),
            http.path.clone(),
        );
        properties.insert(
            OPENLINEAGE_NAMESPACE_KEY.to_string(),
            lineage.namespace.clone(),
        );

        // The stable OpenLineage job name format. When unset, Trino defaults to `$QUERY_ID`.
        if let Some(job_name) = &lineage.job_name {
            properties.insert(
                OPENLINEAGE_JOB_NAME_FORMAT_KEY.to_string(),
                job_name.clone(),
            );
        }

        // Backend TLS: mount and import a `SecretClass` CA into the client truststore. WebPKI and
        // no verification need nothing (WebPKI is trusted via the system bundle already seeded into
        // the truststore; without server verification the URL is plain `http`).
        let (tls_volumes, tls_mounts) = http
            .tls
            .volumes_and_mounts()
            .context(TlsVolumesAndMountsSnafu)?;
        volumes.extend(tls_volumes);
        volume_mounts.extend(tls_mounts);
        init_container_extra_start_commands.extend(openlineage_tls_truststore_commands(&http.tls));

        // Authentication: when the connection sets `credentialsSecretName`, mount that Secret and
        // reference the token via a `${file:...}` placeholder so it is resolved at startup and never
        // lands in the ConfigMap. The token must be stored under the `apiKey` Secret key.
        if let Some(secret_name) = &http.credentials_secret_name {
            volumes.push(Volume {
                name: OPENLINEAGE_AUTH_VOLUME_NAME.to_string(),
                secret: Some(SecretVolumeSource {
                    secret_name: Some(secret_name.clone()),
                    ..SecretVolumeSource::default()
                }),
                ..Volume::default()
            });
            volume_mounts.push(VolumeMount {
                name: OPENLINEAGE_AUTH_VOLUME_NAME.to_string(),
                mount_path: STACKABLE_OPENLINEAGE_AUTH_DIR.to_string(),
                read_only: Some(true),
                ..VolumeMount::default()
            });
            properties.insert(
                OPENLINEAGE_TRANSPORT_API_KEY_KEY.to_string(),
                format!(
                    "${{file:UTF-8:{STACKABLE_OPENLINEAGE_AUTH_DIR}/{OPENLINEAGE_AUTH_SECRET_KEY}}}"
                ),
            );
        }

        Ok(Self {
            properties,
            volumes,
            volume_mounts,
            init_container_extra_start_commands,
        })
    }
}

/// Init-container commands that add the backend's `SecretClass` CA certificate to the client
/// truststore (which is the JVM default truststore, see `config::jvm`). Returns an empty list when
/// no import is needed: no TLS, `verification.none` (plain `http`), or WebPKI verification (trusted
/// via the seeded system bundle).
fn openlineage_tls_truststore_commands(tls: &TlsClientDetails) -> Vec<String> {
    match tls.tls.as_ref().map(|tls| &tls.verification) {
        Some(TlsVerification::Server(TlsServerVerification {
            ca_cert: CaCert::SecretClass(_),
        })) => tls
            .tls_ca_cert_mount_path()
            .map(|ca_cert| command::add_cert_to_truststore(&ca_cert, STACKABLE_CLIENT_TLS_DIR))
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use stackable_operator::commons::tls_verification::Tls;

    use super::*;

    fn tls_details(verification: Option<TlsVerification>) -> TlsClientDetails {
        TlsClientDetails {
            tls: verification.map(|verification| Tls { verification }),
        }
    }

    #[test]
    fn no_tls_yields_no_truststore_commands() {
        assert!(
            openlineage_tls_truststore_commands(&tls_details(None)).is_empty(),
            "plain http needs no truststore setup"
        );
    }

    #[test]
    fn verification_none_yields_no_truststore_commands() {
        // For OpenLineage `verification.none` means no server verification, i.e. plain http.
        assert!(
            openlineage_tls_truststore_commands(&tls_details(Some(TlsVerification::None {})))
                .is_empty()
        );
    }

    #[test]
    fn webpki_verification_yields_no_truststore_commands() {
        let details = tls_details(Some(TlsVerification::Server(TlsServerVerification {
            ca_cert: CaCert::WebPki {},
        })));
        assert!(openlineage_tls_truststore_commands(&details).is_empty());
    }

    #[test]
    fn secret_class_verification_yields_truststore_commands() {
        let details = tls_details(Some(TlsVerification::Server(TlsServerVerification {
            ca_cert: CaCert::SecretClass("openlineage-tls".to_string()),
        })));
        assert!(!openlineage_tls_truststore_commands(&details).is_empty());
    }
}
