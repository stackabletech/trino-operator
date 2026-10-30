//! Resolves `spec.clusterConfig.lineage` into everything the coordinator needs to run the
//! Trino [OpenLineage](https://openlineage.io/) event listener.
//!
//! Trino ships the OpenLineage event listener as a **core** plugin, so nothing needs to be added
//! to the image; the listener runs on the **coordinator only**. This module produces:
//!
//! * the connection-derived `event-listener.properties` settings (transport type/URL, namespace,
//!   job name format and, when authentication is configured, the bearer-token reference),
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
    commons::tls_verification::TlsClientDetailsError,
    crd::openlineage::{self, v1alpha1::OpenLineageTransport},
    k8s_openapi::api::core::v1::{SecretVolumeSource, Volume, VolumeMount},
};

use crate::{
    config::tls::tls_truststore_commands,
    crd::{OPENLINEAGE_AUTH_SECRET_KEY, v1alpha1::TrinoLineageConfig},
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
/// Format for the emitted OpenLineage job name. Set from
/// `spec.clusterConfig.lineage.jobNameFormat`, which defaults to `$QUERY_ID`.
pub const OPENLINEAGE_JOB_NAME_FORMAT_KEY: &str = "openlineage-event-listener.job.name-format";
/// The URI identifying this Trino cluster in emitted lineage. Trino derives the dataset namespace
/// from it. Set from `spec.clusterConfig.lineage.datasetNamespaceUri`, or the coordinator Service
/// address by default, when the `event-listener.properties` are built.
pub const OPENLINEAGE_TRINO_URI_KEY: &str = "openlineage-event-listener.trino.uri";

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("failed to resolve the OpenLineage connection"))]
    ResolveConnection {
        source: openlineage::v1alpha1::OpenLineageError,
    },

    #[snafu(display("failed to build the OpenLineage HTTP transport URL"))]
    TransportUrl {
        source: openlineage::v1alpha1::OpenLineageError,
    },

    #[snafu(display(
        "failed to build volumes and mounts for the OpenLineage backend TLS CA certificate"
    ))]
    TlsVolumesAndMounts { source: TlsClientDetailsError },

    #[snafu(display(
        "Trino does not support disabling the TLS verification of the OpenLineage backend"
    ))]
    TlsVerificationNotSupported,
}

/// Everything the coordinator needs to run the OpenLineage event listener, resolved from
/// `spec.clusterConfig.lineage` during the dereference step.
#[derive(Clone, Debug)]
pub struct ResolvedLineageConfig {
    /// Connection-derived `event-listener.properties` entries.
    pub properties: BTreeMap<String, String>,

    /// The user-provided `datasetNamespaceUri`, `None` when it is empty or unset. The properties
    /// builder derives `trino.uri` from it, or from the coordinator Service address otherwise.
    pub dataset_namespace_uri: Option<String>,

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
        lineage: &TrinoLineageConfig,
        client: &Client,
        namespace: &str,
    ) -> Result<Self, Error> {
        let mut properties = BTreeMap::new();
        let mut volumes = Vec::new();
        let mut volume_mounts = Vec::new();
        let mut init_container_extra_start_commands = Vec::new();

        let connection = lineage
            .open_lineage
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
        // Trino takes the backend origin and the endpoint path as separate properties.
        let transport_url = http.url().context(TransportUrlSnafu)?;
        properties.insert(
            OPENLINEAGE_TRANSPORT_URL_KEY.to_string(),
            transport_url.origin().ascii_serialization(),
        );
        properties.insert(
            OPENLINEAGE_TRANSPORT_ENDPOINT_KEY.to_string(),
            http.path.clone(),
        );
        properties.insert(
            OPENLINEAGE_NAMESPACE_KEY.to_string(),
            lineage.open_lineage.namespace.clone(),
        );
        properties.insert(
            OPENLINEAGE_JOB_NAME_FORMAT_KEY.to_string(),
            lineage.job_name_format.clone(),
        );

        // Backend TLS: mount and import a `SecretClass` CA into the client truststore. WebPKI needs
        // nothing (it is trusted via the system bundle already seeded into the truststore).
        // Disabling verification is rejected: the listener has no option to skip the certificate
        // check, so the `https` connection would fail its handshake at runtime.
        let (tls_volumes, tls_mounts) = http
            .tls
            .volumes_and_mounts()
            .context(TlsVolumesAndMountsSnafu)?;
        volumes.extend(tls_volumes);
        volume_mounts.extend(tls_mounts);
        init_container_extra_start_commands.extend(
            tls_truststore_commands(&http.tls).map_err(|_| Error::TlsVerificationNotSupported)?,
        );

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

        let dataset_namespace_uri =
            Some(lineage.dataset_namespace_uri.clone()).filter(|uri| !uri.is_empty());

        Ok(Self {
            properties,
            dataset_namespace_uri,
            volumes,
            volume_mounts,
            init_container_extra_start_commands,
        })
    }
}
