use std::collections::BTreeMap;

use snafu::{ResultExt, Snafu};
use stackable_operator::{
    client::Client,
    commons::tls_verification::{CaCert, TlsServerVerification, TlsVerification},
    crd::s3,
    k8s_openapi::api::core::v1::{Volume, VolumeMount},
};

use crate::{command, crd::STACKABLE_CLIENT_TLS_DIR};

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("failed to resolve S3 connection"))]
    S3Connection {
        source: s3::v1alpha1::ConnectionError,
    },

    #[snafu(display("trino does not support disabling the TLS verification of S3 servers"))]
    S3TlsNoVerificationNotSupported,

    #[snafu(display("failed to convert data size for [{field}] to bytes"))]
    QuantityConversion {
        source: stackable_operator::memory::Error,
        field: &'static str,
    },
}

pub struct ResolvedS3Config {
    /// Properties to add to config.properties
    pub properties: BTreeMap<String, String>,

    /// Volumes required for the configuration (e.g., for S3 credentials)
    pub volumes: Vec<Volume>,

    /// Volume mounts required for the configuration
    pub volume_mounts: Vec<VolumeMount>,

    /// Additional commands that need to be executed before starting Trino
    /// Used to add TLS certificates to the client's trust store.
    pub init_container_extra_start_commands: Vec<String>,
}

impl ResolvedS3Config {
    /// Resolve S3 connection properties from Kubernetes resources
    /// and prepare spooling filesystem configuration.
    pub async fn from_config(
        connection: &stackable_operator::crd::s3::v1alpha1::InlineConnectionOrReference,
        client: &Client,
        namespace: &str,
    ) -> Result<Self, Error> {
        let mut resolved_config = Self {
            properties: BTreeMap::new(),
            volumes: Vec::new(),
            volume_mounts: Vec::new(),
            init_container_extra_start_commands: Vec::new(),
        };

        let s3_connection = connection
            .clone()
            .resolve(client, namespace)
            .await
            .context(S3ConnectionSnafu)?;

        let (volumes, mounts) = s3_connection
            .volumes_and_mounts()
            .context(S3ConnectionSnafu)?;
        resolved_config.volumes.extend(volumes);
        resolved_config.volume_mounts.extend(mounts);

        resolved_config
            .properties
            .insert("s3.region".to_string(), s3_connection.region.name.clone());
        resolved_config.properties.insert(
            "s3.endpoint".to_string(),
            s3_connection
                .endpoint()
                .context(S3ConnectionSnafu)?
                .to_string(),
        );
        resolved_config.properties.insert(
            "s3.path-style-access".to_string(),
            (s3_connection.access_style == s3::v1alpha1::S3AccessStyle::Path).to_string(),
        );

        if let Some((access_key_path, secret_key_path)) = s3_connection.credentials_mount_paths() {
            resolved_config.properties.extend([
                (
                    "s3.aws-access-key".to_string(),
                    format!("${{file:UTF-8:{access_key_path}}}"),
                ),
                (
                    "s3.aws-secret-key".to_string(),
                    format!("${{file:UTF-8:{secret_key_path}}}"),
                ),
            ]);
        }

        if let Some(tls) = s3_connection.tls.tls.as_ref() {
            match &tls.verification {
                TlsVerification::None {} => return S3TlsNoVerificationNotSupportedSnafu.fail(),
                TlsVerification::Server(TlsServerVerification {
                    ca_cert: CaCert::WebPki {},
                }) => {}
                TlsVerification::Server(TlsServerVerification {
                    ca_cert: CaCert::SecretClass(_),
                }) => {
                    if let Some(ca_cert) = s3_connection.tls.tls_ca_cert_mount_path() {
                        resolved_config.init_container_extra_start_commands.extend(
                            command::add_cert_to_truststore(&ca_cert, STACKABLE_CLIENT_TLS_DIR),
                        );
                    }
                }
            }
        }

        Ok(resolved_config)
    }
}
