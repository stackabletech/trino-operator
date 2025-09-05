use std::collections::BTreeMap;

/// This module manages the client protocol properties, especially the for spooling.
/// Trino documentation is available here: https://trino.io/docs/current/client/client-protocol.html
use serde::{Deserialize, Serialize};
use snafu::Snafu;
use stackable_operator::{
    client::Client,
    commons::tls_verification::{CaCert, TlsServerVerification, TlsVerification},
    crd::s3,
    k8s_openapi::{
        api::core::v1::{Volume, VolumeMount},
        apimachinery::pkg::api::resource::Quantity,
    },
    schemars::{self, JsonSchema},
};

use crate::{
    command,
    crd::{ENV_SPOOLING_SECRET, STACKABLE_CLIENT_TLS_DIR},
};

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ClientProtocolConfig {
    Spooling(ClientSpoolingProtocolConfig),
}
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientSpoolingProtocolConfig {
    // Spool segment location. Each Trino cluster must have its own
    // location independent of any other clusters.
    pub location: String,

    // Spooling filesystem properties. Only S3 is supported.
    pub filesystem: SpoolingFileSystemConfig,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SpoolingFileSystemConfig {
    S3(S3SpoolingConfig),
}
// TODO: this is exactly the same as fault_tolerant_execution::S3ExchangeConfig
// but without the base_directory property.
// Consolidate Trino S3 properties in a single reusable struct.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct S3SpoolingConfig {
    /// S3 connection configuration.
    /// Learn more about S3 configuration in the [S3 concept docs](DOCS_BASE_URL_PLACEHOLDER/concepts/s3).
    pub connection: stackable_operator::crd::s3::v1alpha1::InlineConnectionOrReference,

    /// IAM role to assume for S3 access.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iam_role: Option<String>,

    /// External ID for the IAM role trust policy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,

    /// Maximum number of times the S3 client should retry a request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_error_retries: Option<u32>,

    /// Part data size for S3 multi-part upload.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upload_part_size: Option<Quantity>,
}

pub struct ResolvedClientProtocolConfig {
    /// Properties to add to config.properties
    pub config_properties: BTreeMap<String, String>,

    // Properties for spooling-manager.properties
    pub spooling_manager_properties: BTreeMap<String, String>,

    /// Volumes required for the configuration (e.g., for S3 credentials)
    pub volumes: Vec<Volume>,

    /// Volume mounts required for the configuration
    pub volume_mounts: Vec<VolumeMount>,

    /// Additional commands that need to be executed before starting Trino
    /// Used to add TLS certificates to the client's trust store.
    pub init_container_extra_start_commands: Vec<String>,
}

impl ResolvedClientProtocolConfig {
    /// Resolve S3 connection properties from Kubernetes resources
    /// and prepare spooling filesystem configuration.
    pub async fn from_config(
        config: &ClientProtocolConfig,
        client: Option<&Client>,
        namespace: &str,
    ) -> Result<Self, Error> {
        let mut resolved_config = Self {
            config_properties: BTreeMap::new(),
            spooling_manager_properties: BTreeMap::new(),
            volumes: Vec::new(),
            volume_mounts: Vec::new(),
            init_container_extra_start_commands: Vec::new(),
        };

        match config {
            ClientProtocolConfig::Spooling(spooling_config) => {
                // Resolve external resources if Kubernetes client is available
                // This should always be the case, except for when this function is called during unit tests
                if let Some(client) = client {
                    match &spooling_config.filesystem {
                        SpoolingFileSystemConfig::S3(s3_config) => {
                            resolved_config
                                .resolve_s3_backend(s3_config, client, namespace)
                                .await?;
                        }
                    }
                }

                resolved_config.spooling_manager_properties.extend([
                    ("fs.location".to_string(), spooling_config.location.clone()),
                    (
                        "spooling-manager.name".to_string(),
                        "filesystem".to_string(),
                    ),
                ]);

                // Enable spooling protocol
                resolved_config.config_properties.extend([
                    ("protocol.spooling.enabled".to_string(), "true".to_string()),
                    (
                        "protocol.spooling.shared-secret-key".to_string(),
                        format!("${{ENV:{secret}}}", secret = ENV_SPOOLING_SECRET),
                    ),
                ]);
            }
        }

        Ok(resolved_config)
    }

    async fn resolve_s3_backend(
        &mut self,
        s3_config: &S3SpoolingConfig,
        client: &Client,
        namespace: &str,
    ) -> Result<(), Error> {
        use snafu::ResultExt;

        let s3_connection = s3_config
            .connection
            .clone()
            .resolve(client, namespace)
            .await
            .context(S3ConnectionSnafu)?;

        let (volumes, mounts) = s3_connection
            .volumes_and_mounts()
            .context(S3ConnectionSnafu)?;
        self.volumes.extend(volumes);
        self.volume_mounts.extend(mounts);

        self.spooling_manager_properties
            .insert("s3.region".to_string(), s3_connection.region.name.clone());
        self.spooling_manager_properties.insert(
            "s3.endpoint".to_string(),
            s3_connection
                .endpoint()
                .context(S3ConnectionSnafu)?
                .to_string(),
        );
        self.spooling_manager_properties.insert(
            "s3.path-style-access".to_string(),
            (s3_connection.access_style == s3::v1alpha1::S3AccessStyle::Path).to_string(),
        );

        if let Some((access_key_path, secret_key_path)) = s3_connection.credentials_mount_paths() {
            self.spooling_manager_properties.extend([
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
                        self.init_container_extra_start_commands.extend(
                            command::add_cert_to_truststore(
                                &ca_cert,
                                STACKABLE_CLIENT_TLS_DIR,
                                "spooling-s3-ca-cert",
                            ),
                        );
                    }
                }
            }
        }

        // Enable S3 filesystem after successful resolution
        self.spooling_manager_properties
            .insert("fs.s3.enabled".to_string(), "true".to_string());

        Ok(())
    }
}

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("Failed to resolve S3 connection"))]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_spooling_config() {
        let config = ClientProtocolConfig::Spooling(ClientSpoolingProtocolConfig {
            location: "s3://my-bucket/spooling".to_string(),
            filesystem: SpoolingFileSystemConfig::S3(S3SpoolingConfig {
                connection:
                    stackable_operator::crd::s3::v1alpha1::InlineConnectionOrReference::Reference(
                        "test-s3-connection".to_string(),
                    ),
                iam_role: None,
                external_id: None,
                max_error_retries: None,
                upload_part_size: None,
            }),
        });

        let resolved_spooling_config = ResolvedClientProtocolConfig::from_config(
            &config, None, // No client, so no external resolution
            "default",
        )
        .await
        .unwrap();

        let expected_props = BTreeMap::from([
            (
                "fs.location".to_string(),
                "s3://my-bucket/spooling".to_string(),
            ),
            (
                "spooling-manager.name".to_string(),
                "filesystem".to_string(),
            ),
        ]);
        assert_eq!(
            expected_props,
            resolved_spooling_config.spooling_manager_properties
        );
    }
}
