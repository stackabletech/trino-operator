// Consolidate Trino S3 properties in a single reusable struct.

use std::collections::BTreeMap;

use snafu::{self, ResultExt, Snafu};
use stackable_operator::{
    client::Client,
    k8s_openapi::api::core::v1::{Volume, VolumeMount},
};

use crate::{
    config,
    crd::{
        ENV_SPOOLING_SECRET,
        client_protocol::{ClientProtocolConfig, SpoolingFileSystemConfig},
    },
};

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("Failed to resolve S3 connection"))]
    ResolveS3Connection { source: config::s3::Error },

    #[snafu(display("trino does not support disabling the TLS verification of S3 servers"))]
    S3TlsNoVerificationNotSupported,

    #[snafu(display("failed to convert data size for [{field}] to bytes"))]
    QuantityConversion {
        source: stackable_operator::memory::Error,
        field: &'static str,
    },
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
                            let resolved_s3_config = config::s3::ResolvedS3Config::from_config(
                                s3_config, client, namespace,
                            )
                            .await
                            .context(ResolveS3ConnectionSnafu)?;

                            // Enable S3 filesystem after successful resolution
                            resolved_config
                                .spooling_manager_properties
                                .insert("fs.s3.enabled".to_string(), "true".to_string());

                            // Copy the S3 configuration over
                            resolved_config
                                .spooling_manager_properties
                                .extend(resolved_s3_config.properties);
                            resolved_config.volumes.extend(resolved_s3_config.volumes);
                            resolved_config
                                .volume_mounts
                                .extend(resolved_s3_config.volume_mounts);
                            resolved_config
                                .init_container_extra_start_commands
                                .extend(resolved_s3_config.init_container_extra_start_commands);
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
                        format!("${{ENV:{ENV_SPOOLING_SECRET}}}"),
                    ),
                ]);
            }
        }

        Ok(resolved_config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_spooling_config() {
        let config_yaml = indoc::indoc! {r#"
            spooling:
              location: s3://my-bucket/spooling
              filesystem:
                s3:
                  reference: test-s3-connection
        "#};

        let deserializer = serde_yaml::Deserializer::from_str(config_yaml);
        let config = serde_yaml::with::singleton_map_recursive::deserialize(deserializer)
            .expect("invalid test input");

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
