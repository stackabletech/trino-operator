use super::{
    config::CatalogConfig,
    from_trino_catalog_error::{ResolveS3ConnectionDefSnafu, S3TlsNoVerificationNotSupportedSnafu},
    FromTrinoCatalogError, ToCatalogConfig,
};
use crate::command;
use async_trait::async_trait;
use snafu::ResultExt;
use stackable_operator::{
    builder::{SecretOperatorVolumeSourceBuilder, VolumeBuilder, VolumeMountBuilder},
    client::Client,
    commons::s3::S3AccessStyle,
    commons::tls::{CaCert, TlsServerVerification, TlsVerification},
};
use stackable_trino_crd::{
    CONFIG_DIR_NAME, STACKABLE_CLIENT_TLS_DIR, STACKABLE_MOUNT_CLIENT_TLS_DIR,
    {catalog::hive::HiveConnector, S3_SECRET_DIR_NAME},
};

pub const CONNECTOR_NAME: &str = "hive";

#[async_trait]
impl ToCatalogConfig for HiveConnector {
    async fn to_catalog_config(
        &self,
        catalog_name: &str,
        catalog_namespace: Option<String>,
        client: &Client,
    ) -> Result<CatalogConfig, FromTrinoCatalogError> {
        let mut config = CatalogConfig::new(catalog_name.to_string(), CONNECTOR_NAME);

        config.add_configmap_property(
            "hive.metastore.uri",
            self.metastore.config_map.clone(),
            "HIVE",
        );

        // No authorization checks are enforced at the catalog level.
        // We don't want the hive connector to prevent users from dropping tables.
        // We also don't want that the hive connector makes decisions on which user is allowed to do what.
        // This decision should be done globally (for all catalogs) by OPA.
        // See https://trino.io/docs/current/connector/hive-security.html
        config.add_property("hive.security", "allow-all");

        if let Some(s3_connection_def) = &self.s3 {
            let s3 = s3_connection_def
                .resolve(client, catalog_namespace.as_deref())
                .await
                .context(ResolveS3ConnectionDefSnafu)?;
            if let Some(endpoint) = s3.endpoint() {
                config.add_property("hive.s3.endpoint", endpoint)
            }
            if let Some(S3AccessStyle::Path) = s3.access_style {
                config.add_property("hive.s3.path-style-access", true.to_string())
            }

            if let Some(credentials) = s3.credentials {
                let secret_class = credentials.secret_class;
                let secret_folder = format!("{S3_SECRET_DIR_NAME}/{secret_class}");
                config.volumes.push(
                    VolumeBuilder::new(&secret_class)
                        .ephemeral(SecretOperatorVolumeSourceBuilder::new(&secret_class).build())
                        .build(),
                );
                config
                    .volume_mounts
                    .push(VolumeMountBuilder::new(&secret_class, &secret_folder).build());

                config.add_env_property_from_file(
                    "hive.s3.aws-access-key",
                    format!("{secret_folder}/accessKey"),
                );
                config.add_env_property_from_file(
                    "hive.s3.aws-secret-key",
                    format!("{secret_folder}/secretKey"),
                );
            }

            config.add_property("hive.s3.ssl.enabled", s3.tls.is_some().to_string());
            if let Some(tls) = s3.tls {
                match &tls.verification {
                    TlsVerification::None {} => return S3TlsNoVerificationNotSupportedSnafu.fail(),
                    TlsVerification::Server(TlsServerVerification {
                        ca_cert: CaCert::WebPki {},
                    }) => {}
                    TlsVerification::Server(TlsServerVerification {
                        ca_cert: CaCert::SecretClass(secret_class),
                    }) => {
                        // Add needed ca-cert secretclass mount
                        let volume_name = format!("{secret_class}-ca-cert");
                        config.volumes.push(
                            VolumeBuilder::new(&volume_name)
                                .ephemeral(
                                    SecretOperatorVolumeSourceBuilder::new(secret_class).build(),
                                )
                                .build(),
                        );
                        config.volume_mounts.push(
                            VolumeMountBuilder::new(&volume_name, STACKABLE_MOUNT_CLIENT_TLS_DIR)
                                .build(),
                        );

                        // Copy the ca.crt from the ca-cert secretclass into truststore for external services
                        config.init_container_extra_start_commands.extend(
                            command::add_cert_to_stackable_truststore(
                                format!("{STACKABLE_MOUNT_CLIENT_TLS_DIR}/ca.crt").as_str(),
                                STACKABLE_CLIENT_TLS_DIR,
                                &volume_name,
                            ),
                        );
                    }
                }
            }
        }

        if let Some(hdfs) = &self.hdfs {
            let hdfs_site_dir = format!("{CONFIG_DIR_NAME}/catalog/{catalog_name}/hdfs-config");
            config.add_property(
                "hive.config.resources",
                format!("{hdfs_site_dir}/hdfs-site.xml"),
            );

            let volume_name = format!("{catalog_name}-hdfs");
            config.volumes.push(
                VolumeBuilder::new(&volume_name)
                    .with_config_map(&hdfs.config_map)
                    .build(),
            );
            config
                .volume_mounts
                .push(VolumeMountBuilder::new(&volume_name, &hdfs_site_dir).build());
        }

        Ok(config)
    }
}
