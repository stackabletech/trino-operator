use async_trait::async_trait;
use snafu::{OptionExt, ResultExt};
use stackable_operator::{
    builder::pod::volume::{VolumeBuilder, VolumeMountBuilder},
    client::Client,
    commons::{
        s3::{S3AccessStyle, S3ConnectionInlineOrReference},
        tls_verification::{CaCert, TlsServerVerification, TlsVerification},
    },
    k8s_openapi::api::core::v1::ConfigMap,
};
use stackable_trino_crd::{
    catalog::commons::{HdfsConnection, MetastoreConnection},
    CONFIG_DIR_NAME, STACKABLE_CLIENT_TLS_DIR,
};

use super::{
    config::CatalogConfig,
    from_trino_catalog_error::{
        ConfigureS3Snafu, FailedToGetDiscoveryConfigMapDataKeySnafu,
        FailedToGetDiscoveryConfigMapDataSnafu, FailedToGetDiscoveryConfigMapSnafu,
        ObjectHasNoNamespaceSnafu, S3TlsNoVerificationNotSupportedSnafu,
    },
    ExtendCatalogConfig, FromTrinoCatalogError,
};
use crate::command;

#[async_trait]
impl ExtendCatalogConfig for MetastoreConnection {
    async fn extend_catalog_config(
        &self,
        catalog_config: &mut CatalogConfig,
        catalog_name: &str,
        catalog_namespace: Option<String>,
        client: &Client,
    ) -> Result<(), FromTrinoCatalogError> {
        let hive_cm: ConfigMap = client
            .get(
                &self.config_map,
                catalog_namespace
                    .as_deref()
                    .context(ObjectHasNoNamespaceSnafu)?,
            )
            .await
            .with_context(|_| FailedToGetDiscoveryConfigMapSnafu {
                catalog: catalog_name.to_string(),
                cm_name: self.config_map.to_string(),
            })?;

        let data_key = "HIVE";
        let hive_connection = hive_cm
            .data
            .as_ref()
            .with_context(|| FailedToGetDiscoveryConfigMapDataSnafu {
                catalog: catalog_name.to_string(),
                cm_name: self.config_map.to_string(),
            })?
            .get(data_key)
            .with_context(|| FailedToGetDiscoveryConfigMapDataKeySnafu {
                catalog: catalog_name.to_string(),
                cm_name: self.config_map.to_string(),
                data_key: data_key.to_string(),
            })?;

        // This is tightly coupled with the hive discovery config map data layout now
        let transformed_hive_connection = hive_connection.replace('\n', ",");

        catalog_config.add_property("hive.metastore.uri", transformed_hive_connection);

        Ok(())
    }
}

#[async_trait]
impl ExtendCatalogConfig for S3ConnectionInlineOrReference {
    async fn extend_catalog_config(
        &self,
        catalog_config: &mut CatalogConfig,
        catalog_name: &str,
        catalog_namespace: Option<String>,
        client: &Client,
    ) -> Result<(), FromTrinoCatalogError> {
        let s3 = self
            .clone()
            .resolve(
                client,
                catalog_namespace
                    .as_deref()
                    .context(ObjectHasNoNamespaceSnafu)?,
            )
            .await
            .context(ConfigureS3Snafu)?;

        catalog_config.add_property("hive.s3.endpoint", s3.endpoint().context(ConfigureS3Snafu)?);
        catalog_config.add_property(
            "hive.s3.path-style-access",
            (s3.access_style == S3AccessStyle::Path).to_string(),
        );

        let (volumes, mounts) = s3.volumes_and_mounts().context(ConfigureS3Snafu)?;
        catalog_config.volumes.extend(volumes);
        catalog_config.volume_mounts.extend(mounts);

        if let Some((access_key, secret_key)) = s3.credentials_mount_paths() {
            catalog_config.add_env_property_from_file("hive.s3.aws-access-key", access_key);
            catalog_config.add_env_property_from_file("hive.s3.aws-secret-key", secret_key);
        }

        catalog_config.add_property("hive.s3.ssl.enabled", s3.tls.uses_tls().to_string());
        if let Some(tls) = s3.tls.tls.as_ref() {
            match &tls.verification {
                TlsVerification::None {} => return S3TlsNoVerificationNotSupportedSnafu.fail(),
                TlsVerification::Server(TlsServerVerification {
                    ca_cert: CaCert::WebPki {},
                }) => {}
                TlsVerification::Server(TlsServerVerification {
                    ca_cert: CaCert::SecretClass(_),
                }) => {
                    if let Some(ca_cert) = s3.tls.tls_ca_cert_mount_path() {
                        catalog_config.init_container_extra_start_commands.extend(
                            command::add_cert_to_truststore(
                                &ca_cert,
                                STACKABLE_CLIENT_TLS_DIR,
                                &format!("{catalog_name}-ca-cert"),
                            ),
                        );
                    }
                }
            }
        }

        Ok(())
    }
}

#[async_trait]
impl ExtendCatalogConfig for HdfsConnection {
    async fn extend_catalog_config(
        &self,
        catalog_config: &mut CatalogConfig,
        catalog_name: &str,
        _catalog_namespace: Option<String>,
        _client: &Client,
    ) -> Result<(), FromTrinoCatalogError> {
        let hdfs_site_dir = format!("{CONFIG_DIR_NAME}/catalog/{catalog_name}/hdfs-config");
        catalog_config.add_property(
            "hive.config.resources",
            format!("{hdfs_site_dir}/core-site.xml,{hdfs_site_dir}/hdfs-site.xml"),
        );

        let volume_name = format!("{catalog_name}-hdfs");
        catalog_config.volumes.push(
            VolumeBuilder::new(&volume_name)
                .with_config_map(&self.config_map)
                .build(),
        );
        catalog_config
            .volume_mounts
            .push(VolumeMountBuilder::new(&volume_name, &hdfs_site_dir).build());

        Ok(())
    }
}
