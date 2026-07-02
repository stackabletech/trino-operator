use async_trait::async_trait;
use snafu::{OptionExt, ResultExt, ensure};
use stackable_operator::{
    builder::pod::volume::{VolumeBuilder, VolumeMountBuilder},
    client::Client,
    crd::s3,
    k8s_openapi::api::core::v1::ConfigMap,
    v2::types::kubernetes::NamespaceName,
};

use super::{
    ExtendCatalogConfig, FromTrinoCatalogError,
    config::CatalogConfig,
    from_trino_catalog_error::{
        ConfigureS3Snafu, FailedToGetDiscoveryConfigMapDataKeySnafu,
        FailedToGetDiscoveryConfigMapDataSnafu, FailedToGetDiscoveryConfigMapSnafu,
        S3TlsNoVerificationNotSupportedSnafu, S3TlsRequiredSnafu,
    },
};
use crate::{
    config,
    crd::{
        CONFIG_DIR_NAME,
        catalog::commons::{HdfsConnection, MetastoreConnection},
    },
};

#[async_trait]
impl ExtendCatalogConfig for MetastoreConnection {
    async fn extend_catalog_config(
        &self,
        catalog_config: &mut CatalogConfig,
        catalog_name: &str,
        catalog_namespace: &NamespaceName,
        client: &Client,
        _trino_version: u16,
    ) -> Result<(), FromTrinoCatalogError> {
        let hive_cm: ConfigMap = client
            .get(self.config_map.as_ref(), catalog_namespace.as_ref())
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
impl ExtendCatalogConfig for s3::v1alpha1::InlineConnectionOrReference {
    async fn extend_catalog_config(
        &self,
        catalog_config: &mut CatalogConfig,
        _catalog_name: &str,
        catalog_namespace: &NamespaceName,
        client: &Client,
        _trino_version: u16,
    ) -> Result<(), FromTrinoCatalogError> {
        let s3 = self
            .clone()
            .resolve(client, catalog_namespace.as_ref())
            .await
            .context(ConfigureS3Snafu)?;

        let (volumes, mounts) = s3.volumes_and_mounts().context(ConfigureS3Snafu)?;
        catalog_config.volumes.extend(volumes);
        catalog_config.volume_mounts.extend(mounts);

        catalog_config.add_property("fs.native-s3.enabled", "true");
        catalog_config.add_property("s3.endpoint", s3.endpoint().context(ConfigureS3Snafu)?);
        catalog_config.add_property("s3.region", &s3.region.name);
        catalog_config.add_property(
            "s3.path-style-access",
            (s3.access_style == s3::v1alpha1::S3AccessStyle::Path).to_string(),
        );

        if let Some((access_key, secret_key)) = s3.credentials_mount_paths() {
            catalog_config.add_env_property_from_file("s3.aws-access-key", access_key);
            catalog_config.add_env_property_from_file("s3.aws-secret-key", secret_key);
        }

        // TLS is required when using native S3 implementation.
        ensure!(s3.tls.uses_tls(), S3TlsRequiredSnafu);

        catalog_config.init_container_extra_start_commands.extend(
            config::s3::s3_tls_truststore_commands(&s3.tls)
                .map_err(|_| S3TlsNoVerificationNotSupportedSnafu.build())?,
        );

        Ok(())
    }
}

#[async_trait]
impl ExtendCatalogConfig for HdfsConnection {
    async fn extend_catalog_config(
        &self,
        catalog_config: &mut CatalogConfig,
        catalog_name: &str,
        _catalog_namespace: &NamespaceName,
        _client: &Client,
        _trino_version: u16,
    ) -> Result<(), FromTrinoCatalogError> {
        // Since Trino 458, fs.hadoop.enabled defaults to false.
        catalog_config.add_property("fs.hadoop.enabled", "true");

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
