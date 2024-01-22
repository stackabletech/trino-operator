use crate::command;

use async_trait::async_trait;
use snafu::{OptionExt, ResultExt};
use stackable_operator::{
    builder::{SecretOperatorVolumeSourceBuilder, VolumeBuilder, VolumeMountBuilder},
    client::Client,
    commons::authentication::tls::{CaCert, TlsServerVerification, TlsVerification},
    commons::s3::{S3AccessStyle, S3ConnectionDef},
    k8s_openapi::api::core::v1::ConfigMap,
};
use stackable_trino_crd::catalog::commons::{HdfsConnection, MetastoreConnection};
use stackable_trino_crd::{
    CONFIG_DIR_NAME, S3_SECRET_DIR_NAME, STACKABLE_CLIENT_TLS_DIR, STACKABLE_MOUNT_CLIENT_TLS_DIR,
};

use super::{
    config::CatalogConfig,
    from_trino_catalog_error::{
        CreateS3CredentialsSecretOperatorVolumeSnafu, CreateS3TLSSecretOperatorVolumeSnafu,
        FailedToGetDiscoveryConfigMapDataKeySnafu, FailedToGetDiscoveryConfigMapDataSnafu,
        FailedToGetDiscoveryConfigMapSnafu, ObjectHasNoNamespaceSnafu, ResolveS3ConnectionDefSnafu,
        S3TlsNoVerificationNotSupportedSnafu,
    },
    ExtendCatalogConfig, FromTrinoCatalogError,
};

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
impl ExtendCatalogConfig for S3ConnectionDef {
    async fn extend_catalog_config(
        &self,
        catalog_config: &mut CatalogConfig,
        catalog_name: &str,
        catalog_namespace: Option<String>,
        client: &Client,
    ) -> Result<(), FromTrinoCatalogError> {
        let s3 = self
            .resolve(
                client,
                catalog_namespace
                    .as_deref()
                    .context(ObjectHasNoNamespaceSnafu)?,
            )
            .await
            .context(ResolveS3ConnectionDefSnafu)?;

        if let Some(endpoint) = s3.endpoint() {
            catalog_config.add_property("hive.s3.endpoint", endpoint)
        }
        if let Some(S3AccessStyle::Path) = s3.access_style {
            catalog_config.add_property("hive.s3.path-style-access", true.to_string())
        }

        if let Some(credentials) = s3.credentials {
            let secret_class = credentials.secret_class;
            let volume_name = format!("{catalog_name}-{secret_class}");
            let volume_mount_path = format!("{S3_SECRET_DIR_NAME}/{catalog_name}/{secret_class}");
            catalog_config.volumes.push(
                VolumeBuilder::new(&volume_name)
                    .ephemeral(
                        SecretOperatorVolumeSourceBuilder::new(&secret_class)
                            .build()
                            .context(CreateS3CredentialsSecretOperatorVolumeSnafu)?,
                    )
                    .build(),
            );
            catalog_config
                .volume_mounts
                .push(VolumeMountBuilder::new(&volume_name, &volume_mount_path).build());

            catalog_config.add_env_property_from_file(
                "hive.s3.aws-access-key",
                format!("{volume_mount_path}/accessKey"),
            );
            catalog_config.add_env_property_from_file(
                "hive.s3.aws-secret-key",
                format!("{volume_mount_path}/secretKey"),
            );
        }

        catalog_config.add_property("hive.s3.ssl.enabled", s3.tls.is_some().to_string());
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
                    let volume_name = format!("{catalog_name}-{secret_class}-ca-cert");
                    let volume_mount_path =
                        format!("{STACKABLE_MOUNT_CLIENT_TLS_DIR}/{catalog_name}/{secret_class}");
                    catalog_config.volumes.push(
                        VolumeBuilder::new(&volume_name)
                            .ephemeral(
                                SecretOperatorVolumeSourceBuilder::new(secret_class)
                                    .build()
                                    .context(CreateS3TLSSecretOperatorVolumeSnafu)?,
                            )
                            .build(),
                    );
                    catalog_config
                        .volume_mounts
                        .push(VolumeMountBuilder::new(&volume_name, &volume_mount_path).build());

                    // Copy the ca.crt from the ca-cert secretclass into truststore for external services
                    catalog_config.init_container_extra_start_commands.extend(
                        command::add_cert_to_truststore(
                            format!("{volume_mount_path}/ca.crt").as_str(),
                            STACKABLE_CLIENT_TLS_DIR,
                            &volume_name,
                        ),
                    );
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
