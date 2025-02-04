pub mod black_hole;
pub mod commons;
pub mod config;
pub mod delta_lake;
pub mod generic;
pub mod google_sheet;
pub mod hive;
pub mod iceberg;
pub mod tpcds;
pub mod tpch;

use async_trait::async_trait;
use snafu::Snafu;
use stackable_operator::{
    client::Client,
    commons::{s3::S3Error, tls_verification::TlsClientDetailsError},
};

use self::config::CatalogConfig;

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum FromTrinoCatalogError {
    #[snafu(display("object has no namespace"))]
    ObjectHasNoNamespace,

    #[snafu(display("failed to configure S3 connection"))]
    ConfigureS3 { source: S3Error },

    #[snafu(display("failed to configure S3 TLS client details"))]
    ConfigureS3TlsClientDetails { source: TlsClientDetailsError },

    #[snafu(display("trino does not support disabling the TLS verification of S3 servers"))]
    S3TlsNoVerificationNotSupported,

    #[snafu(display("trino catalog has no name set"))]
    InvalidCatalogSpec,

    #[snafu(display("failed to resolve [{catalog}] discovery config map [{cm_name}]"))]
    FailedToGetDiscoveryConfigMap {
        source: stackable_operator::client::Error,
        catalog: String,
        cm_name: String,
    },

    #[snafu(display(
        "failed to retrieve [{catalog}] discovery config map [{cm_name}] data field"
    ))]
    FailedToGetDiscoveryConfigMapData { catalog: String, cm_name: String },

    #[snafu(display(
        "failed to retrieve [{catalog}] discovery config map [{cm_name}] data key [{data_key}]"
    ))]
    FailedToGetDiscoveryConfigMapDataKey {
        catalog: String,
        cm_name: String,
        data_key: String,
    },

    #[snafu(display("Failed to create the Secret Volume for the S3 credentials"))]
    CreateS3CredentialsSecretOperatorVolume {
        source: stackable_operator::builder::pod::volume::SecretOperatorVolumeSourceBuilderError,
    },
}

#[async_trait]
pub trait ToCatalogConfig {
    async fn to_catalog_config(
        &self,
        catalog_name: &str,
        catalog_namespace: Option<String>,
        client: &Client,
    ) -> Result<CatalogConfig, FromTrinoCatalogError>;
}

#[async_trait]
pub trait ExtendCatalogConfig {
    async fn extend_catalog_config(
        &self,
        catalog_config: &mut CatalogConfig,
        catalog_name: &str,
        catalog_namespace: Option<String>,
        client: &Client,
    ) -> Result<(), FromTrinoCatalogError>;
}
