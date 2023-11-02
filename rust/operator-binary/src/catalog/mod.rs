pub mod black_hole;
pub mod commons;
pub mod config;
pub mod generic;
pub mod google_sheet;
pub mod hive;
pub mod iceberg;
pub mod tpcds;
pub mod tpch;

use self::config::CatalogConfig;
use async_trait::async_trait;
use snafu::Snafu;
use stackable_operator::client::Client;

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum FromTrinoCatalogError {
    #[snafu(display("object has no namespace"))]
    ObjectHasNoNamespace,

    #[snafu(display("failed to resolve S3ConnectionDef"))]
    ResolveS3ConnectionDef {
        source: stackable_operator::error::Error,
    },

    #[snafu(display("trino does not support disabling the TLS verification of S3 servers"))]
    S3TlsNoVerificationNotSupported,

    #[snafu(display("trino catalog has no name set"))]
    InvalidCatalogSpec,

    #[snafu(display("failed to resolve [{catalog}] discovery config map [{cm_name}]"))]
    FailedToGetDiscoveryConfigMap {
        source: stackable_operator::error::Error,
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
