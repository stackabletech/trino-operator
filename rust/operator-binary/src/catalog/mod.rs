pub mod commons;
pub mod config;
pub mod hive;
pub mod iceberg;

use self::config::CatalogConfig;
use async_trait::async_trait;
use snafu::Snafu;
use stackable_operator::client::Client;

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum FromTrinoCatalogError {
    #[snafu(display("failed to resolve S3ConnectionDef"))]
    ResolveS3ConnectionDef {
        source: stackable_operator::error::Error,
    },
    #[snafu(display("trino does not support disabling the TLS verification of S3 servers"))]
    S3TlsNoVerificationNotSupported,
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
