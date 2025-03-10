use async_trait::async_trait;
use stackable_operator::client::Client;

use super::{config::CatalogConfig, FromTrinoCatalogError, ToCatalogConfig};
use crate::crd::catalog::black_hole::BlackHoleConnector;

pub const CONNECTOR_NAME: &str = "blackhole";

#[async_trait]
impl ToCatalogConfig for BlackHoleConnector {
    async fn to_catalog_config(
        &self,
        catalog_name: &str,
        _catalog_namespace: Option<String>,
        _client: &Client,
        _trino_version: u16,
    ) -> Result<CatalogConfig, FromTrinoCatalogError> {
        // No additional properties needed
        Ok(CatalogConfig::new(catalog_name.to_string(), CONNECTOR_NAME))
    }
}
