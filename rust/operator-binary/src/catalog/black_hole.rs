use async_trait::async_trait;
use stackable_operator::client::Client;
use stackable_trino_crd::catalog::black_hole::BlackHoleConnector;

use crate::trino_version::TrinoVersion;

use super::{config::CatalogConfig, FromTrinoCatalogError, ToCatalogConfig};

pub const CONNECTOR_NAME: &str = "blackhole";

#[async_trait]
impl ToCatalogConfig for BlackHoleConnector {
    async fn to_catalog_config(
        &self,
        catalog_name: &str,
        _catalog_namespace: Option<String>,
        _client: &Client,
        _trino_version: &TrinoVersion,
    ) -> Result<CatalogConfig, FromTrinoCatalogError> {
        // No additional properties needed
        Ok(CatalogConfig::new(catalog_name.to_string(), CONNECTOR_NAME))
    }
}
