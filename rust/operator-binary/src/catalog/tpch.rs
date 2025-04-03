use async_trait::async_trait;
use stackable_operator::client::Client;

use super::{FromTrinoCatalogError, ToCatalogConfig, config::CatalogConfig};
use crate::crd::catalog::tpch::TpchConnector;

pub const CONNECTOR_NAME: &str = "tpch";

#[async_trait]
impl ToCatalogConfig for TpchConnector {
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
