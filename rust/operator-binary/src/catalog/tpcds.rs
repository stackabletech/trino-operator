use async_trait::async_trait;
use stackable_operator::client::Client;

use super::{config::CatalogConfig, FromTrinoCatalogError, ToCatalogConfig};
use crate::crd::catalog::tpcds::TpcdsConnector;

pub const CONNECTOR_NAME: &str = "tpcds";

#[async_trait]
impl ToCatalogConfig for TpcdsConnector {
    async fn to_catalog_config(
        &self,
        catalog_name: &str,
        _catalog_namespace: Option<String>,
        _client: &Client,
    ) -> Result<CatalogConfig, FromTrinoCatalogError> {
        // No additional properties needed
        Ok(CatalogConfig::new(catalog_name.to_string(), CONNECTOR_NAME))
    }
}
