use async_trait::async_trait;
use stackable_operator::{client::Client, v2::types::kubernetes::NamespaceName};

use crate::{
    catalog::{FromTrinoCatalogError, ToCatalogConfig, config::CatalogConfig},
    crd::catalog::{TrinoCatalogName, black_hole::BlackHoleConnector},
};

pub const CONNECTOR_NAME: &str = "blackhole";

#[async_trait]
impl ToCatalogConfig for BlackHoleConnector {
    async fn to_catalog_config(
        &self,
        catalog_name: &TrinoCatalogName,
        _catalog_namespace: &NamespaceName,
        _client: &Client,
        _trino_version: u16,
    ) -> Result<CatalogConfig, FromTrinoCatalogError> {
        // No additional properties needed
        Ok(CatalogConfig::new(catalog_name, CONNECTOR_NAME))
    }
}
