use async_trait::async_trait;
use stackable_operator::{client::Client, v2::types::kubernetes::NamespaceName};

use super::{FromTrinoCatalogError, ToCatalogConfig, config::CatalogConfig};
use crate::{controller::dereference::TrinoCatalogName, crd::catalog::tpch::TpchConnector};

pub const CONNECTOR_NAME: &str = "tpch";

#[async_trait]
impl ToCatalogConfig for TpchConnector {
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
