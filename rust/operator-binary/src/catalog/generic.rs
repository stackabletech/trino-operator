use async_trait::async_trait;
use stackable_operator::client::Client;
use stackable_trino_crd::catalog::generic::{GenericConnector, Property};

use crate::trino_version::TrinoVersion;

use super::{config::CatalogConfig, FromTrinoCatalogError, ToCatalogConfig};

#[async_trait]
impl ToCatalogConfig for GenericConnector {
    async fn to_catalog_config(
        &self,
        catalog_name: &str,
        _catalog_namespace: Option<String>,
        _client: &Client,
        _trino_version: &TrinoVersion,
    ) -> Result<CatalogConfig, FromTrinoCatalogError> {
        let connector_name = &self.connector_name;
        let mut config = CatalogConfig::new(catalog_name.to_string(), connector_name);

        for (property_name, property) in &self.properties {
            match property {
                Property::Value(value) => config.add_property(property_name, value),
                Property::ValueFromSecret {
                    secret_key_selector,
                } => {
                    config.add_env_property_from_secret(property_name, secret_key_selector.clone())
                }
                Property::ValueFromConfigMap {
                    config_map_key_selector,
                } => config.add_env_property_from_config_map(
                    property_name,
                    config_map_key_selector.clone(),
                ),
            }
        }

        Ok(config)
    }
}
