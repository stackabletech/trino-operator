use super::{config::CatalogConfig, FromTrinoCatalogError, ToCatalogConfig};
use async_trait::async_trait;
use stackable_operator::client::Client;
use stackable_trino_crd::catalog::generic::GenericConnector;

#[async_trait]
impl ToCatalogConfig for GenericConnector {
    async fn to_catalog_config(
        &self,
        catalog_name: &str,
        _catalog_namespace: Option<String>,
        _client: &Client,
    ) -> Result<CatalogConfig, FromTrinoCatalogError> {
        let connector_name = &self.connector_name;
        let mut config = CatalogConfig::new(catalog_name.to_string(), connector_name);

        for (property, value) in &self.properties {
            config.add_property(property, value);
        }
        for (property, secret_key_selector) in &self.properties_from_secret {
            config.add_env_property_from_secret(property, secret_key_selector.clone());
        }
        for (property, config_map_key_selector) in &self.properties_from_config_map {
            config.add_env_property_from_config_map(property, config_map_key_selector.clone());
        }

        Ok(config)
    }
}
