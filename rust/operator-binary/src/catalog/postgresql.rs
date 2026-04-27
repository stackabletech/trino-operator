use async_trait::async_trait;
use snafu::ResultExt;
use stackable_operator::{
    client::Client, database_connections::drivers::jdbc::JdbcDatabaseConnection,
};

use super::{FromTrinoCatalogError, ToCatalogConfig, config::CatalogConfig};
use crate::{
    catalog::from_trino_catalog_error::GetPostgresConnectionDetailsSnafu,
    crd::catalog::postgresql::PostgresqlConnector,
};

pub const CONNECTOR_NAME: &str = "postgresql";

#[async_trait]
impl ToCatalogConfig for PostgresqlConnector {
    async fn to_catalog_config(
        &self,
        catalog_name: &str,
        _catalog_namespace: Option<String>,
        _client: &Client,
        _trino_version: u16,
    ) -> Result<CatalogConfig, FromTrinoCatalogError> {
        let mut config = CatalogConfig::new(catalog_name.to_string(), CONNECTOR_NAME);
        // SAFETY: `unique_database_name` must only contains uppercase ASCII letters and underscores.
        let unique_database_name = format!(
            "POSTGRESQL_{}",
            catalog_name.replace('-', "_").to_uppercase()
        );
        let jdbc_connection_details = self
            .inner
            .jdbc_connection_details(&unique_database_name)
            .context(GetPostgresConnectionDetailsSnafu)?;

        config.add_property("connection-url", jdbc_connection_details.connection_url);
        if let Some(username_env) = jdbc_connection_details.username_env {
            config.add_property("connection-user", format!("${{ENV:{}}}", username_env.name));
            config.env_bindings.push(username_env);
        };
        if let Some(password_env) = jdbc_connection_details.password_env {
            config.add_property(
                "connection-password",
                format!("${{ENV:{}}}", password_env.name),
            );
            config.env_bindings.push(password_env);
        };

        Ok(config)
    }
}
