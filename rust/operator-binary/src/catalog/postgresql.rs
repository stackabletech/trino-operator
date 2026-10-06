use async_trait::async_trait;
use snafu::ResultExt;
use stackable_operator::{
    client::Client, database_connections::drivers::jdbc::JdbcDatabaseConnection,
    v2::types::kubernetes::NamespaceName,
};

use crate::{
    catalog::{
        FromTrinoCatalogError, ToCatalogConfig, config::CatalogConfig,
        from_trino_catalog_error::GetPostgresConnectionDetailsSnafu,
    },
    crd::catalog::{TrinoCatalogName, postgresql::PostgresqlConnector},
};

pub const CONNECTOR_NAME: &str = "postgresql";

#[async_trait]
impl ToCatalogConfig for PostgresqlConnector {
    async fn to_catalog_config(
        &self,
        catalog_name: &TrinoCatalogName,
        _catalog_namespace: &NamespaceName,
        _client: &Client,
    ) -> Result<CatalogConfig, FromTrinoCatalogError> {
        let mut config = CatalogConfig::new(catalog_name, CONNECTOR_NAME);
        // SAFETY: `unique_database_name` must only contain uppercase ASCII letters and underscores.
        let unique_database_name = format!(
            "POSTGRESQL_{}",
            catalog_name.to_string().replace('-', "_").to_uppercase()
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
