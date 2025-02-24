use async_trait::async_trait;
use stackable_operator::client::Client;

use super::{config::CatalogConfig, ExtendCatalogConfig, FromTrinoCatalogError, ToCatalogConfig};
use crate::crd::catalog::delta_lake::DeltaLakeConnector;

pub const CONNECTOR_NAME: &str = "delta_lake";

#[async_trait]
impl ToCatalogConfig for DeltaLakeConnector {
    async fn to_catalog_config(
        &self,
        catalog_name: &str,
        catalog_namespace: Option<String>,
        client: &Client,
    ) -> Result<CatalogConfig, FromTrinoCatalogError> {
        let mut config = CatalogConfig::new(catalog_name.to_string(), CONNECTOR_NAME);

        // No authorization checks are enforced at the catalog level.
        // We don't want the delta connector to prevent users from dropping tables.
        // We also don't want that the delta connector makes decisions on which user is allowed to do what.
        // This decision should be done globally (for all catalogs) by OPA.
        // See https://trino.io/docs/current/connector/delta-lake.html
        config.add_property("delta.security", "allow-all");

        self.metastore
            .extend_catalog_config(&mut config, catalog_name, catalog_namespace.clone(), client)
            .await?;

        if let Some(ref s3) = self.s3 {
            s3.extend_catalog_config(&mut config, catalog_name, catalog_namespace.clone(), client)
                .await?;
        }

        if let Some(ref hdfs) = self.hdfs {
            hdfs.extend_catalog_config(
                &mut config,
                catalog_name,
                catalog_namespace.clone(),
                client,
            )
            .await?;
        }

        Ok(config)
    }
}
