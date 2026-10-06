use async_trait::async_trait;
use stackable_operator::{client::Client, v2::types::kubernetes::NamespaceName};

use crate::{
    catalog::{ExtendCatalogConfig, FromTrinoCatalogError, ToCatalogConfig, config::CatalogConfig},
    crd::catalog::{TrinoCatalogName, iceberg::IcebergConnector},
};

pub const CONNECTOR_NAME: &str = "iceberg";

#[async_trait]
impl ToCatalogConfig for IcebergConnector {
    async fn to_catalog_config(
        &self,
        catalog_name: &TrinoCatalogName,
        catalog_namespace: &NamespaceName,
        client: &Client,
    ) -> Result<CatalogConfig, FromTrinoCatalogError> {
        let mut config = CatalogConfig::new(catalog_name, CONNECTOR_NAME);

        // No authorization checks are enforced at the catalog level.
        // We don't want the iceberg connector to prevent users from dropping tables.
        // We also don't want that the iceberg connector makes decisions on which user is allowed to do what.
        // This decision should be done globally (for all catalogs) by OPA.
        // See https://trino.io/docs/current/connector/iceberg.html
        config.add_property("iceberg.security", "allow-all");

        if let Some(metastore) = &self.metastore {
            metastore
                .extend_catalog_config(&mut config, catalog_name, catalog_namespace, client)
                .await?;
        }

        if let Some(ref s3) = self.s3 {
            s3.extend_catalog_config(&mut config, catalog_name, catalog_namespace, client)
                .await?;
        }

        if let Some(ref hdfs) = self.hdfs {
            hdfs.extend_catalog_config(&mut config, catalog_name, catalog_namespace, client)
                .await?;
        }

        Ok(config)
    }
}
