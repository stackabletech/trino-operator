use async_trait::async_trait;
use stackable_operator::{
    builder::pod::volume::{VolumeBuilder, VolumeMountBuilder},
    client::Client,
    v2::types::kubernetes::NamespaceName,
};

use crate::{
    catalog::{FromTrinoCatalogError, ToCatalogConfig, config::CatalogConfig},
    crd::{
        CONFIG_DIR_NAME,
        catalog::{TrinoCatalogName, google_sheet::GoogleSheetConnector},
    },
};

pub const CONNECTOR_NAME: &str = "gsheets";

#[async_trait]
impl ToCatalogConfig for GoogleSheetConnector {
    async fn to_catalog_config(
        &self,
        catalog_name: &TrinoCatalogName,
        _catalog_namespace: &NamespaceName,
        _client: &Client,
        _trino_version: u16,
    ) -> Result<CatalogConfig, FromTrinoCatalogError> {
        let mut config = CatalogConfig::new(catalog_name, CONNECTOR_NAME);

        let volume_name = format!("{catalog_name}-sheets-credentials");
        let google_sheets_credentials_dir =
            format!("{CONFIG_DIR_NAME}/catalog/{catalog_name}/sheets-credentials/");

        config.volumes.push(
            VolumeBuilder::new(&volume_name)
                .with_secret(&self.credentials_secret, false)
                .build(),
        );
        config
            .volume_mounts
            .push(VolumeMountBuilder::new(&volume_name, &google_sheets_credentials_dir).build());

        config.add_property(
            "credentials-path",
            format!("{google_sheets_credentials_dir}/credentials"),
        );
        config.add_property("metadata-sheet-id", &self.metadata_sheet_id);

        if let Some(cache) = &self.cache {
            if let Some(cache_sheets_data_max_cache_size) = &cache.sheets_data_max_cache_size {
                config.add_property(
                    "sheets-data-max-cache-size",
                    cache_sheets_data_max_cache_size,
                );
            }
            if let Some(cache_sheets_data_expire_after_write) =
                &cache.sheets_data_expire_after_write
            {
                config.add_property(
                    "sheets-data-expire-after-write",
                    cache_sheets_data_expire_after_write,
                );
            }
        }

        Ok(config)
    }
}
