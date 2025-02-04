use async_trait::async_trait;
use stackable_operator::{
    builder::pod::volume::{VolumeBuilder, VolumeMountBuilder},
    client::Client,
};
use stackable_trino_crd::{catalog::google_sheet::GoogleSheetConnector, CONFIG_DIR_NAME};

use super::{config::CatalogConfig, FromTrinoCatalogError, ToCatalogConfig};

pub const CONNECTOR_NAME: &str = "gsheets";

#[async_trait]
impl ToCatalogConfig for GoogleSheetConnector {
    async fn to_catalog_config(
        &self,
        catalog_name: &str,
        _catalog_namespace: Option<String>,
        _client: &Client,
    ) -> Result<CatalogConfig, FromTrinoCatalogError> {
        let mut config = CatalogConfig::new(catalog_name.to_string(), CONNECTOR_NAME);

        let volume_name = format!("{catalog_name}-google-sheets-credentials");
        let google_sheets_credentials_dir =
            format!("{CONFIG_DIR_NAME}/catalog/{catalog_name}/google-sheets-credentials/");

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
