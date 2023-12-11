use serde::{Deserialize, Serialize};
use stackable_operator::schemars::{self, JsonSchema};

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GoogleSheetConnector {
    /// The Secret containing the Google API JSON key file.
    /// The key used from the Secret is `credentials`.
    pub credentials_secret: String,
    /// Sheet ID of the spreadsheet, that contains the table mapping.
    pub metadata_sheet_id: String,
    /// Cache the contents of sheets.
    /// This is used to reduce Google Sheets API usage and latency.
    pub cache: Option<GoogleSheetConnectorCache>,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GoogleSheetConnectorCache {
    /// Maximum number of spreadsheets to cache, defaults to 1000.
    pub sheets_data_max_cache_size: Option<String>,
    /// How long to cache spreadsheet data or metadata, defaults to `5m`.
    pub sheets_data_expire_after_write: Option<String>,
}
