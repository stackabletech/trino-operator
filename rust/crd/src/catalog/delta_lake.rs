use super::hive::HiveConnector;
use serde::{Deserialize, Serialize};
use stackable_operator::schemars::{self, JsonSchema};

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeltaLakeConnector {
    /// The Hive connector exposes the same config
    #[serde(flatten)]
    pub hive: HiveConnector,
}
