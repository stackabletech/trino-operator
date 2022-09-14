use super::hive::HiveAndIcebergCommonAttributes;
use serde::{Deserialize, Serialize};
use stackable_operator::schemars::{self, JsonSchema};

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IcebergConnector {
    #[serde(flatten)]
    pub common: HiveAndIcebergCommonAttributes,
}
