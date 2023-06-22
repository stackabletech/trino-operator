use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use stackable_operator::{
    k8s_openapi::api::core::v1::{ConfigMapKeySelector, SecretKeySelector},
    schemars::{self, JsonSchema},
};

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GenericConnector {
    /// Name of the Trino connector.
    /// Will end in `connector.name`
    pub connector_name: String,
    /// A map of properties to put in the connector configuration file
    #[serde(default)]
    pub properties: BTreeMap<String, String>,
    /// A map of properties pulled from a Secret.
    /// Values must be a `SecretKeySelector`
    #[serde(default)]
    pub properties_from_secret: BTreeMap<String, SecretKeySelector>,
    /// A map of properties pulled from a ConfigMap
    /// /// Values must be a `ConfigMapKeySelector`
    #[serde(default)]
    pub properties_from_config_map: BTreeMap<String, ConfigMapKeySelector>,
}
