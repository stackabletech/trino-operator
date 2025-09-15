/// This module manages the client protocol properties, especially the for spooling.
/// Trino documentation is available here: https://trino.io/docs/current/client/client-protocol.html
use serde::{Deserialize, Serialize};
use stackable_operator::schemars::{self, JsonSchema};

use crate::crd::s3::S3Config;

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ClientProtocolConfig {
    Spooling(ClientSpoolingProtocolConfig),
}
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientSpoolingProtocolConfig {
    // Spool segment location. Each Trino cluster must have its own
    // location independent of any other clusters.
    pub location: String,

    // Spooling filesystem properties. Only S3 is supported.
    pub filesystem: SpoolingFileSystemConfig,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SpoolingFileSystemConfig {
    S3(S3Config),
}
