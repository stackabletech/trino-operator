/// This module manages the client protocol properties, especially the for spooling.
/// Trino documentation is available here: https://trino.io/docs/current/client/client-protocol.html
use serde::{Deserialize, Serialize};
use stackable_operator::schemars::{self, JsonSchema};

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
    S3(S3FilesystemConfig),
}

// This adds a `connection` property to keep the structure consistent with the fault-tolerant execution
// config. It is similar to the `crate::crd::fault_tolerant_execution::S3ExchangeConfig` and maybe
// these two structures can be merged in the future.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct S3FilesystemConfig {
    pub connection: stackable_operator::crd::s3::v1alpha1::InlineConnectionOrReference,
}
