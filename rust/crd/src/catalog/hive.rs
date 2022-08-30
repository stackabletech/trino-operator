use serde::{Deserialize, Serialize};
use stackable_operator::{
    commons::s3::S3ConnectionDef,
    schemars::{self, JsonSchema},
};

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HiveConnector {
    /// Mandatory connection to a Hive Metastore, which will be used as a storage for metadata
    pub metastore: MetastoreConnection, // We are using this nested struct to support HMS caching later on
    /// Connection to an S3 store
    pub s3: Option<S3ConnectionDef>,
    /// Connection to an HDFS cluster
    pub hdfs: Option<HdfsConnection>,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MetastoreConnection {
    /// Name of the discovery-configmap providing information about the Hive metastore
    pub config_map: String,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HdfsConnection {
    /// Name of the discovery-configmap providing information about the HDFS cluster
    pub config_map: String,
}
