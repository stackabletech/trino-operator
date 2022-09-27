use super::commons::{HdfsConnection, MetastoreConnection};
use serde::{Deserialize, Serialize};
use stackable_operator::{
    commons::s3::S3ConnectionDef,
    schemars::{self, JsonSchema},
};

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IcebergConnector {
    /// Mandatory connection to a Hive Metastore, which will be used as a storage for metadata
    pub metastore: MetastoreConnection,
    /// Connection to an S3 store
    pub s3: Option<S3ConnectionDef>,
    /// Connection to an HDFS cluster
    pub hdfs: Option<HdfsConnection>,
}
