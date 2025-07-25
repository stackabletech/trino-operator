use serde::{Deserialize, Serialize};
use stackable_operator::{
    crd::s3,
    schemars::{self, JsonSchema},
};

use super::commons::{HdfsConnection, MetastoreConnection};

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HiveConnector {
    /// Mandatory connection to a Hive Metastore, which will be used as a storage for metadata.
    pub metastore: MetastoreConnection,

    /// Connection to an S3 store.
    /// Please make sure that the underlying Hive metastore also has access to the S3 store.
    /// Learn more about S3 configuration in the [S3 concept docs](DOCS_BASE_URL_PLACEHOLDER/concepts/s3).
    pub s3: Option<s3::v1alpha1::InlineConnectionOrReference>,

    /// Connection to an HDFS cluster.
    /// Please make sure that the underlying Hive metastore also has access to the HDFS.
    pub hdfs: Option<HdfsConnection>,
}
