use super::commons::{HdfsConnection, MetastoreConnection};
use serde::{Deserialize, Serialize};
use stackable_operator::{
    commons::s3::S3ConnectionDef,
    schemars::{self, JsonSchema},
};

/// This struct is similar to [`super::hive::HiveConnector`], but we do not `#[serde(flatten)]` it here, to avoid changing
/// stuff there and missing that these settings don't apply to other connectors (such as Iceberg or Delta Lake).
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeltaLakeConnector {
    /// Mandatory connection to a Hive Metastore, which will be used as a storage for metadata.
    pub metastore: MetastoreConnection,
    /// Connection to an S3 store.
    /// Please make sure that the underlying Hive metastore also has access to the S3 store.
    /// Learn more about S3 configuration in the [S3 concept docs](DOCS_BASE_URL_PLACEHOLDER/concepts/s3).
    pub s3: Option<S3ConnectionDef>,
    /// Connection to an HDFS cluster.
    /// Please make sure that the underlying Hive metastore also has access to the HDFS.
    pub hdfs: Option<HdfsConnection>,
}
