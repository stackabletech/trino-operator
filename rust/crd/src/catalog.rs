use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use stackable_operator::{
    commons::s3::S3ConnectionDef,
    kube::CustomResource,
    schemars::{self, JsonSchema},
};

#[derive(Clone, CustomResource, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[kube(
    group = "trino.stackable.tech",
    version = "v1alpha1",
    kind = "TrinoCatalog",
    plural = "trinocatalogs",
    namespaced,
    crates(
        kube_core = "stackable_operator::kube::core",
        k8s_openapi = "stackable_operator::k8s_openapi",
        schemars = "stackable_operator::schemars"
    )
)]
#[serde(rename_all = "camelCase")]
pub struct TrinoCatalogSpec {
    pub connector: TrinoCatalogConnector,
    #[serde(default)]
    pub config_overrides: HashMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum TrinoCatalogConnector {
    Hive(HiveConnector),
}

impl TrinoCatalogConnector {
    pub fn name(&self) -> String {
        match self {
            TrinoCatalogConnector::Hive(_) => "hive".to_string(),
        }
    }
}

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
    /// Name of the discovery-configmap providing information about the HDFS
    pub config_map: String,
}
