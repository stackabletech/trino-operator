pub mod black_hole;
pub mod commons;
pub mod google_sheet;
pub mod hive;
pub mod iceberg;
pub mod tpcds;
pub mod tpch;

use serde::{Deserialize, Serialize};
use stackable_operator::{
    kube::CustomResource,
    schemars::{self, JsonSchema},
};
use std::collections::HashMap;

use black_hole::BlackHoleConnector;
use google_sheet::GoogleSheetConnector;
use hive::HiveConnector;
use iceberg::IcebergConnector;
use tpcds::TpcdsConnector;
use tpch::TpchConnector;

#[derive(Clone, CustomResource, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
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

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum TrinoCatalogConnector {
    BlackHole(BlackHoleConnector),
    GoogleSheet(GoogleSheetConnector),
    Hive(HiveConnector),
    Iceberg(IcebergConnector),
    Tpcds(TpcdsConnector),
    Tpch(TpchConnector),
}
