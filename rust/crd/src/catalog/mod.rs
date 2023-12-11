pub mod black_hole;
pub mod commons;
pub mod generic;
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
use generic::GenericConnector;
use google_sheet::GoogleSheetConnector;
use hive::HiveConnector;
use iceberg::IcebergConnector;
use tpcds::TpcdsConnector;
use tpch::TpchConnector;

/// The TrinoCatalog resource can be used to define catalogs in Kubernetes objects.
/// Read more about it in the [Trino operator concept docs](DOCS_BASE_URL_PLACEHOLDER/trino/concepts)
/// and the [Trino operator usage guide](DOCS_BASE_URL_PLACEHOLDER/trino/usage-guide/catalogs/).
/// The documentation also contains a list of all the supported backends.
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
    /// The `connector` defines which connector is used.
    pub connector: TrinoCatalogConnector,
    #[serde(default)]
    /// The `configOverrides` allow overriding arbitrary Trino settings.
    /// For example, for Hive you could add `hive.metastore.username: trino`.
    pub config_overrides: HashMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum TrinoCatalogConnector {
    /// A [Black Hole](DOCS_BASE_URL_PLACEHOLDER/trino/usage-guide/catalogs/black-hole) connector.
    BlackHole(BlackHoleConnector),

    /// A [Google sheets](DOCS_BASE_URL_PLACEHOLDER/trino/usage-guide/catalogs/google-sheets) connector.
    GoogleSheet(GoogleSheetConnector),

    /// A [generic](DOCS_BASE_URL_PLACEHOLDER/trino/usage-guide/catalogs/generic) connector.
    Generic(GenericConnector),

    /// An [Apache Hive](DOCS_BASE_URL_PLACEHOLDER/trino/usage-guide/catalogs/hive) connector.
    Hive(HiveConnector),

    /// An [Apache Iceberg](DOCS_BASE_URL_PLACEHOLDER/trino/usage-guide/catalogs/iceberg) connector.
    Iceberg(IcebergConnector),

    /// A [TPC-DS](DOCS_BASE_URL_PLACEHOLDER/trino/usage-guide/catalogs/tpcds) connector.
    Tpcds(TpcdsConnector),

    /// A [TPC-H](DOCS_BASE_URL_PLACEHOLDER/trino/usage-guide/catalogs/tpch) connector.
    Tpch(TpchConnector),
}

#[cfg(test)]
mod tests {
    use stackable_operator::kube::CustomResourceExt;

    use super::*;

    #[test]
    fn test_crd_generation() {
        TrinoCatalog::crd();
    }
}
