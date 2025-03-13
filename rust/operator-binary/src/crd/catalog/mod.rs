pub mod black_hole;
pub mod commons;
pub mod delta_lake;
pub mod generic;
pub mod google_sheet;
pub mod hive;
pub mod iceberg;
pub mod tpcds;
pub mod tpch;

use std::collections::HashMap;

use black_hole::BlackHoleConnector;
use generic::GenericConnector;
use google_sheet::GoogleSheetConnector;
use hive::HiveConnector;
use iceberg::IcebergConnector;
use serde::{Deserialize, Serialize};
use stackable_operator::{
    kube::CustomResource,
    schemars::{self, JsonSchema},
};
use stackable_versioned::versioned;
use tpcds::TpcdsConnector;
use tpch::TpchConnector;

use self::delta_lake::DeltaLakeConnector;

#[versioned(version(name = "v1alpha1"), options(skip(from)))]
pub mod versioned {
    /// The TrinoCatalog resource can be used to define catalogs in Kubernetes objects.
    /// Read more about it in the [Trino operator concept docs](DOCS_BASE_URL_PLACEHOLDER/trino/concepts)
    /// and the [Trino operator usage guide](DOCS_BASE_URL_PLACEHOLDER/trino/usage-guide/catalogs/).
    /// The documentation also contains a list of all the supported backends.
    #[versioned(k8s(
        group = "trino.stackable.tech",
        kind = "TrinoCatalog",
        plural = "trinocatalogs",
        namespaced,
        crates(
            kube_core = "stackable_operator::kube::core",
            k8s_openapi = "stackable_operator::k8s_openapi",
            schemars = "stackable_operator::schemars"
        )
    ))]
    #[derive(Clone, CustomResource, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct TrinoCatalogSpec {
        /// The `connector` defines which connector is used.
        pub connector: TrinoCatalogConnector,

        /// The `configOverrides` allow overriding arbitrary Trino settings.
        /// For example, for Hive you could add `hive.metastore.username: trino`.
        #[serde(default)]
        pub config_overrides: HashMap<String, String>,

        /// List of config properties which should be removed.
        ///
        /// This is helpful, because Trino fails to start in case you have any unused config
        /// properties. The removals are executed after the `configOverrides`.
        ///
        /// This field is experimental, and might be replaced by a more generic mechanism to edit config properties
        #[serde(default, rename = "experimentalConfigRemovals")]
        pub config_removals: Vec<String>,
    }
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum TrinoCatalogConnector {
    /// A [Black Hole](DOCS_BASE_URL_PLACEHOLDER/trino/usage-guide/catalogs/black-hole) connector.
    BlackHole(BlackHoleConnector),

    /// An [Delta Lake](DOCS_BASE_URL_PLACEHOLDER/trino/usage-guide/catalogs/delta-lake) connector.
    DeltaLake(DeltaLakeConnector),

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
    use crate::crd::catalog::TrinoCatalog;
    #[test]
    fn test_crd_generation() {
        TrinoCatalog::merged_crd(TrinoCatalog::V1Alpha1).unwrap();
    }
}
