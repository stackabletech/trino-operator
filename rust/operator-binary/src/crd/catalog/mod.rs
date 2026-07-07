pub mod black_hole;
pub mod commons;
pub mod delta_lake;
pub mod generic;
pub mod google_sheet;
pub mod hive;
pub mod iceberg;
pub mod postgresql;
pub mod tpcds;
pub mod tpch;

use std::{collections::HashMap, str::FromStr};

use black_hole::BlackHoleConnector;
use generic::GenericConnector;
use google_sheet::GoogleSheetConnector;
use hive::HiveConnector;
use iceberg::IcebergConnector;
use serde::{Deserialize, Serialize};
use stackable_operator::{
    attributed_string_type,
    kube::CustomResource,
    schemars::{self, JsonSchema},
    versioned::versioned,
};
use tpcds::TpcdsConnector;
use tpch::TpchConnector;

use self::delta_lake::DeltaLakeConnector;
use crate::crd::catalog::postgresql::PostgresqlConnector;

#[versioned(
    version(name = "v1alpha1"),
    crates(
        kube_core = "stackable_operator::kube::core",
        kube_client = "stackable_operator::kube::client",
        k8s_openapi = "stackable_operator::k8s_openapi",
        schemars = "stackable_operator::schemars",
        versioned = "stackable_operator::versioned",
    ),
    skip(from)
)]
pub mod versioned {
    /// The TrinoCatalog resource can be used to define catalogs in Kubernetes objects.
    /// Read more about it in the [Trino operator concept docs](DOCS_BASE_URL_PLACEHOLDER/trino/concepts)
    /// and the [Trino operator usage guide](DOCS_BASE_URL_PLACEHOLDER/trino/usage-guide/catalogs/).
    /// The documentation also contains a list of all the supported backends.
    #[versioned(crd(group = "trino.stackable.tech", plural = "trinocatalogs", namespaced,))]
    #[derive(Clone, CustomResource, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct TrinoCatalogSpec {
        /// The name of the catalog
        #[serde(default)]
        pub name: TrinoCatalogNameSpec,

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

    // We might implement more variants in the future. See the CRD decision in
    // https://github.com/stackabletech/trino-operator/issues/891 for details.
    #[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub enum TrinoCatalogNameSpec {
        /// Infer the catalog name from the `.metadata.name` of the TrinoCatalog resource.
        ///
        /// This ensures that no catalog names clash, as there can only be one TrinoCatalog with a
        /// given name.
        #[serde(rename_all = "camelCase")]
        Inferred {
            /// Whether hyphens (`-`) in the name of the catalog should be replaced by underscores (`_`).
            ///
            /// This is recommended because Kubernetes only allows `a-z` and `-`, while Trino
            /// requires quoting for catalogs containing `-` characters. This mechanism allows
            /// you to use valid Kubernetes names, but keeps the convenience of using `_` in
            /// catalog names.
            #[serde(default)]
            replace_hyphens_with_underscores: bool,
        },
    }
}

impl Default for v1alpha1::TrinoCatalogNameSpec {
    fn default() -> Self {
        Self::Inferred {
            replace_hyphens_with_underscores: false,
        }
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

    /// An [PostgreSQL](DOCS_BASE_URL_PLACEHOLDER/trino/usage-guide/catalogs/postgresql) connector.
    Postgresql(PostgresqlConnector),

    /// A [TPC-DS](DOCS_BASE_URL_PLACEHOLDER/trino/usage-guide/catalogs/tpcds) connector.
    Tpcds(TpcdsConnector),

    /// A [TPC-H](DOCS_BASE_URL_PLACEHOLDER/trino/usage-guide/catalogs/tpch) connector.
    Tpch(TpchConnector),
}

attributed_string_type! {
    TrinoCatalogName,
    "The name of a TrinoCluster",
    "lakehouse",
    // Suffixes are added to produce resource/volume names.
    //
    // 40 characters should be sufficient and still allow the operators to append custom suffixes.
    // As of 2026-07 the longest suffix is for a volume name (63 characters limit) and is
    // "-sheets-credentials" (19 characters).
    (max_length = 40),
    is_valid_label_value
}

#[cfg(test)]
mod tests {
    use stackable_operator::versioned::test_utils::RoundtripTestData;

    use super::{TrinoCatalog, TrinoCatalogVersion, v1alpha1};

    #[test]
    fn test_crd_generation() {
        TrinoCatalog::merged_crd(TrinoCatalogVersion::V1Alpha1).unwrap();
    }

    impl RoundtripTestData for v1alpha1::TrinoCatalogSpec {
        fn roundtrip_test_data() -> Vec<Self> {
            stackable_operator::utils::yaml_from_str_singleton_map(indoc::indoc! {"
          - connector:
              blackHole: {}
          - connector:
              deltaLake:
                metastore:
                  configMap: simple-hive
                s3:
                  inline:
                    host: test-minio
                    port: 9000
                    accessStyle: Path
                    credentials:
                      secretClass: minio-credentials
          - connector:
              generic:
                connectorName: postgresql
                properties: # optional
                  connection-url:
                    value: jdbc:postgresql://example.net:5432/database
                  connection-user:
                    valueFromSecret:
                      name: my-postgresql-credentials-secret
                      key: user
                  connection-password:
                    valueFromSecret:
                      name: my-postgresql-credentials-secret
                      key: password
          - connector:
              googleSheet:
                credentialsSecret: gsheet-credentials
                metadataSheetId: 1dT4dRWo9tAKBk5GdH-a54dcizuoxOTn98X8igZcnYr8
                cache: # optional
                  sheetsDataMaxCacheSize: 1000
                  sheetsDataExpireAfterWrite: 5m
          - connector:
              hive:
                metastore:
                  configMap: simple-hive
                s3:
                  inline:
                    host: test-minio
                    port: 9000
                    accessStyle: Path
                    credentials:
                      secretClass: minio-credentials
            configOverrides:
              hive.metastore.username: trino
          - connector:
              iceberg:
                metastore:
                  configMap: simple-hive
                s3:
                  inline:
                    host: test-minio
                    port: 9000
                    accessStyle: Path
                    credentials:
                      secretClass: minio-credentials
          - connector:
              tpcds: {}
          - name:
              inferred:
                replaceHyphensWithUnderscores: true
            connector:
              tpch: {}
        "})
            .expect("Failed to parse TrinoCatalogSpec YAML")
        }
    }
}
