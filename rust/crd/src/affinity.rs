use stackable_operator::{
    commons::affinity::{
        affinity_between_cluster_pods, affinity_between_role_pods, StackableAffinityFragment,
    },
    k8s_openapi::api::core::v1::{PodAffinity, PodAntiAffinity},
};

use crate::{catalog::TrinoCatalogConnector, TrinoCatalog, TrinoRole, APP_NAME};

pub fn get_affinity(
    cluster_name: &str,
    role: &TrinoRole,
    trino_catalogs: &[TrinoCatalog],
) -> StackableAffinityFragment {
    let affinity_between_cluster_pods = affinity_between_cluster_pods(APP_NAME, cluster_name, 20);
    let mut affinities = vec![affinity_between_cluster_pods];
    let additional_affinities: Vec<_> = match role {
        TrinoRole::Coordinator => trino_catalogs
            .iter()
            .filter_map(|catalog| match &catalog.spec.connector {
                TrinoCatalogConnector::Hive(hive) => Some(&hive.metastore.config_map),
                TrinoCatalogConnector::Iceberg(iceberg) => Some(&iceberg.metastore.config_map),
                TrinoCatalogConnector::BlackHole(_)
                | TrinoCatalogConnector::Generic(_)
                | TrinoCatalogConnector::GoogleSheet(_)
                | TrinoCatalogConnector::Tpcds(_)
                | TrinoCatalogConnector::Tpch(_) => None,
            })
            .map(|hive_cluster_name| {
                affinity_between_role_pods(
                    "hive",
                    hive_cluster_name, // The discovery cm has the same name as the HiveCluster itself
                    "metastore",
                    50,
                )
            })
            .collect(),
        TrinoRole::Worker => trino_catalogs
            .iter()
            .filter_map(|catalog| match &catalog.spec.connector {
                TrinoCatalogConnector::Hive(hive) => {
                    hive.hdfs.as_ref().map(|hdfs| &hdfs.config_map)
                }
                TrinoCatalogConnector::Iceberg(iceberg) => {
                    iceberg.hdfs.as_ref().map(|hdfs| &hdfs.config_map)
                }
                TrinoCatalogConnector::BlackHole(_)
                | TrinoCatalogConnector::Generic(_)
                | TrinoCatalogConnector::GoogleSheet(_)
                | TrinoCatalogConnector::Tpcds(_)
                | TrinoCatalogConnector::Tpch(_) => None,
            })
            .map(|hdfs_cluster_name| {
                affinity_between_role_pods(
                    "hdfs",
                    hdfs_cluster_name, // The discovery cm has the same name as the HdfsCluster itself
                    "datanode",
                    50,
                )
            })
            .collect(),
    };
    affinities.extend(additional_affinities);
    StackableAffinityFragment {
        pod_affinity: Some(PodAffinity {
            preferred_during_scheduling_ignored_during_execution: Some(affinities),
            required_during_scheduling_ignored_during_execution: None,
        }),
        pod_anti_affinity: Some(PodAntiAffinity {
            preferred_during_scheduling_ignored_during_execution: Some(vec![
                affinity_between_role_pods(APP_NAME, cluster_name, &role.to_string(), 70),
            ]),
            required_during_scheduling_ignored_during_execution: None,
        }),
        node_affinity: None,
        node_selector: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use rstest::rstest;
    use std::collections::BTreeMap;

    use crate::TrinoCluster;
    use stackable_operator::{
        commons::affinity::{StackableAffinity, StackableNodeSelector},
        k8s_openapi::{
            api::core::v1::{
                NodeAffinity, NodeSelector, NodeSelectorRequirement, NodeSelectorTerm, PodAffinity,
                PodAffinityTerm, PodAntiAffinity, WeightedPodAffinityTerm,
            },
            apimachinery::pkg::apis::meta::v1::LabelSelector,
        },
    };

    #[rstest]
    #[case(TrinoRole::Coordinator)]
    #[case(TrinoRole::Worker)]
    fn test_affinity_defaults(#[case] role: TrinoRole) {
        let input = r#"
        apiVersion: trino.stackable.tech/v1alpha1
        kind: TrinoCluster
        metadata:
          name: simple-trino
        spec:
          image:
            productVersion: "428"
          clusterConfig:
            catalogLabelSelector:
              matchLabels:
                trino: simple-trino
          coordinators:
            roleGroups:
              default:
                replicas: 1
          workers:
            roleGroups:
              default:
                replicas: 1
        "#;
        let trino: TrinoCluster = serde_yaml::from_str(input).expect("illegal test input");
        let merged_config = trino
            .merged_config(&role, &role.rolegroup_ref(&trino, "default"), &[])
            .unwrap();

        assert_eq!(
            merged_config.affinity,
            StackableAffinity {
                pod_affinity: Some(PodAffinity {
                    preferred_during_scheduling_ignored_during_execution: Some(vec![
                        WeightedPodAffinityTerm {
                            pod_affinity_term: PodAffinityTerm {
                                label_selector: Some(LabelSelector {
                                    match_expressions: None,
                                    match_labels: Some(BTreeMap::from([
                                        ("app.kubernetes.io/name".to_string(), "trino".to_string()),
                                        (
                                            "app.kubernetes.io/instance".to_string(),
                                            "simple-trino".to_string(),
                                        ),
                                    ])),
                                }),
                                namespace_selector: None,
                                namespaces: None,
                                topology_key: "kubernetes.io/hostname".to_string(),
                            },
                            weight: 20,
                        }
                    ]),
                    required_during_scheduling_ignored_during_execution: None,
                }),
                pod_anti_affinity: Some(PodAntiAffinity {
                    preferred_during_scheduling_ignored_during_execution: Some(vec![
                        WeightedPodAffinityTerm {
                            pod_affinity_term: PodAffinityTerm {
                                label_selector: Some(LabelSelector {
                                    match_expressions: None,
                                    match_labels: Some(BTreeMap::from([
                                        ("app.kubernetes.io/name".to_string(), "trino".to_string(),),
                                        (
                                            "app.kubernetes.io/instance".to_string(),
                                            "simple-trino".to_string(),
                                        ),
                                        (
                                            "app.kubernetes.io/component".to_string(),
                                            role.to_string(),
                                        )
                                    ]))
                                }),
                                namespace_selector: None,
                                namespaces: None,
                                topology_key: "kubernetes.io/hostname".to_string(),
                            },
                            weight: 70
                        }
                    ]),
                    required_during_scheduling_ignored_during_execution: None,
                }),
                node_affinity: None,
                node_selector: None,
            }
        );
    }

    #[rstest]
    #[case(TrinoRole::Coordinator)]
    #[case(TrinoRole::Worker)]
    fn test_hms_and_hdfs_affinity(#[case] role: TrinoRole) {
        let input = r#"
        apiVersion: trino.stackable.tech/v1alpha1
        kind: TrinoCluster
        metadata:
          name: simple-trino
        spec:
          image:
            productVersion: "428"
          clusterConfig:
            catalogLabelSelector:
              matchLabels:
                trino: simple-trino
          coordinators:
            roleGroups:
              default:
                replicas: 1
          workers:
            roleGroups:
              default:
                replicas: 1
        "#;
        let trino: TrinoCluster = serde_yaml::from_str(input).expect("illegal test input");

        let input = r#"
        apiVersion: trino.stackable.tech/v1alpha1
        kind: TrinoCatalog
        metadata:
          name: hive-1
          labels:
            trino: simple-trino
        spec:
          connector:
            hive:
              metastore:
                configMap: simple-hive-1
              hdfs:
                configMap: simple-hdfs
        "#;
        let deserializer = serde_yaml::Deserializer::from_str(input);
        let hive_catalog_1: TrinoCatalog =
            serde_yaml::with::singleton_map_recursive::deserialize(deserializer).unwrap();

        let input = r#"
        apiVersion: trino.stackable.tech/v1alpha1
        kind: TrinoCatalog
        metadata:
          name: tpch
          labels:
            trino: simple-trino
        spec:
          connector:
            tpch: {}
        "#;
        let deserializer = serde_yaml::Deserializer::from_str(input);
        let tpch_catalog: TrinoCatalog =
            serde_yaml::with::singleton_map_recursive::deserialize(deserializer).unwrap();

        let input = r#"
            apiVersion: trino.stackable.tech/v1alpha1
            kind: TrinoCatalog
            metadata:
              name: hive-2
              labels:
                trino: simple-trino
            spec:
              connector:
                hive:
                  metastore:
                    configMap: simple-hive-2
                  s3:
                    reference: minio
            "#;
        let deserializer = serde_yaml::Deserializer::from_str(input);
        let hive_catalog_2: TrinoCatalog =
            serde_yaml::with::singleton_map_recursive::deserialize(deserializer).unwrap();

        let merged_config = trino
            .merged_config(
                &role,
                &role.rolegroup_ref(&trino, "default"),
                &[hive_catalog_1, tpch_catalog, hive_catalog_2],
            )
            .unwrap();

        let mut expected_affinities = vec![WeightedPodAffinityTerm {
            pod_affinity_term: PodAffinityTerm {
                label_selector: Some(LabelSelector {
                    match_expressions: None,
                    match_labels: Some(BTreeMap::from([
                        ("app.kubernetes.io/name".to_string(), "trino".to_string()),
                        (
                            "app.kubernetes.io/instance".to_string(),
                            "simple-trino".to_string(),
                        ),
                    ])),
                }),
                namespace_selector: None,
                namespaces: None,
                topology_key: "kubernetes.io/hostname".to_string(),
            },
            weight: 20,
        }];

        match role {
            TrinoRole::Coordinator => {
                expected_affinities.push(WeightedPodAffinityTerm {
                    pod_affinity_term: PodAffinityTerm {
                        label_selector: Some(LabelSelector {
                            match_expressions: None,
                            match_labels: Some(BTreeMap::from([
                                ("app.kubernetes.io/name".to_string(), "hive".to_string()),
                                (
                                    "app.kubernetes.io/instance".to_string(),
                                    "simple-hive-1".to_string(),
                                ),
                                (
                                    "app.kubernetes.io/component".to_string(),
                                    "metastore".to_string(),
                                ),
                            ])),
                        }),
                        namespace_selector: None,
                        namespaces: None,
                        topology_key: "kubernetes.io/hostname".to_string(),
                    },
                    weight: 50,
                });
                expected_affinities.push(WeightedPodAffinityTerm {
                    pod_affinity_term: PodAffinityTerm {
                        label_selector: Some(LabelSelector {
                            match_expressions: None,
                            match_labels: Some(BTreeMap::from([
                                ("app.kubernetes.io/name".to_string(), "hive".to_string()),
                                (
                                    "app.kubernetes.io/instance".to_string(),
                                    "simple-hive-2".to_string(),
                                ),
                                (
                                    "app.kubernetes.io/component".to_string(),
                                    "metastore".to_string(),
                                ),
                            ])),
                        }),
                        namespace_selector: None,
                        namespaces: None,
                        topology_key: "kubernetes.io/hostname".to_string(),
                    },
                    weight: 50,
                });
            }
            TrinoRole::Worker => {
                expected_affinities.push(WeightedPodAffinityTerm {
                    pod_affinity_term: PodAffinityTerm {
                        label_selector: Some(LabelSelector {
                            match_expressions: None,
                            match_labels: Some(BTreeMap::from([
                                ("app.kubernetes.io/name".to_string(), "hdfs".to_string()),
                                (
                                    "app.kubernetes.io/instance".to_string(),
                                    "simple-hdfs".to_string(),
                                ),
                                (
                                    "app.kubernetes.io/component".to_string(),
                                    "datanode".to_string(),
                                ),
                            ])),
                        }),
                        namespace_selector: None,
                        namespaces: None,
                        topology_key: "kubernetes.io/hostname".to_string(),
                    },
                    weight: 50,
                });
            }
        };

        assert_eq!(
            merged_config.affinity,
            StackableAffinity {
                pod_affinity: Some(PodAffinity {
                    preferred_during_scheduling_ignored_during_execution: Some(expected_affinities),
                    required_during_scheduling_ignored_during_execution: None,
                }),
                pod_anti_affinity: Some(PodAntiAffinity {
                    preferred_during_scheduling_ignored_during_execution: Some(vec![
                        WeightedPodAffinityTerm {
                            pod_affinity_term: PodAffinityTerm {
                                label_selector: Some(LabelSelector {
                                    match_expressions: None,
                                    match_labels: Some(BTreeMap::from([
                                        ("app.kubernetes.io/name".to_string(), "trino".to_string(),),
                                        (
                                            "app.kubernetes.io/instance".to_string(),
                                            "simple-trino".to_string(),
                                        ),
                                        (
                                            "app.kubernetes.io/component".to_string(),
                                            role.to_string(),
                                        )
                                    ]))
                                }),
                                namespace_selector: None,
                                namespaces: None,
                                topology_key: "kubernetes.io/hostname".to_string(),
                            },
                            weight: 70
                        }
                    ]),
                    required_during_scheduling_ignored_during_execution: None,
                }),
                node_affinity: None,
                node_selector: None,
            }
        );
    }

    #[test]
    fn test_affinity_legacy_node_selector() {
        let input = r#"
        apiVersion: trino.stackable.tech/v1alpha1
        kind: TrinoCluster
        metadata:
          name: simple-trino
        spec:
          image:
            productVersion: "428"
          clusterConfig:
            catalogLabelSelector:
              matchLabels:
                trino: simple-trino
          coordinators:
            roleGroups:
              default:
                replicas: 1
                selector:
                  matchLabels:
                    disktype: ssd
                  matchExpressions:
                    - key: topology.kubernetes.io/zone
                      operator: In
                      values:
                        - antarctica-east1
                        - antarctica-west1
          workers:
            roleGroups:
              default:
                replicas: 1
        "#;
        let trino: TrinoCluster = serde_yaml::from_str(input).expect("illegal test input");
        let merged_config = trino
            .merged_config(
                &TrinoRole::Coordinator,
                &TrinoRole::Coordinator.rolegroup_ref(&trino, "default"),
                &[],
            )
            .unwrap();

        assert_eq!(
            merged_config.affinity,
            StackableAffinity {
                pod_affinity: Some(PodAffinity {
                    preferred_during_scheduling_ignored_during_execution: Some(vec![
                        WeightedPodAffinityTerm {
                            pod_affinity_term: PodAffinityTerm {
                                label_selector: Some(LabelSelector {
                                    match_expressions: None,
                                    match_labels: Some(BTreeMap::from([
                                        ("app.kubernetes.io/name".to_string(), "trino".to_string(),),
                                        (
                                            "app.kubernetes.io/instance".to_string(),
                                            "simple-trino".to_string(),
                                        ),
                                    ]))
                                }),
                                namespace_selector: None,
                                namespaces: None,
                                topology_key: "kubernetes.io/hostname".to_string(),
                            },
                            weight: 20
                        }
                    ]),
                    required_during_scheduling_ignored_during_execution: None,
                }),
                pod_anti_affinity: Some(PodAntiAffinity {
                    preferred_during_scheduling_ignored_during_execution: Some(vec![
                        WeightedPodAffinityTerm {
                            pod_affinity_term: PodAffinityTerm {
                                label_selector: Some(LabelSelector {
                                    match_expressions: None,
                                    match_labels: Some(BTreeMap::from([
                                        ("app.kubernetes.io/name".to_string(), "trino".to_string(),),
                                        (
                                            "app.kubernetes.io/instance".to_string(),
                                            "simple-trino".to_string(),
                                        ),
                                        (
                                            "app.kubernetes.io/component".to_string(),
                                            "coordinator".to_string(),
                                        )
                                    ]))
                                }),
                                namespace_selector: None,
                                namespaces: None,
                                topology_key: "kubernetes.io/hostname".to_string(),
                            },
                            weight: 70
                        }
                    ]),
                    required_during_scheduling_ignored_during_execution: None,
                }),
                node_affinity: Some(NodeAffinity {
                    preferred_during_scheduling_ignored_during_execution: None,
                    required_during_scheduling_ignored_during_execution: Some(NodeSelector {
                        node_selector_terms: vec![NodeSelectorTerm {
                            match_expressions: Some(vec![NodeSelectorRequirement {
                                key: "topology.kubernetes.io/zone".to_string(),
                                operator: "In".to_string(),
                                values: Some(vec![
                                    "antarctica-east1".to_string(),
                                    "antarctica-west1".to_string()
                                ]),
                            }]),
                            match_fields: None,
                        }]
                    }),
                }),
                node_selector: Some(StackableNodeSelector {
                    node_selector: BTreeMap::from([("disktype".to_string(), "ssd".to_string())])
                }),
            }
        );
    }
}
