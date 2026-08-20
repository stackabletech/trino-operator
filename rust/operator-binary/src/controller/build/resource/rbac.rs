//! Builds the RBAC resources (ServiceAccount + RoleBinding) shared by all role groups.

use stackable_operator::{
    k8s_openapi::api::{core::v1::ServiceAccount, rbac::v1::RoleBinding},
    v2::rbac,
};

use crate::controller::{ValidatedCluster, build::recommended_labels_for_cluster_resources};

/// Builds the [`ServiceAccount`] that the coordinator and worker Pods run under.
pub fn build_service_account(cluster: &ValidatedCluster) -> ServiceAccount {
    rbac::build_service_account(
        cluster,
        &cluster.cluster_resource_names(),
        recommended_labels_for_cluster_resources(cluster),
    )
}

/// Builds the [`RoleBinding`] that binds the [`ServiceAccount`] from [`build_service_account`] to
/// the operator-deployed ClusterRole.
pub fn build_role_binding(cluster: &ValidatedCluster) -> RoleBinding {
    rbac::build_role_binding(
        cluster,
        &cluster.cluster_resource_names(),
        recommended_labels_for_cluster_resources(cluster),
    )
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::controller::{app_version_label, validated_cluster};

    // `simple-trino` vs `trino`: see the swap-guard note on `MINIMAL_TRINO_YAML`.

    #[test]
    fn test_service_account() {
        let service_account = build_service_account(&validated_cluster());

        assert_eq!(
            json!({
                "apiVersion": "v1",
                "kind": "ServiceAccount",
                "metadata": {
                    // The RBAC resources are cluster-shared, so role and role group are `none`.
                    "labels": {
                        "app.kubernetes.io/instance": "simple-trino",
                        "app.kubernetes.io/managed-by": "trino.stackable.tech_trinocluster",
                        "app.kubernetes.io/name": "trino",
                        "app.kubernetes.io/version": app_version_label("481"),
                        "stackable.tech/vendor": "Stackable"
                    },
                    "name": "simple-trino-serviceaccount",
                    "namespace": "default",
                    "ownerReferences": [
                        {
                            "apiVersion": "trino.stackable.tech/v1alpha1",
                            "controller": true,
                            "kind": "TrinoCluster",
                            "name": "simple-trino",
                            "uid": "e6ac237d-a6d4-43a1-8135-f36506110912"
                        }
                    ]
                }
            }),
            serde_json::to_value(service_account).expect("must be serializable")
        );
    }

    #[test]
    fn test_role_binding() {
        let role_binding = build_role_binding(&validated_cluster());

        assert_eq!(
            json!({
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "RoleBinding",
                "metadata": {
                    "labels": {
                        "app.kubernetes.io/instance": "simple-trino",
                        "app.kubernetes.io/managed-by": "trino.stackable.tech_trinocluster",
                        "app.kubernetes.io/name": "trino",
                        "app.kubernetes.io/version": app_version_label("481"),
                        "stackable.tech/vendor": "Stackable"
                    },
                    "name": "simple-trino-rolebinding",
                    "namespace": "default",
                    "ownerReferences": [
                        {
                            "apiVersion": "trino.stackable.tech/v1alpha1",
                            "controller": true,
                            "kind": "TrinoCluster",
                            "name": "simple-trino",
                            "uid": "e6ac237d-a6d4-43a1-8135-f36506110912"
                        }
                    ]
                },
                "roleRef": {
                    "apiGroup": "rbac.authorization.k8s.io",
                    "kind": "ClusterRole",
                    "name": "trino-clusterrole"
                },
                "subjects": [
                    {
                        "kind": "ServiceAccount",
                        "name": "simple-trino-serviceaccount",
                        "namespace": "default"
                    }
                ]
            }),
            serde_json::to_value(role_binding).expect("must be serializable")
        );
    }
}
