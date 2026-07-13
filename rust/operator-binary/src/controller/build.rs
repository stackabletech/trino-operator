//! Builders that turn a `ValidatedCluster` into Kubernetes resource contents.

use std::str::FromStr;

use snafu::{ResultExt, Snafu};
use stackable_operator::{
    utils::cluster_info::KubernetesClusterInfo, v2::types::operator::RoleGroupName,
};

use crate::controller::{
    KubernetesResources, ValidatedCluster,
    build::resource::{
        config_map,
        listener::{build_group_listener, group_listener_name},
        pdb::build_pdb,
        service::{
            build_rolegroup_headless_service, build_rolegroup_metrics_service,
            headless_service_ports,
        },
        statefulset,
    },
};

pub mod command;
pub mod graceful_shutdown;
pub mod ports;
pub mod properties;
pub mod resource;

// Placeholder role-group name used for the recommended labels of a role's group listener.
// The group listener is owned by the role (not a single role-group), so there is no real
// role-group to attribute it to.
stackable_operator::constant!(PLACEHOLDER_LISTENER_ROLE_GROUP: RoleGroupName = "none");

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("failed to build ConfigMap for role group {role_group}"))]
    ConfigMap {
        source: config_map::Error,
        role_group: RoleGroupName,
    },

    #[snafu(display("failed to build StatefulSet for role group {role_group}"))]
    StatefulSet {
        source: statefulset::Error,
        role_group: RoleGroupName,
    },
}

/// Builds every Kubernetes resource for the given validated cluster.
///
/// Does not need a Kubernetes client: every reference to another Kubernetes resource is already
/// dereferenced and validated by this point, so the errors returned here are resource-assembly
/// failures only.
///
/// `service_account_name` is the name of the RBAC `ServiceAccount` the role-group Pods run under
/// (RBAC resources are built and applied separately, in the reconcile step).
pub fn build(
    cluster: &ValidatedCluster,
    cluster_info: &KubernetesClusterInfo,
    service_account_name: &str,
) -> Result<KubernetesResources, Error> {
    let mut stateful_sets = vec![];
    let mut services = vec![];
    let mut listeners = vec![];
    let mut config_maps = vec![];
    let mut pod_disruption_budgets = vec![];

    for (role, role_group_configs) in &cluster.role_group_configs {
        for (role_group_name, role_group_config) in role_group_configs {
            let recommended_labels = cluster.recommended_labels(role, role_group_name);
            let selector = cluster.role_group_selector(role, role_group_name);

            services.push(build_rolegroup_headless_service(
                cluster,
                role,
                role_group_name,
                &recommended_labels,
                selector.clone().into(),
                headless_service_ports(cluster),
            ));
            services.push(build_rolegroup_metrics_service(
                cluster,
                role,
                role_group_name,
                &recommended_labels,
                selector.into(),
            ));
            config_maps.push(
                config_map::build_rolegroup_config_map(
                    cluster,
                    role,
                    role_group_name,
                    cluster_info,
                    &recommended_labels,
                )
                .context(ConfigMapSnafu {
                    role_group: role_group_name.clone(),
                })?,
            );
            config_maps.push(
                config_map::build_rolegroup_catalog_config_map(
                    cluster,
                    role,
                    role_group_name,
                    &recommended_labels,
                )
                .context(ConfigMapSnafu {
                    role_group: role_group_name.clone(),
                })?,
            );
            stateful_sets.push(
                statefulset::build_rolegroup_statefulset(
                    cluster,
                    role,
                    role_group_name,
                    role_group_config,
                    service_account_name,
                )
                .context(StatefulSetSnafu {
                    role_group: role_group_name.clone(),
                })?,
            );
        }

        let Some(role_config) = cluster.role_config(role) else {
            continue;
        };

        if let Some(listener_class) = &role_config.listener_class
            && let Some(listener_group_name) = group_listener_name(cluster, role)
        {
            listeners.push(build_group_listener(
                cluster,
                cluster.recommended_labels(role, &PLACEHOLDER_LISTENER_ROLE_GROUP),
                listener_class,
                listener_group_name,
            ));
        }

        pod_disruption_budgets.extend(build_pdb(&role_config.pdb, cluster, role));
    }

    Ok(KubernetesResources {
        stateful_sets,
        services,
        listeners,
        config_maps,
        pod_disruption_budgets,
    })
}

#[cfg(test)]
mod tests {
    use stackable_operator::{
        commons::networking::DomainName, kube::Resource, utils::cluster_info::KubernetesClusterInfo,
    };

    use super::build;
    use crate::controller::validated_cluster;

    /// Collects the `.metadata.name`s of the given resources, sorted for stable comparison.
    fn sorted_names(resources: &[impl Resource]) -> Vec<&str> {
        let mut names: Vec<&str> = resources
            .iter()
            .filter_map(|resource| resource.meta().name.as_deref())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn build_produces_expected_resource_names() {
        let cluster = validated_cluster();
        let cluster_info = KubernetesClusterInfo {
            cluster_domain: DomainName::try_from("cluster.local")
                .expect("cluster.local is a valid domain name"),
        };

        let resources =
            build(&cluster, &cluster_info, "simple-trino-serviceaccount").expect("build succeeds");

        // One StatefulSet per role group.
        assert_eq!(
            sorted_names(&resources.stateful_sets),
            [
                "simple-trino-coordinator-default",
                "simple-trino-worker-default",
            ]
        );
        // One headless and one metrics Service per role group.
        assert_eq!(
            sorted_names(&resources.services),
            [
                "simple-trino-coordinator-default-headless",
                "simple-trino-coordinator-default-metrics",
                "simple-trino-worker-default-headless",
                "simple-trino-worker-default-metrics",
            ]
        );
        // A config ConfigMap and a catalog ConfigMap per role group.
        assert_eq!(
            sorted_names(&resources.config_maps),
            [
                "simple-trino-coordinator-default",
                "simple-trino-coordinator-default-catalog",
                "simple-trino-worker-default",
                "simple-trino-worker-default-catalog",
            ]
        );
        // The coordinator is the only role with a group Listener.
        assert_eq!(
            sorted_names(&resources.listeners),
            ["simple-trino-coordinator"]
        );
        // A default PodDisruptionBudget per role.
        assert_eq!(
            sorted_names(&resources.pod_disruption_budgets),
            ["simple-trino-coordinator", "simple-trino-worker"]
        );
    }
}
