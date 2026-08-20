//! Builders that turn a `ValidatedCluster` into Kubernetes resource contents.

use std::marker::PhantomData;

use snafu::{ResultExt, Snafu};
use stackable_operator::{
    builder::meta::ObjectMetaBuilder,
    kvp::Labels,
    utils::cluster_info::KubernetesClusterInfo,
    v2::{
        builder::meta::ownerreference_from_resource,
        kvp::label,
        types::operator::{RoleGroupName, RoleName},
    },
};

use crate::{
    controller::{
        KubernetesResources, Prepared, ValidatedCluster,
        build::resource::{
            config_map,
            listener::{build_group_listener, group_listener_name},
            pdb::build_pdb,
            rbac::{build_role_binding, build_service_account},
            service::{
                build_rolegroup_headless_service, build_rolegroup_metrics_service,
                headless_service_ports,
            },
            statefulset,
        },
    },
    trino_controller::{CONTROLLER_NAME, OPERATOR_NAME, PRODUCT_NAME},
};

pub mod command;
pub mod graceful_shutdown;
pub mod ports;
pub mod properties;
pub mod resource;

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
pub fn build(
    cluster: &ValidatedCluster,
    cluster_info: &KubernetesClusterInfo,
) -> Result<KubernetesResources<Prepared>, Error> {
    let mut stateful_sets = vec![];
    let mut services = vec![];
    let mut listeners = vec![];
    let mut config_maps = vec![];
    let mut pod_disruption_budgets = vec![];

    for (role, role_group_configs) in &cluster.role_group_configs {
        for (role_group_name, role_group_config) in role_group_configs {
            let selector = role_group_selector(cluster, role, role_group_name);

            services.push(build_rolegroup_headless_service(
                cluster,
                role,
                role_group_name,
                selector.clone().into(),
                headless_service_ports(cluster),
            ));
            services.push(build_rolegroup_metrics_service(
                cluster,
                role,
                role_group_name,
                selector.into(),
            ));
            config_maps.push(
                config_map::build_rolegroup_config_map(
                    cluster,
                    role,
                    role_group_name,
                    cluster_info,
                )
                .context(ConfigMapSnafu {
                    role_group: role_group_name.clone(),
                })?,
            );
            config_maps.push(
                config_map::build_rolegroup_catalog_config_map(cluster, role, role_group_name)
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
                role,
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
        service_accounts: vec![build_service_account(cluster)],
        role_bindings: vec![build_role_binding(cluster)],
        status: PhantomData,
    })
}

/// Returns an [`ObjectMetaBuilder`] pre-filled with the namespace, an owner reference back to
/// the cluster, the given `name`, and the given `labels` (usually one of the recommended label
/// sets built by the functions below).
///
/// Consolidates the metadata chain repeated by the child-resource builders. Call sites that
/// need extra labels/annotations chain them onto the returned builder.
pub(crate) fn object_meta(
    validated: &ValidatedCluster,
    name: impl Into<String>,
    labels: Labels,
) -> ObjectMetaBuilder {
    let mut builder = ObjectMetaBuilder::new();
    builder
        .name_and_namespace(validated)
        .name(name)
        .ownerreference(ownerreference_from_resource(validated, None, Some(true)))
        .with_labels(labels);
    builder
}

pub(crate) fn recommended_labels_for_cluster_resources(cluster: &ValidatedCluster) -> Labels {
    label::recommended_labels_for_cluster_resources(
        &cluster.name,
        &PRODUCT_NAME,
        &cluster.product_version,
        &OPERATOR_NAME,
        &CONTROLLER_NAME,
    )
}

pub(crate) fn recommended_labels_for_role_resources(
    cluster: &ValidatedCluster,
    role_name: &RoleName,
) -> Labels {
    label::recommended_labels_for_role_resources(
        &cluster.name,
        &PRODUCT_NAME,
        &cluster.product_version,
        &OPERATOR_NAME,
        &CONTROLLER_NAME,
        role_name,
    )
}

pub(crate) fn recommended_labels_for_role_group_resources(
    cluster: &ValidatedCluster,
    role_name: &RoleName,
    role_group_name: &RoleGroupName,
) -> Labels {
    label::recommended_labels_for_role_group_resources(
        &cluster.name,
        &PRODUCT_NAME,
        &cluster.product_version,
        &OPERATOR_NAME,
        &CONTROLLER_NAME,
        role_name,
        role_group_name,
    )
}

pub(crate) fn recommended_labels_for_unversioned_role_group_resources(
    cluster: &ValidatedCluster,
    role_name: &RoleName,
    role_group_name: &RoleGroupName,
) -> Labels {
    label::recommended_labels_for_unversioned_role_group_resources(
        &cluster.name,
        &PRODUCT_NAME,
        &OPERATOR_NAME,
        &CONTROLLER_NAME,
        role_name,
        role_group_name,
    )
}

/// Selector labels matching the pods of a role group.
pub(crate) fn role_group_selector(
    cluster: &ValidatedCluster,
    role_name: &RoleName,
    role_group_name: &RoleGroupName,
) -> Labels {
    label::role_group_selector(&cluster.name, &PRODUCT_NAME, role_name, role_group_name)
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

        let resources = build(&cluster, &cluster_info).expect("build succeeds");

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
        // The cluster-shared RBAC pair.
        assert_eq!(
            sorted_names(&resources.service_accounts),
            ["simple-trino-serviceaccount"]
        );
        assert_eq!(
            sorted_names(&resources.role_bindings),
            ["simple-trino-rolebinding"]
        );
    }
}
