use std::{cmp::max, str::FromStr};

use stackable_operator::{
    commons::pdb::PdbConfig,
    k8s_openapi::api::policy::v1::PodDisruptionBudget,
    v2::{builder::pdb::pod_disruption_budget_builder_with_role, types::operator::RoleName},
};

use crate::{
    controller::{ValidatedCluster, controller_name, operator_name, product_name},
    crd::TrinoRole,
};

/// Builds the [`PodDisruptionBudget`] for the given `role`, or `None` if PDBs are disabled.
///
/// The reconciler applies the returned object; this function does not touch the cluster.
pub fn build_pdb(
    pdb: &PdbConfig,
    cluster: &ValidatedCluster,
    role: &TrinoRole,
) -> Option<PodDisruptionBudget> {
    if !pdb.enabled {
        return None;
    }
    let max_unavailable = pdb.max_unavailable.unwrap_or(match role {
        TrinoRole::Coordinator => max_unavailable_coordinators(),
        TrinoRole::Worker => max_unavailable_workers(worker_count(cluster)),
    });
    let role_name =
        RoleName::from_str(&role.to_string()).expect("a TrinoRole is a valid RFC 1123 role name");
    let pdb = pod_disruption_budget_builder_with_role(
        cluster,
        &product_name(),
        &role_name,
        &operator_name(),
        &controller_name(),
    )
    .with_max_unavailable(max_unavailable)
    .build();

    Some(pdb)
}

/// Total number of worker replicas across all worker role groups.
fn worker_count(cluster: &ValidatedCluster) -> u16 {
    cluster
        .role_group_configs
        .get(&TrinoRole::Worker)
        .into_iter()
        .flat_map(|groups| groups.values())
        .map(|rg| rg.replicas)
        .sum()
}

fn max_unavailable_coordinators() -> u16 {
    1
}

fn max_unavailable_workers(num_workers: u16) -> u16 {
    // As users normally scale Trino workers to achieve more performance, we can safely take out 10% of the workers.
    let max_unavailable = num_workers / 10;

    // Clamp to at least a single node allowed to be offline, so we don't block Kubernetes nodes from draining.
    max(max_unavailable, 1)
}

#[cfg(test)]
mod test {
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case(0, 1)]
    #[case(1, 1)]
    #[case(2, 1)]
    #[case(3, 1)]
    #[case(4, 1)]
    #[case(5, 1)]
    #[case(6, 1)]
    #[case(7, 1)]
    #[case(8, 1)]
    #[case(9, 1)]
    #[case(10, 1)]
    #[case(11, 1)]
    #[case(12, 1)]
    #[case(19, 1)]
    #[case(20, 2)]
    #[case(21, 2)]
    #[case(29, 2)]
    #[case(30, 3)]
    #[case(31, 3)]
    #[case(100, 10)]
    fn test_max_unavailable_servers(
        #[case] num_workers: u16,
        #[case] expected_max_unavailable: u16,
    ) {
        let max_unavailable = max_unavailable_workers(num_workers);
        assert_eq!(max_unavailable, expected_max_unavailable);
    }
}
