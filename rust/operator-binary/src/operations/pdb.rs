use std::cmp::max;

use snafu::{ResultExt, Snafu};
use stackable_operator::{
    builder::pdb::PodDisruptionBudgetBuilder, client::Client, cluster_resources::ClusterResources,
    commons::pdb::PdbConfig, kube::ResourceExt,
};
use stackable_trino_crd::{TrinoCluster, TrinoRole, APP_NAME};

use crate::controller::{CONTROLLER_NAME, OPERATOR_NAME};

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("Cannot create PodDisruptionBudget for role [{role}]"))]
    CreatePdb {
        source: stackable_operator::builder::pdb::Error,
        role: String,
    },

    #[snafu(display("Cannot apply PodDisruptionBudget [{name}]"))]
    ApplyPdb {
        source: stackable_operator::cluster_resources::Error,
        name: String,
    },
}

pub async fn add_pdbs(
    pdb: &PdbConfig,
    trino: &TrinoCluster,
    role: &TrinoRole,
    client: &Client,
    cluster_resources: &mut ClusterResources,
) -> Result<(), Error> {
    if !pdb.enabled {
        return Ok(());
    }
    let max_unavailable = pdb.max_unavailable.unwrap_or(match role {
        TrinoRole::Coordinator => max_unavailable_coordinators(),
        TrinoRole::Worker => max_unavailable_workers(trino.num_workers()),
    });
    let pdb = PodDisruptionBudgetBuilder::new_with_role(
        trino,
        APP_NAME,
        &role.to_string(),
        OPERATOR_NAME,
        CONTROLLER_NAME,
    )
    .with_context(|_| CreatePdbSnafu {
        role: role.to_string(),
    })?
    .with_max_unavailable(max_unavailable)
    .build();
    let pdb_name = pdb.name_any();
    cluster_resources
        .add(client, pdb)
        .await
        .with_context(|_| ApplyPdbSnafu { name: pdb_name })?;

    Ok(())
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
