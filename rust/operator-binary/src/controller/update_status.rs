//! The update_status step in the TrinoCluster controller.

use snafu::{ResultExt, Snafu};
use stackable_operator::{
    client::Client,
    status::condition::{
        compute_conditions, operations::ClusterOperationsConditionBuilder,
        statefulset::StatefulSetConditionBuilder,
    },
};
use strum::{EnumDiscriminants, IntoStaticStr};

use crate::{
    controller::{Applied, KubernetesResources},
    crd::v1alpha1,
    trino_controller::TRINO_OPERATOR_NAME,
};

#[derive(Snafu, Debug, EnumDiscriminants)]
#[strum_discriminants(derive(IntoStaticStr))]
pub enum Error {
    #[snafu(display("failed to update status"))]
    ApplyStatus {
        source: stackable_operator::client::Error,
    },
}

type Result<T, E = Error> = std::result::Result<T, E>;

/// Computes the cluster status from the applied resources and patches it onto the
/// [`v1alpha1::TrinoCluster`].
///
/// Takes [`KubernetesResources<Applied>`], so the type system proves that the status is derived
/// from the resources the API server acknowledged and not from the ones we merely built. They are
/// consumed, because this is the last step of the reconciliation pipeline.
pub async fn update_status(
    client: &Client,
    trino: &v1alpha1::TrinoCluster,
    applied: KubernetesResources<Applied>,
) -> Result<()> {
    let mut sts_cond_builder = StatefulSetConditionBuilder::default();
    for stateful_set in applied.stateful_sets {
        sts_cond_builder.add(stateful_set);
    }

    let cluster_operation_cond_builder =
        ClusterOperationsConditionBuilder::new(&trino.spec.cluster_operation);

    let status = v1alpha1::TrinoClusterStatus {
        conditions: compute_conditions(
            trino,
            &[&sts_cond_builder, &cluster_operation_cond_builder],
        ),
    };

    client
        .apply_patch_status(TRINO_OPERATOR_NAME, trino, &status)
        .await
        .context(ApplyStatusSnafu)?;

    Ok(())
}
