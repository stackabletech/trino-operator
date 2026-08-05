//! The apply step in the TrinoCluster controller.

use std::marker::PhantomData;

use snafu::{ResultExt, Snafu};
use stackable_operator::{
    client::Client,
    cluster_resources::{ClusterResource, ClusterResourceApplyStrategy, ClusterResources},
    commons::random_secret_creation,
    deep_merger::ObjectOverrides,
    v2::cluster_resources::cluster_resources_new,
};
use strum::{EnumDiscriminants, IntoStaticStr};

use crate::{
    controller::{
        Applied, KubernetesResources, Prepared, ValidatedCluster, controller_name, operator_name,
        product_name, shared_internal_secret_name, shared_spooling_secret_name,
    },
    crd::{ENV_INTERNAL_SECRET, ENV_SPOOLING_SECRET},
};

#[derive(Snafu, Debug, EnumDiscriminants)]
#[strum_discriminants(derive(IntoStaticStr))]
pub enum Error {
    #[snafu(display("failed to apply Kubernetes resource"))]
    ApplyResource {
        source: stackable_operator::cluster_resources::Error,
    },

    #[snafu(display("failed to delete orphaned resources"))]
    DeleteOrphanedResources {
        source: stackable_operator::cluster_resources::Error,
    },

    #[snafu(display("failed to create internal secret"))]
    CreateInternalSecret {
        source: random_secret_creation::Error,
    },
}

type Result<T, E = Error> = std::result::Result<T, E>;

/// Applier for the Kubernetes resource specifications produced by this controller.
///
/// The implementation is not tied to this controller and could theoretically be moved to
/// stackable_operator if [`KubernetesResources`] would contain all possible resource types.
pub struct Applier<'a> {
    client: &'a Client,
    cluster_resources: ClusterResources<'a>,
}

impl<'a> Applier<'a> {
    pub fn new(
        client: &'a Client,
        cluster: &ValidatedCluster,
        apply_strategy: ClusterResourceApplyStrategy,
        object_overrides: &'a ObjectOverrides,
    ) -> Applier<'a> {
        let cluster_resources = cluster_resources_new(
            &product_name(),
            &operator_name(),
            &controller_name(),
            &cluster.name,
            &cluster.namespace,
            &cluster.uid,
            apply_strategy,
            object_overrides,
        );

        Applier {
            client,
            cluster_resources,
        }
    }

    /// Applies the given Kubernetes resources and marks them as applied.
    ///
    /// Resources that are owned by this cluster but no longer part of `resources` are deleted
    /// afterwards.
    pub async fn apply(
        mut self,
        resources: KubernetesResources<Prepared>,
    ) -> Result<KubernetesResources<Applied>> {
        // Destructured without `..`, so that adding a field to [`KubernetesResources`] fails to
        // compile here instead of the new resource silently never being applied.
        let KubernetesResources {
            stateful_sets,
            services,
            listeners,
            config_maps,
            pod_disruption_budgets,
            service_accounts,
            role_bindings,
            status: _,
        } = resources;

        // The ServiceAccount comes first, because the Pods reference it at creation time.
        let service_accounts = self.add_resources(service_accounts).await?;
        let role_bindings = self.add_resources(role_bindings).await?;
        let services = self.add_resources(services).await?;
        let listeners = self.add_resources(listeners).await?;
        let config_maps = self.add_resources(config_maps).await?;
        let pod_disruption_budgets = self.add_resources(pod_disruption_budgets).await?;

        // Note: The StatefulSet needs to be applied after all ConfigMaps and Secrets it mounts
        // to prevent unnecessary Pod restarts.
        // See https://github.com/stackabletech/commons-operator/issues/111 for details.
        let stateful_sets = self.add_resources(stateful_sets).await?;

        self.cluster_resources
            .delete_orphaned_resources(self.client)
            .await
            .context(DeleteOrphanedResourcesSnafu)?;

        Ok(KubernetesResources {
            stateful_sets,
            services,
            listeners,
            config_maps,
            pod_disruption_budgets,
            service_accounts,
            role_bindings,
            status: PhantomData,
        })
    }

    /// Applies the given resources and returns them as the API server echoed them back.
    async fn add_resources<T: ClusterResource + Sync>(
        &mut self,
        resources: Vec<T>,
    ) -> Result<Vec<T>> {
        let mut applied_resources = vec![];

        for resource in resources {
            let applied_resource = self
                .cluster_resources
                .add(self.client, resource)
                .await
                .context(ApplyResourceSnafu)?;
            applied_resources.push(applied_resource);
        }

        Ok(applied_resources)
    }
}

/// Ensures the two shared random Secrets (internal communication and spooling) exist, creating
/// any that are missing.
///
/// These are read-or-create client operations, so they cannot be part of the client-free
/// `build()` step. They are also deliberately not tracked in [`ClusterResources`], so that they
/// survive orphan deletion and an existing Secret is never overwritten (rotating them would
/// invalidate all running queries).
pub async fn ensure_random_secrets(client: &Client, cluster: &ValidatedCluster) -> Result<()> {
    random_secret_creation::create_random_secret_if_not_exists(
        &shared_internal_secret_name(&cluster.name),
        ENV_INTERNAL_SECRET,
        512,
        cluster,
        client,
    )
    .await
    .context(CreateInternalSecretSnafu)?;

    // This secret is created even if spooling is not configured.
    // Trino currently requires the secret to be exactly 256 bits long.
    random_secret_creation::create_random_secret_if_not_exists(
        &shared_spooling_secret_name(&cluster.name),
        ENV_SPOOLING_SECRET,
        32,
        cluster,
        client,
    )
    .await
    .context(CreateInternalSecretSnafu)?;

    Ok(())
}
