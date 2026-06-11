//! Controller-level vocabulary: the [`ValidatedCluster`] type produced by the [`validate`] step
//! and consumed by the [`build`] steps, plus the `dereference` / `validate` / `build` sub-modules.

use std::collections::BTreeMap;

use stackable_operator::{
    commons::product_image_selection::ResolvedProductImage,
    kube::{Resource, api::ObjectMeta},
    role_utils::JvmArgumentOverrides,
    v2::types::{
        kubernetes::{NamespaceName, Uid},
        operator::ClusterName,
    },
};

use crate::{
    authentication::TrinoAuthenticationConfig,
    authorization::opa::TrinoOpaConfig,
    catalog::config::CatalogConfig,
    config::{
        client_protocol::ResolvedClientProtocolConfig,
        fault_tolerant_execution::ResolvedFaultTolerantExecutionConfig,
    },
    crd::{TrinoRole, discovery::TrinoPodRef, v1alpha1},
};

pub(crate) mod build;
pub(crate) mod dereference;
pub(crate) mod validate;

pub use validate::{RoleGroupName, TrinoRoleGroupConfig};

#[derive(Clone, Debug)]
pub struct ValidatedTls {
    pub server: Option<String>,
    pub internal: Option<String>,
}

/// Cluster-wide settings, grouped to parallel `spec.clusterConfig` CRD.
#[derive(Clone, Debug)]
pub struct ValidatedClusterConfig {
    pub tls: ValidatedTls,
    pub authentication: TrinoAuthenticationConfig,
    pub authentication_enabled: bool,
    pub authorization: Option<TrinoOpaConfig>,
    pub fault_tolerant_execution: Option<ResolvedFaultTolerantExecutionConfig>,
    pub client_protocol: Option<ResolvedClientProtocolConfig>,
    pub coordinator_pod_refs: Vec<TrinoPodRef>,
    pub catalogs: Vec<CatalogConfig>,
}

/// The validated TrinoCluster. The output of the validate step.
#[derive(Clone, Debug)]
pub struct ValidatedCluster {
    /// Metadata mirroring the source [`v1alpha1::TrinoCluster`] (name, namespace and UID).
    ///
    /// Kept private and only exposed through the [`Resource`] implementation, so that a
    /// `ValidatedCluster` can be used directly as the owner of generated objects (e.g. to set
    /// owner references) without threading the raw `TrinoCluster` through the build step.
    metadata: ObjectMeta,
    pub name: ClusterName,
    pub namespace: NamespaceName,
    pub uid: Uid,
    pub image: ResolvedProductImage,
    pub product_version: u16,
    pub cluster_config: ValidatedClusterConfig,
    pub role_group_configs: BTreeMap<TrinoRole, BTreeMap<RoleGroupName, TrinoRoleGroupConfig>>,
    /// Role-level JVM argument overrides per role. Required to render `jvm.config` in the build
    /// step without access to the raw [`v1alpha1::TrinoCluster`] (the role-group level overrides
    /// are carried by [`TrinoRoleGroupConfig::product_specific_common_config`]).
    pub role_jvm_argument_overrides: BTreeMap<TrinoRole, JvmArgumentOverrides>,
}

impl ValidatedCluster {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: ClusterName,
        namespace: NamespaceName,
        uid: Uid,
        image: ResolvedProductImage,
        product_version: u16,
        cluster_config: ValidatedClusterConfig,
        role_group_configs: BTreeMap<TrinoRole, BTreeMap<RoleGroupName, TrinoRoleGroupConfig>>,
        role_jvm_argument_overrides: BTreeMap<TrinoRole, JvmArgumentOverrides>,
    ) -> Self {
        Self {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(namespace.to_string()),
                uid: Some(uid.to_string()),
                ..ObjectMeta::default()
            },
            name,
            namespace,
            uid,
            image,
            product_version,
            cluster_config,
            role_group_configs,
            role_jvm_argument_overrides,
        }
    }
}

impl Resource for ValidatedCluster {
    type DynamicType = <v1alpha1::TrinoCluster as Resource>::DynamicType;
    type Scope = <v1alpha1::TrinoCluster as Resource>::Scope;

    fn kind(dt: &Self::DynamicType) -> std::borrow::Cow<'_, str> {
        v1alpha1::TrinoCluster::kind(dt)
    }

    fn group(dt: &Self::DynamicType) -> std::borrow::Cow<'_, str> {
        v1alpha1::TrinoCluster::group(dt)
    }

    fn version(dt: &Self::DynamicType) -> std::borrow::Cow<'_, str> {
        v1alpha1::TrinoCluster::version(dt)
    }

    fn plural(dt: &Self::DynamicType) -> std::borrow::Cow<'_, str> {
        v1alpha1::TrinoCluster::plural(dt)
    }

    fn meta(&self) -> &ObjectMeta {
        &self.metadata
    }

    fn meta_mut(&mut self) -> &mut ObjectMeta {
        &mut self.metadata
    }
}
