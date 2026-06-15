//! Controller-level vocabulary: the [`ValidatedCluster`] type produced by the [`validate`] step
//! and consumed by the [`build`] steps, plus the `dereference` / `validate` / `build` sub-modules.

use std::{collections::BTreeMap, str::FromStr};

use stackable_operator::{
    commons::{
        affinity::StackableAffinity,
        product_image_selection::ResolvedProductImage,
        resources::{NoRuntimeLimits, Resources},
    },
    kube::{Resource, api::ObjectMeta},
    shared::time::Duration,
    v2::{
        role_group_utils::ResourceNames,
        types::{
            kubernetes::{NamespaceName, Uid},
            operator::{ClusterName, RoleGroupName as RoleGroupNameV2, RoleName},
        },
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
    crd::{
        HTTP_PORT, HTTP_PORT_NAME, HTTPS_PORT, HTTPS_PORT_NAME, TrinoRole, discovery::TrinoPodRef,
        v1alpha1,
    },
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

/// A validated, merged Trino role-group config.
///
/// Holds the merged [`v1alpha1::TrinoConfig`] fields so the build steps consume this
/// controller-owned type instead of the raw CRD struct (mirroring the opensearch- and
/// hive-operators' `Validated…Config`).
#[derive(Clone, Debug)]
pub struct ValidatedTrinoConfig {
    pub affinity: StackableAffinity,
    pub graceful_shutdown_timeout: Option<Duration>,
    pub logging: validate::ValidatedLogging,
    pub query_max_memory: Option<String>,
    pub query_max_memory_per_node: Option<String>,
    pub resources: Resources<v1alpha1::TrinoStorageConfig, NoRuntimeLimits>,
    pub requested_secret_lifetime: Option<Duration>,
}

impl ValidatedTrinoConfig {
    /// Builds the validated config from the merged [`v1alpha1::TrinoConfig`], swapping in the
    /// already-validated logging.
    fn from_merged(merged: v1alpha1::TrinoConfig, logging: validate::ValidatedLogging) -> Self {
        Self {
            affinity: merged.affinity,
            graceful_shutdown_timeout: merged.graceful_shutdown_timeout,
            logging,
            query_max_memory: merged.query_max_memory,
            query_max_memory_per_node: merged.query_max_memory_per_node,
            resources: merged.resources,
            requested_secret_lifetime: merged.requested_secret_lifetime,
        }
    }
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
        }
    }

    /// Whether the (client-facing) server TLS is enabled.
    pub fn server_tls_enabled(&self) -> bool {
        self.cluster_config.tls.server.is_some()
    }

    /// The client-facing port Trino exposes: HTTPS when server TLS is enabled, otherwise HTTP.
    ///
    /// Replaces `v1alpha1::TrinoCluster::exposed_port`, derived here from the validated TLS config
    /// so build steps don't re-read the raw cluster.
    pub fn exposed_port(&self) -> u16 {
        if self.server_tls_enabled() {
            HTTPS_PORT
        } else {
            HTTP_PORT
        }
    }

    /// The name of the client-facing port (see [`Self::exposed_port`]).
    pub fn exposed_protocol(&self) -> &'static str {
        if self.server_tls_enabled() {
            HTTPS_PORT_NAME
        } else {
            HTTP_PORT_NAME
        }
    }

    /// Type-safe names for the resources of a given role group.
    pub(crate) fn resource_names(&self, role: &TrinoRole, role_group_name: &str) -> ResourceNames {
        ResourceNames {
            cluster_name: self.name.clone(),
            role_name: RoleName::from_str(&role.to_string())
                .expect("a TrinoRole is a valid RFC 1123 role name"),
            role_group_name: RoleGroupNameV2::from_str(role_group_name)
                .expect("a validated role group name is a valid role group name"),
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

/// A minimal, valid TrinoCluster spec shared across unit tests.
#[cfg(test)]
pub(crate) const MINIMAL_TRINO_YAML: &str = r#"
    apiVersion: trino.stackable.tech/v1alpha1
    kind: TrinoCluster
    metadata:
      name: simple-trino
      namespace: default
      uid: "e6ac237d-a6d4-43a1-8135-f36506110912"
    spec:
      image:
        productVersion: "479"
      clusterConfig:
        catalogLabelSelector: {}
      coordinators:
        roleGroups:
          default:
            replicas: 1
      workers:
        roleGroups:
          default:
            replicas: 1
    "#;

/// Parses [`MINIMAL_TRINO_YAML`] into a [`v1alpha1::TrinoCluster`].
#[cfg(test)]
pub(crate) fn minimal_trino() -> v1alpha1::TrinoCluster {
    serde_yaml::from_str(MINIMAL_TRINO_YAML).expect("invalid test TrinoCluster YAML")
}

/// The validated [`MINIMAL_TRINO_YAML`] cluster with empty dereferenced inputs. The common test
/// fixture for build-step unit tests.
#[cfg(test)]
pub(crate) fn validated_cluster() -> ValidatedCluster {
    use stackable_operator::cli::OperatorEnvironmentOptions;

    use crate::controller::dereference::DereferencedObjects;

    let derefs = DereferencedObjects {
        resolved_authentication_classes: Vec::new(),
        catalog_definitions: Vec::new(),
        catalogs: Vec::new(),
        trino_opa_config: None,
        resolved_fte_config: None,
        resolved_client_protocol_config: None,
    };
    let operator_env = OperatorEnvironmentOptions {
        operator_namespace: "stackable-operators".to_string(),
        operator_service_name: "trino-operator".to_string(),
        image_repository: "oci.example.org".to_string(),
    };

    validate::validate(&minimal_trino(), &derefs, &operator_env).expect("validate should succeed")
}
