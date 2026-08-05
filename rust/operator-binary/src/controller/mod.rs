use std::{collections::BTreeMap, marker::PhantomData, str::FromStr};

use stackable_operator::{
    commons::{
        affinity::StackableAffinity,
        product_image_selection::ResolvedProductImage,
        resources::{NoRuntimeLimits, Resources},
    },
    crd::listener::v1alpha1::Listener,
    k8s_openapi::api::{
        apps::v1::StatefulSet,
        core::v1::{ConfigMap, Service, ServiceAccount},
        policy::v1::PodDisruptionBudget,
        rbac::v1::RoleBinding,
    },
    kube::{Resource, api::ObjectMeta},
    kvp::Labels,
    memory::{BinaryMultiple, MemoryQuantity},
    shared::time::Duration,
    v2::{
        HasName, HasUid, NameIsValidLabelValue,
        kvp::label::{recommended_labels, role_group_selector},
        role_group_utils::ResourceNames,
        role_utils,
        types::{
            kubernetes::{ListenerClassName, NamespaceName, SecretClassName, Uid},
            operator::{
                ClusterName, ControllerName, OperatorName, ProductName, ProductVersion, RoleName,
            },
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
    crd::{APP_NAME, TrinoRole, catalog::TrinoCatalogName, discovery::TrinoPodRef, v1alpha1},
    trino_controller::{CONTROLLER_NAME, OPERATOR_NAME},
};

pub(crate) mod apply;
pub(crate) mod build;
pub(crate) mod dereference;
pub(crate) mod validate;

pub use stackable_operator::v2::product_logging::framework::STACKABLE_LOG_DIR;
pub use validate::{RoleGroupName, TrinoRoleGroupConfig};
pub const STACKABLE_LOG_CONFIG_DIR: &str = "/stackable/log_config";

pub const MAX_PREPARE_LOG_FILE_SIZE: MemoryQuantity = MemoryQuantity {
    value: 1.0,
    unit: BinaryMultiple::Mebi,
};

pub(crate) fn shared_internal_secret_name(cluster_name: &ClusterName) -> String {
    format!("{cluster_name}-internal-secret")
}

pub(crate) fn shared_spooling_secret_name(cluster_name: &ClusterName) -> String {
    format!("{cluster_name}-spooling-secret")
}

// Placeholder version label value for resources whose labels must not change after deployment.
stackable_operator::constant!(UNVERSIONED_PRODUCT_VERSION: ProductVersion = "none");

/// Marker for prepared Kubernetes resources which are not applied yet.
pub struct Prepared;

/// Marker for Kubernetes resources which have been applied to the Kubernetes cluster.
pub struct Applied;

/// Every Kubernetes resource produced by the client-free [`build()`](build::build) step.
///
/// `T` marks whether these resources are only [`Prepared`] or already [`Applied`]. The marker
/// lets the type system enforce, for example, that the cluster status is derived from the
/// resources the API server returned rather than from the ones we merely built.
pub struct KubernetesResources<T> {
    pub stateful_sets: Vec<StatefulSet>,
    pub services: Vec<Service>,
    pub listeners: Vec<Listener>,
    pub config_maps: Vec<ConfigMap>,
    pub pod_disruption_budgets: Vec<PodDisruptionBudget>,
    pub service_accounts: Vec<ServiceAccount>,
    pub role_bindings: Vec<RoleBinding>,
    pub status: PhantomData<T>,
}

#[derive(Clone, Debug)]
pub struct ValidatedTls {
    pub server: Option<SecretClassName>,
    pub internal: Option<SecretClassName>,
}

/// Cluster-wide settings, grouped to parallel `spec.clusterConfig` CRD.
#[derive(Clone, Debug)]
pub struct ValidatedClusterConfig {
    pub tls: ValidatedTls,
    pub authentication: TrinoAuthenticationConfig,
    pub authorization: Option<TrinoOpaConfig>,
    pub fault_tolerant_execution: Option<ResolvedFaultTolerantExecutionConfig>,
    pub client_protocol: Option<ResolvedClientProtocolConfig>,
    pub coordinator_pod_refs: Vec<TrinoPodRef>,
    pub catalogs: BTreeMap<TrinoCatalogName, CatalogConfig>,
}

impl ValidatedClusterConfig {
    /// Whether any authentication is configured.
    pub fn authentication_enabled(&self) -> bool {
        !self.authentication.is_empty()
    }
}

/// A validated, merged Trino role-group config.
///
/// Holds the merged [`v1alpha1::TrinoConfig`] fields so the build steps consume this
/// controller-owned type instead of the raw CRD struct.
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

/// Per-role configuration extracted during validation.
///
/// Lets the reconciler and build steps consume this controller-owned type instead of re-reading
/// the raw [`v1alpha1::TrinoCluster`].
#[derive(Clone, Debug)]
pub struct ValidatedRoleConfig {
    pub pdb: stackable_operator::commons::pdb::PdbConfig,
    /// The listener class for the role's group listener, if it has one (coordinator only).
    pub listener_class: Option<ListenerClassName>,
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
    /// The numeric Trino version (e.g. `481`), used for version-dependent configuration.
    pub numeric_product_version: u16,
    /// The version label value (`app.kubernetes.io/version`) as a type-safe [`ProductVersion`],
    /// parsed once from the resolved image's app version label value.
    pub product_version: ProductVersion,
    pub cluster_config: ValidatedClusterConfig,
    pub role_configs: BTreeMap<TrinoRole, ValidatedRoleConfig>,
    pub role_group_configs: BTreeMap<TrinoRole, BTreeMap<RoleGroupName, TrinoRoleGroupConfig>>,
}

impl ValidatedCluster {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: ClusterName,
        namespace: NamespaceName,
        uid: Uid,
        image: ResolvedProductImage,
        numeric_product_version: u16,
        cluster_config: ValidatedClusterConfig,
        role_configs: BTreeMap<TrinoRole, ValidatedRoleConfig>,
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
            product_version: ProductVersion::from_str(&image.app_version_label_value)
                .expect("the app version label value is a valid product version"),
            image,
            numeric_product_version,
            cluster_config,
            role_configs,
            role_group_configs,
        }
    }

    /// The validated per-role config for `role`, if the role is defined.
    pub(crate) fn role_config(&self, role: &TrinoRole) -> Option<&ValidatedRoleConfig> {
        self.role_configs.get(role)
    }

    /// Whether the (client-facing) server TLS is enabled.
    pub fn server_tls_enabled(&self) -> bool {
        self.cluster_config.tls.server.is_some()
    }

    /// Whether internal (inter-node) TLS is enabled.
    pub fn internal_tls_enabled(&self) -> bool {
        self.cluster_config.tls.internal.is_some()
    }

    /// The user-provided server TLS SecretClass, if any.
    pub fn get_server_tls(&self) -> Option<&SecretClassName> {
        self.cluster_config.tls.server.as_ref()
    }

    /// The user-provided internal TLS SecretClass, if any.
    pub fn get_internal_tls(&self) -> Option<&SecretClassName> {
        self.cluster_config.tls.internal.as_ref()
    }

    /// Whether client TLS should be set, depending on authentication and server TLS settings.
    pub fn tls_enabled(&self) -> bool {
        self.cluster_config.authentication_enabled() || self.server_tls_enabled()
    }

    /// Type-safe names for the per-cluster RBAC resources: the ServiceAccount shared by all
    /// Pods, its (namespaced) RoleBinding, and the operator-deployed ClusterRole it binds.
    pub fn cluster_resource_names(&self) -> role_utils::ResourceNames {
        role_utils::ResourceNames {
            cluster_name: self.name.clone(),
            product_name: product_name(),
        }
    }

    /// Type-safe names for the resources of a given role group.
    pub(crate) fn role_group_resource_names(
        &self,
        role: &TrinoRole,
        role_group_name: &RoleGroupName,
    ) -> ResourceNames {
        ResourceNames {
            cluster_name: self.name.clone(),
            role_name: role.into(),
            role_group_name: role_group_name.clone(),
        }
    }

    /// Name of the rolegroup's catalog `ConfigMap`, derived from the rolegroup config map name
    /// by appending the `-catalog` suffix.
    pub(crate) fn role_group_catalog_config_map_name(
        &self,
        role: &TrinoRole,
        role_group_name: &RoleGroupName,
    ) -> String {
        format!(
            "{}-catalog",
            self.role_group_resource_names(role, role_group_name)
                .role_group_config_map()
        )
    }

    /// A [`TrinoRole`] as a type-safe [`RoleName`].
    fn recommended_labels_with(
        &self,
        version: &ProductVersion,
        role_name: &RoleName,
        role_group_name: &RoleGroupName,
    ) -> Labels {
        recommended_labels(
            self,
            &product_name(),
            version,
            &operator_name(),
            &controller_name(),
            role_name,
            role_group_name,
        )
    }

    /// Recommended labels for a role-group resource (using the resolved product version).
    pub fn recommended_labels(&self, role: &TrinoRole, role_group_name: &RoleGroupName) -> Labels {
        self.recommended_labels_for(&role.into(), role_group_name)
    }

    /// Recommended labels for a resource that is not tied to a concrete [`TrinoRole`] (e.g. the
    /// cluster-shared RBAC resources), using a free-form role/role-group label value.
    pub fn recommended_labels_for(
        &self,
        role_name: &RoleName,
        role_group_name: &RoleGroupName,
    ) -> Labels {
        self.recommended_labels_with(&self.product_version, role_name, role_group_name)
    }

    /// Recommended labels with the constant [`UNVERSIONED_PRODUCT_VERSION`], for resources whose
    /// labels must not change after creation (e.g. listener PVC templates).
    pub fn unversioned_recommended_labels(
        &self,
        role: &TrinoRole,
        role_group_name: &RoleGroupName,
    ) -> Labels {
        self.recommended_labels_with(&UNVERSIONED_PRODUCT_VERSION, &role.into(), role_group_name)
    }

    /// Selector labels matching the pods of a role group.
    pub fn role_group_selector(&self, role: &TrinoRole, role_group_name: &RoleGroupName) -> Labels {
        role_group_selector(self, &product_name(), &role.into(), role_group_name)
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

impl HasName for ValidatedCluster {
    fn to_name(&self) -> String {
        self.name.to_string()
    }
}

impl HasUid for ValidatedCluster {
    fn to_uid(&self) -> Uid {
        self.uid.clone()
    }
}

impl NameIsValidLabelValue for ValidatedCluster {
    fn to_label_value(&self) -> String {
        self.name.to_label_value()
    }
}

/// The product name (`trino`) as a type-safe label value.
pub(crate) fn product_name() -> ProductName {
    ProductName::from_str(APP_NAME).expect("'trino' is a valid product name")
}

/// The operator name as a type-safe label value.
pub(crate) fn operator_name() -> OperatorName {
    OperatorName::from_str(OPERATOR_NAME).expect("the operator name is a valid label value")
}

/// The controller name as a type-safe label value.
pub(crate) fn controller_name() -> ControllerName {
    ControllerName::from_str(CONTROLLER_NAME).expect("the controller name is a valid label value")
}

/// The expected `app.kubernetes.io/version` label value for the given product version.
///
/// The `-stackable` suffix carries the operator's own version, which is `0.0.0-dev` on main
/// but rewritten by the release process — so tests must derive it rather than hardcode it,
/// or they fail on release branches.
#[cfg(test)]
pub(crate) fn app_version_label(product_version: &str) -> String {
    format!(
        "{product_version}-stackable{}",
        crate::built_info::PKG_VERSION
    )
}

/// A minimal, valid TrinoCluster spec shared across unit tests.
///
/// The cluster name (`simple-trino`) deliberately differs from the product name (`trino`), so
/// tests asserting recommended labels catch swapped `name`/`instance` values.
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
        productVersion: "481"
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

#[cfg(test)]
mod tests {
    use stackable_operator::v2::types::operator::RoleName;
    use strum::IntoEnumIterator;

    use crate::crd::TrinoRole;

    /// Locks the invariant behind the `expect` in the `From<TrinoRole> for RoleName` impls:
    /// every `TrinoRole` variant (present and future) must serialise to a valid `RoleName`.
    #[test]
    fn every_trino_role_serialises_to_a_valid_role_name() {
        for role in TrinoRole::iter() {
            let _: RoleName = (&role).into();
            let _: RoleName = role.into();
        }
    }
}
