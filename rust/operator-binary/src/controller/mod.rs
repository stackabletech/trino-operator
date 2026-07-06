use std::{collections::BTreeMap, str::FromStr};

use stackable_operator::{
    builder::meta::ObjectMetaBuilder,
    commons::{
        affinity::StackableAffinity,
        product_image_selection::ResolvedProductImage,
        resources::{NoRuntimeLimits, Resources},
    },
    kube::{Resource, api::ObjectMeta},
    kvp::Labels,
    shared::time::Duration,
    v2::{
        HasName, HasUid, NameIsValidLabelValue,
        builder::meta::ownerreference_from_resource,
        kvp::label::{recommended_labels, role_group_selector},
        role_group_utils::ResourceNames,
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
    crd::{APP_NAME, TrinoRole, discovery::TrinoPodRef, v1alpha1},
    trino_controller::{CONTROLLER_NAME, OPERATOR_NAME},
};

pub(crate) mod build;
pub(crate) mod dereference;
pub(crate) mod validate;

pub use validate::{RoleGroupName, TrinoRoleGroupConfig};

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
    pub catalogs: Vec<CatalogConfig>,
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
    pub product_version: u16,
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
        product_version: u16,
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
            image,
            product_version,
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

    /// Type-safe names for the resources of a given role group.
    pub(crate) fn resource_names(
        &self,
        role: &TrinoRole,
        role_group_name: &RoleGroupName,
    ) -> ResourceNames {
        ResourceNames {
            cluster_name: self.name.clone(),
            role_name: Self::role_name(role),
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
            self.resource_names(role, role_group_name)
                .role_group_config_map()
        )
    }

    /// Returns an [`ObjectMetaBuilder`] pre-filled with this cluster's namespace, an owner
    /// reference back to the cluster, the resource `name` and the given `recommended_labels`.
    ///
    /// Consolidates the metadata chain repeated by the child-resource builders. Call sites that
    /// need extra labels/annotations chain them onto the returned builder.
    pub(crate) fn object_meta(
        &self,
        name: impl Into<String>,
        recommended_labels: Labels,
    ) -> ObjectMetaBuilder {
        let mut builder = ObjectMetaBuilder::new();
        builder
            .name_and_namespace(self)
            .name(name)
            .ownerreference(ownerreference_from_resource(self, None, Some(true)))
            .with_labels(recommended_labels);
        builder
    }

    /// A [`TrinoRole`] as a type-safe [`RoleName`].
    fn role_name(role: &TrinoRole) -> RoleName {
        RoleName::from_str(&role.to_string()).expect("a TrinoRole is a valid RFC 1123 role name")
    }

    /// The version label value (`app.kubernetes.io/version`) as a type-safe [`ProductVersion`].
    fn version_label(&self) -> ProductVersion {
        ProductVersion::from_str(&self.image.app_version_label_value)
            .expect("the app version label value is a valid product version")
    }

    fn recommended_labels_with_version(
        &self,
        version: &ProductVersion,
        role: &TrinoRole,
        role_group_name: &RoleGroupName,
    ) -> Labels {
        recommended_labels(
            self,
            &product_name(),
            version,
            &operator_name(),
            &controller_name(),
            &Self::role_name(role),
            role_group_name,
        )
    }

    /// Recommended labels for a role-group resource (using the resolved product version).
    pub(crate) fn recommended_labels(
        &self,
        role: &TrinoRole,
        role_group_name: &RoleGroupName,
    ) -> Labels {
        self.recommended_labels_with_version(&self.version_label(), role, role_group_name)
    }

    /// Recommended labels using a fixed `"none"` version, for resources whose labels must not
    /// change after creation (e.g. listener PVC templates).
    pub(crate) fn unversioned_recommended_labels(
        &self,
        role: &TrinoRole,
        role_group_name: &RoleGroupName,
    ) -> Labels {
        let none = ProductVersion::from_str("none")
            .expect("\"none\" is a valid product version label value");
        self.recommended_labels_with_version(&none, role, role_group_name)
    }

    /// Selector labels matching the pods of a role group.
    pub(crate) fn role_group_selector(
        &self,
        role: &TrinoRole,
        role_group_name: &RoleGroupName,
    ) -> Labels {
        role_group_selector(
            self,
            &product_name(),
            &Self::role_name(role),
            role_group_name,
        )
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
