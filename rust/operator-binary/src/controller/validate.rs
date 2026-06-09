//! The validate step in the TrinoCluster controller.
//!
//! Synchronously validates inputs that don't require a Kubernetes client and
//! produces the typed [`ValidatedCluster`], consumed by `controller::build::*`.

use std::{collections::BTreeMap, str::FromStr};

use snafu::{ResultExt, Snafu};
use stackable_operator::{
    cli::OperatorEnvironmentOptions,
    commons::product_image_selection::{self, ResolvedProductImage},
    kube::{Resource, ResourceExt as _, api::ObjectMeta},
    role_utils::{GenericRoleConfig, JavaCommonConfig, JvmArgumentOverrides},
    v2::{
        controller_utils::{get_cluster_name, get_namespace, get_uid},
        types::{
            kubernetes::{NamespaceName, Uid},
            operator::ClusterName,
        },
    },
};
use strum::{EnumDiscriminants, IntoEnumIterator, IntoStaticStr};

use crate::{
    authentication::{self, TrinoAuthenticationConfig, TrinoAuthenticationTypes},
    authorization::opa::TrinoOpaConfig,
    catalog::config::CatalogConfig,
    config::{
        client_protocol::ResolvedClientProtocolConfig,
        fault_tolerant_execution::ResolvedFaultTolerantExecutionConfig,
    },
    controller::dereference::DereferencedObjects,
    crd::{TrinoRole, discovery::TrinoPodRef, v1alpha1},
    framework::role_utils::with_validated_config,
};

#[derive(Snafu, Debug, EnumDiscriminants)]
#[strum_discriminants(derive(IntoStaticStr))]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    #[snafu(display("failed to resolve product image"))]
    ResolveProductImage {
        source: product_image_selection::Error,
    },

    #[snafu(display("failed to get the cluster name"))]
    GetClusterName {
        source: stackable_operator::v2::controller_utils::Error,
    },

    #[snafu(display("failed to get the cluster namespace"))]
    GetClusterNamespace {
        source: stackable_operator::v2::controller_utils::Error,
    },

    #[snafu(display("failed to get the cluster UID"))]
    GetClusterUid {
        source: stackable_operator::v2::controller_utils::Error,
    },

    #[snafu(display("unable to parse Trino version {product_version:?}"))]
    ParseTrinoVersion {
        source: std::num::ParseIntError,
        product_version: String,
    },

    #[snafu(display("unsupported Trino authentication"))]
    UnsupportedAuthenticationConfig { source: authentication::Error },

    #[snafu(display("invalid Trino authentication"))]
    InvalidAuthenticationConfig { source: authentication::Error },

    #[snafu(display(
        "client spooling protocol is not supported for Trino version {product_version}"
    ))]
    ClientSpoolingProtocolTrinoVersion { product_version: String },

    #[snafu(display("object defines no {role:?} role"))]
    MissingTrinoRole {
        source: crate::crd::Error,
        role: String,
    },

    #[snafu(display("failed to validate config fragment"))]
    InvalidConfigFragment {
        source: stackable_operator::config::fragment::ValidationError,
    },
}

type Result<T, E = Error> = std::result::Result<T, E>;

pub type RoleGroupName = String;

pub type TrinoRoleGroupConfig = crate::framework::role_utils::RoleGroupConfig<
    v1alpha1::TrinoConfig,
    JavaCommonConfig,
    v1alpha1::TrinoConfigOverrides,
>;

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

/// Validates the cluster spec and dereferenced inputs.
pub fn validate(
    trino: &v1alpha1::TrinoCluster,
    dereferenced_objects: &DereferencedObjects,
    operator_environment: &OperatorEnvironmentOptions,
) -> Result<ValidatedCluster> {
    let namespace = get_namespace(trino).context(GetClusterNamespaceSnafu)?;

    let image = trino
        .spec
        .image
        .resolve(
            super::CONTAINER_IMAGE_BASE_NAME,
            &operator_environment.image_repository,
            crate::built_info::PKG_VERSION,
        )
        .context(ResolveProductImageSnafu)?;

    let product_version =
        u16::from_str(&image.product_version).context(ParseTrinoVersionSnafu {
            product_version: image.product_version.clone(),
        })?;

    let authentication = TrinoAuthenticationConfig::new(
        &image,
        TrinoAuthenticationTypes::try_from(
            dereferenced_objects.resolved_authentication_classes.clone(),
        )
        .context(UnsupportedAuthenticationConfigSnafu)?,
    )
    .context(InvalidAuthenticationConfigSnafu)?;

    if dereferenced_objects
        .resolved_client_protocol_config
        .is_some()
        && image.product_version.starts_with("45")
    {
        return Err(Error::ClientSpoolingProtocolTrinoVersion {
            product_version: image.product_version.clone(),
        });
    }

    let mut role_group_configs: BTreeMap<TrinoRole, BTreeMap<RoleGroupName, TrinoRoleGroupConfig>> =
        BTreeMap::new();
    let mut role_jvm_argument_overrides: BTreeMap<TrinoRole, JvmArgumentOverrides> =
        BTreeMap::new();
    for trino_role in TrinoRole::iter() {
        let role = trino
            .role(&trino_role)
            .with_context(|_| MissingTrinoRoleSnafu {
                role: trino_role.to_string(),
            })?;
        let default_config = v1alpha1::TrinoConfig::default_config(
            &trino.name_any(),
            &trino_role,
            &dereferenced_objects.catalog_definitions,
        );
        let mut groups = BTreeMap::new();
        for (rg_name, rg) in &role.role_groups {
            let validated_rg = with_validated_config::<
                v1alpha1::TrinoConfig,
                JavaCommonConfig,
                v1alpha1::TrinoConfigFragment,
                GenericRoleConfig,
                v1alpha1::TrinoConfigOverrides,
            >(rg, &role, &default_config)
            .context(InvalidConfigFragmentSnafu)?;
            groups.insert(rg_name.clone(), validated_rg);
        }
        role_jvm_argument_overrides.insert(
            trino_role.clone(),
            role.config
                .product_specific_common_config
                .jvm_argument_overrides
                .clone(),
        );
        role_group_configs.insert(trino_role, groups);
    }

    let cluster_config = ValidatedClusterConfig {
        tls: ValidatedTls {
            server: trino.get_server_tls().map(String::from),
            internal: trino.get_internal_tls().map(String::from),
        },
        authentication,
        authentication_enabled: trino.authentication_enabled(),
        authorization: dereferenced_objects.trino_opa_config.clone(),
        fault_tolerant_execution: dereferenced_objects.resolved_fte_config.clone(),
        client_protocol: dereferenced_objects.resolved_client_protocol_config.clone(),
        coordinator_pod_refs: trino.coordinator_pods(&namespace).collect(),
        catalogs: dereferenced_objects.catalogs.clone(),
    };

    let name = get_cluster_name(trino).context(GetClusterNameSnafu)?;
    let uid = get_uid(trino).context(GetClusterUidSnafu)?;

    Ok(ValidatedCluster::new(
        name,
        namespace,
        uid,
        image,
        product_version,
        cluster_config,
        role_group_configs,
        role_jvm_argument_overrides,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL_TRINO_YAML: &str = r#"
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

    #[test]
    fn validate_minimal_cluster() {
        let trino: v1alpha1::TrinoCluster =
            serde_yaml::from_str(MINIMAL_TRINO_YAML).expect("invalid test input");
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

        let validated = validate(&trino, &derefs, &operator_env).expect("validate should succeed");

        assert_eq!(validated.name.to_string(), "simple-trino");
        assert_eq!(validated.namespace.to_string(), "default");
        assert_eq!(
            validated.uid.to_string(),
            "e6ac237d-a6d4-43a1-8135-f36506110912"
        );
        assert_eq!(validated.product_version, 479);
        assert!(!validated.cluster_config.authentication_enabled);
        assert!(
            validated
                .role_group_configs
                .contains_key(&TrinoRole::Coordinator)
        );
        assert!(
            validated
                .role_group_configs
                .contains_key(&TrinoRole::Worker)
        );
        assert_eq!(
            validated.role_group_configs[&TrinoRole::Coordinator]["default"].replicas,
            1
        );
    }
}
