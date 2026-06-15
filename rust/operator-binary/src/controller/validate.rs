//! The validate step in the TrinoCluster controller.
//!
//! Synchronously validates inputs that don't require a Kubernetes client and
//! produces the typed [`ValidatedCluster`], consumed by `controller::build::*`.

use std::{collections::BTreeMap, str::FromStr};

use snafu::{ResultExt, Snafu};
use stackable_operator::{
    cli::OperatorEnvironmentOptions,
    commons::product_image_selection,
    config::fragment,
    kube::ResourceExt as _,
    role_utils::{GenericRoleConfig, RoleGroup},
    v2::{
        builder::pod::container::{self, EnvVarName, EnvVarSet},
        controller_utils::{get_cluster_name, get_namespace, get_uid},
        role_utils::{JavaCommonConfig, RoleGroupConfig, with_validated_config},
    },
};
use strum::{EnumDiscriminants, IntoEnumIterator, IntoStaticStr};

use super::{ValidatedCluster, ValidatedClusterConfig, ValidatedTls, ValidatedTrinoConfig};
use crate::{
    authentication::{self, TrinoAuthenticationConfig, TrinoAuthenticationTypes},
    controller::dereference::DereferencedObjects,
    crd::{TrinoRole, v1alpha1},
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

    #[snafu(display("failed to resolve and merge config for role group {role_group}"))]
    FailedToResolveConfig {
        source: fragment::ValidationError,
        role_group: String,
    },

    #[snafu(display("invalid environment variable override name"))]
    ParseEnvVarName { source: container::Error },
}

type Result<T, E = Error> = std::result::Result<T, E>;

pub type RoleGroupName = String;

pub type TrinoRoleGroupConfig =
    RoleGroupConfig<ValidatedTrinoConfig, JavaCommonConfig, v1alpha1::TrinoConfigOverrides>;

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
            crate::trino_controller::CONTAINER_IMAGE_BASE_NAME,
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
            // Merges and validates the role group config (default <- role <- role group). Because
            // `JavaCommonConfig` implements `Merge`, the role and role-group `jvmArgumentOverrides`
            // are merged here too and carried by `product_specific_common_config`.
            let merged = with_validated_config::<
                v1alpha1::TrinoConfig,
                JavaCommonConfig,
                v1alpha1::TrinoConfigFragment,
                GenericRoleConfig,
                v1alpha1::TrinoConfigOverrides,
            >(rg, &role, &default_config)
            .with_context(|_| FailedToResolveConfigSnafu {
                role_group: rg_name.clone(),
            })?;
            groups.insert(rg_name.clone(), into_role_group_config(merged)?);
        }
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
    ))
}

/// Adapts the validated [`RoleGroup`] produced by [`with_validated_config`] into the flattened
/// [`TrinoRoleGroupConfig`] consumed by the build steps.
///
/// Upstream `with_validated_config` returns a [`RoleGroup`] with a `HashMap` of env overrides and an
/// optional replica count; this converts it to the ergonomic [`RoleGroupConfig`] with an
/// [`EnvVarSet`] and a concrete replica count (defaulting to 1).
fn into_role_group_config(
    merged: RoleGroup<v1alpha1::TrinoConfig, JavaCommonConfig, v1alpha1::TrinoConfigOverrides>,
) -> Result<TrinoRoleGroupConfig> {
    let replicas = merged.replicas.unwrap_or(1);
    let common = merged.config;

    let mut env_overrides = EnvVarSet::new();
    for (name, value) in common.env_overrides {
        env_overrides = env_overrides.with_value(
            &EnvVarName::from_str(&name).context(ParseEnvVarNameSnafu)?,
            value,
        );
    }

    Ok(RoleGroupConfig {
        replicas,
        config: ValidatedTrinoConfig::from_merged(common.config),
        config_overrides: common.config_overrides,
        env_overrides,
        cli_overrides: common.cli_overrides,
        pod_overrides: common.pod_overrides,
        product_specific_common_config: common.product_specific_common_config,
    })
}

/// Test-only helper: merges and validates a single role group's config from an arbitrary
/// [`v1alpha1::TrinoCluster`] (with the given catalogs feeding `default_config`), reusing the
/// production merge path. Shared by the `crd::affinity` and `config::jvm` unit tests, which need a
/// merged config without dereferencing a full cluster.
#[cfg(test)]
pub(crate) fn merged_role_group_config(
    trino: &v1alpha1::TrinoCluster,
    trino_role: &TrinoRole,
    role_group: &str,
    trino_catalogs: &[crate::crd::catalog::v1alpha1::TrinoCatalog],
) -> TrinoRoleGroupConfig {
    let role = trino.role(trino_role).expect("role should be defined");
    let default_config =
        v1alpha1::TrinoConfig::default_config(&trino.name_any(), trino_role, trino_catalogs);
    let rg = role
        .role_groups
        .get(role_group)
        .expect("role group should be defined");
    let merged = with_validated_config::<
        v1alpha1::TrinoConfig,
        JavaCommonConfig,
        v1alpha1::TrinoConfigFragment,
        GenericRoleConfig,
        v1alpha1::TrinoConfigOverrides,
    >(rg, &role, &default_config)
    .expect("role group config should be valid");
    into_role_group_config(merged).expect("env overrides should be valid")
}

#[cfg(test)]
mod tests {
    use super::super::validated_cluster;
    use crate::crd::TrinoRole;

    #[test]
    fn validate_minimal_cluster() {
        let validated = validated_cluster();

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
