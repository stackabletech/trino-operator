//! The validate step in the TrinoCluster controller.
//!
//! Synchronously validates inputs that don't require a Kubernetes client and
//! produces the typed [`ValidatedCluster`], consumed by `controller::build::*`.

use std::{collections::BTreeMap, str::FromStr};

use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::{
    cli::OperatorEnvironmentOptions,
    commons::product_image_selection,
    config::fragment,
    kube::ResourceExt as _,
    product_logging::spec::Logging,
    role_utils::{GenericRoleConfig, RoleGroup},
    v2::{
        builder::pod::container::{self, EnvVarName, EnvVarSet},
        controller_utils::{get_cluster_name, get_namespace, get_uid},
        product_logging::framework::{
            ValidatedContainerLogConfigChoice, VectorContainerLogConfig,
            validate_logging_configuration_for_container,
        },
        role_utils::{JavaCommonConfig, RoleGroupConfig, with_validated_config},
        types::kubernetes::ConfigMapName,
    },
};
use strum::{EnumDiscriminants, IntoEnumIterator, IntoStaticStr};

use super::{
    ValidatedCluster, ValidatedClusterConfig, ValidatedRoleConfig, ValidatedTls,
    ValidatedTrinoConfig,
};
use crate::{
    authentication::{self, TrinoAuthenticationConfig, TrinoAuthenticationTypes},
    controller::dereference::DereferencedObjects,
    crd::{Container, TrinoRole, v1alpha1},
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

    #[snafu(display("failed to validate logging configuration"))]
    ValidateLoggingConfig {
        source: stackable_operator::v2::product_logging::framework::Error,
    },

    #[snafu(display(
        "the Vector aggregator discovery ConfigMap name is required when the Vector agent is enabled"
    ))]
    MissingVectorAggregatorConfigMapName,
}

type Result<T, E = Error> = std::result::Result<T, E>;

pub type RoleGroupName = String;

/// Validated logging configuration for the Trino, prepare and (optional) Vector containers.
///
/// Produced up-front by [`validate_logging`] (mirroring the opensearch- and hive-operators) so
/// that an invalid custom log ConfigMap name or a missing Vector aggregator discovery ConfigMap
/// name fails reconciliation during validation rather than at resource-build time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedLogging {
    pub prepare_container: ValidatedContainerLogConfigChoice,
    pub trino_container: ValidatedContainerLogConfigChoice,
    pub vector_container: Option<VectorContainerLogConfig>,
    pub enable_vector_agent: bool,
}

/// Validates the logging configuration for the Trino, prepare and (optional) Vector containers.
///
/// `vector_aggregator_config_map_name` is the discovery ConfigMap name of the Vector aggregator;
/// it is required (and validated) only when the Vector agent is enabled.
fn validate_logging(
    logging: &Logging<Container>,
    vector_aggregator_config_map_name: &Option<ConfigMapName>,
) -> Result<ValidatedLogging> {
    let prepare_container =
        validate_logging_configuration_for_container(logging, &Container::Prepare)
            .context(ValidateLoggingConfigSnafu)?;
    let trino_container = validate_logging_configuration_for_container(logging, &Container::Trino)
        .context(ValidateLoggingConfigSnafu)?;

    let vector_container = if logging.enable_vector_agent {
        let vector_aggregator_config_map_name = vector_aggregator_config_map_name
            .clone()
            .context(MissingVectorAggregatorConfigMapNameSnafu)?;
        Some(VectorContainerLogConfig {
            log_config: validate_logging_configuration_for_container(logging, &Container::Vector)
                .context(ValidateLoggingConfigSnafu)?,
            vector_aggregator_config_map_name,
        })
    } else {
        None
    };

    Ok(ValidatedLogging {
        prepare_container,
        trino_container,
        vector_container,
        enable_vector_agent: logging.enable_vector_agent,
    })
}

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

    // The Vector aggregator discovery ConfigMap name (validated here so an invalid name fails
    // up-front). It is only required when the Vector agent is enabled for a role group.
    let vector_aggregator_config_map_name = trino
        .spec
        .cluster_config
        .vector_aggregator_config_map_name
        .clone();

    let mut role_configs: BTreeMap<TrinoRole, ValidatedRoleConfig> = BTreeMap::new();
    let mut role_group_configs: BTreeMap<TrinoRole, BTreeMap<RoleGroupName, TrinoRoleGroupConfig>> =
        BTreeMap::new();
    for trino_role in TrinoRole::iter() {
        let role = trino
            .role(&trino_role)
            .with_context(|_| MissingTrinoRoleSnafu {
                role: trino_role.to_string(),
            })?;

        // Extract the per-role PDB and (optional) listener class up-front, so the reconciler and
        // build steps consume the validated config instead of re-reading the raw cluster.
        role_configs.insert(
            trino_role.clone(),
            ValidatedRoleConfig {
                pdb: trino
                    .generic_role_config(&trino_role)
                    .map(|rc| rc.pod_disruption_budget.clone())
                    .unwrap_or_default(),
                listener_class: trino_role.listener_class_name(trino),
            },
        );

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
            groups.insert(
                rg_name.clone(),
                into_role_group_config(merged, &vector_aggregator_config_map_name)?,
            );
        }
        role_group_configs.insert(trino_role, groups);
    }

    let tls = &trino.spec.cluster_config.tls;
    let cluster_config = ValidatedClusterConfig {
        tls: ValidatedTls {
            server: tls.server_secret_class.as_ref().map(ToString::to_string),
            internal: tls.internal_secret_class.as_ref().map(ToString::to_string),
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
        role_configs,
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
    vector_aggregator_config_map_name: &Option<ConfigMapName>,
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

    let logging = validate_logging(&common.config.logging, vector_aggregator_config_map_name)?;

    Ok(RoleGroupConfig {
        replicas,
        config: ValidatedTrinoConfig::from_merged(common.config, logging),
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
    // The shared test clusters do not enable the Vector agent, so no aggregator ConfigMap name is
    // required here.
    into_role_group_config(merged, &None).expect("env overrides should be valid")
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
