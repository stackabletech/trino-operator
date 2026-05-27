//! The validate step in the TrinoCluster controller
//!
//! Synchronously validates inputs that don't require a Kubernetes client. Produces
//! [`ValidatedInputs`], consumed by the rest of `reconcile_trino`.

use std::collections::HashMap;

use product_config::{ProductConfigManager, types::PropertyNameKind};
use snafu::{ResultExt, Snafu};
use stackable_operator::{
    cli::OperatorEnvironmentOptions,
    commons::product_image_selection::{self, ResolvedProductImage},
    product_config_utils::{
        ValidatedRoleConfigByPropertyKind, transform_all_roles_to_config,
        validate_all_roles_and_groups_config,
    },
};
use strum::{EnumDiscriminants, IntoStaticStr};

use crate::{
    authentication::{self, TrinoAuthenticationConfig, TrinoAuthenticationTypes},
    controller::dereference::DereferencedObjects,
    crd::{
        ACCESS_CONTROL_PROPERTIES, CONFIG_PROPERTIES, EXCHANGE_MANAGER_PROPERTIES, JVM_CONFIG,
        JVM_SECURITY_PROPERTIES, LOG_PROPERTIES, NODE_PROPERTIES, SPOOLING_MANAGER_PROPERTIES,
        TrinoRole, v1alpha1,
    },
};

#[derive(Snafu, Debug, EnumDiscriminants)]
#[strum_discriminants(derive(IntoStaticStr))]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    #[snafu(display("failed to resolve product image"))]
    ResolveProductImage {
        source: product_image_selection::Error,
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

    #[snafu(display("failed to transform configs"))]
    ProductConfigTransform {
        source: stackable_operator::product_config_utils::Error,
    },

    #[snafu(display("invalid product config"))]
    InvalidProductConfig {
        source: stackable_operator::product_config_utils::Error,
    },

    #[snafu(display("unable to parse Trino version: {product_version:?}"))]
    ParseTrinoVersion {
        source: std::num::ParseIntError,
        product_version: String,
    },

    #[snafu(display("failed to validate config fragment"))]
    InvalidConfigFragment {
        source: stackable_operator::config::fragment::ValidationError,
    },

    #[snafu(display("failed to enumerate coordinator pods"))]
    CoordinatorPods { source: crate::crd::Error },
}

type Result<T, E = Error> = std::result::Result<T, E>;

/// Synchronous inputs the rest of `reconcile_trino` needs after dereferencing.
pub struct ValidatedInputs {
    pub image: ResolvedProductImage,
    pub trino_authentication_config: TrinoAuthenticationConfig,
    pub validated_role_config: ValidatedRoleConfigByPropertyKind,
}

/// Validates the cluster spec and the dereferenced inputs.
pub fn validate(
    trino: &v1alpha1::TrinoCluster,
    dereferenced_objects: &DereferencedObjects,
    operator_environment: &OperatorEnvironmentOptions,
    product_config: &ProductConfigManager,
) -> Result<ValidatedInputs> {
    let resolved_product_image = trino
        .spec
        .image
        .resolve(
            super::CONTAINER_IMAGE_BASE_NAME,
            &operator_environment.image_repository,
            crate::built_info::PKG_VERSION,
        )
        .context(ResolveProductImageSnafu)?;

    let trino_authentication_config = TrinoAuthenticationConfig::new(
        &resolved_product_image,
        TrinoAuthenticationTypes::try_from(
            dereferenced_objects.resolved_authentication_classes.clone(),
        )
        .context(UnsupportedAuthenticationConfigSnafu)?,
    )
    .context(InvalidAuthenticationConfigSnafu)?;

    if dereferenced_objects
        .resolved_client_protocol_config
        .is_some()
        && resolved_product_image.product_version.starts_with("45")
    {
        return Err(Error::ClientSpoolingProtocolTrinoVersion {
            product_version: resolved_product_image.product_version.clone(),
        });
    }

    let validated_role_config = validated_product_config(
        trino,
        // The Trino version is a single number like 396.
        // The product config expects semver formatted version strings.
        // That is why we just add minor and patch version 0 here.
        &format!("{}.0.0", resolved_product_image.product_version),
        product_config,
    )?;

    Ok(ValidatedInputs {
        image: resolved_product_image,
        trino_authentication_config,
        validated_role_config,
    })
}

pub(super) fn validated_product_config(
    trino: &v1alpha1::TrinoCluster,
    version: &str,
    product_config: &ProductConfigManager,
) -> Result<ValidatedRoleConfigByPropertyKind> {
    let mut roles = HashMap::new();

    let config_files = vec![
        PropertyNameKind::Env,
        PropertyNameKind::File(CONFIG_PROPERTIES.to_string()),
        PropertyNameKind::File(NODE_PROPERTIES.to_string()),
        PropertyNameKind::File(JVM_CONFIG.to_string()),
        PropertyNameKind::File(LOG_PROPERTIES.to_string()),
        PropertyNameKind::File(JVM_SECURITY_PROPERTIES.to_string()),
        PropertyNameKind::File(ACCESS_CONTROL_PROPERTIES.to_string()),
        PropertyNameKind::File(SPOOLING_MANAGER_PROPERTIES.to_string()),
        PropertyNameKind::File(EXCHANGE_MANAGER_PROPERTIES.to_string()),
    ];

    let coordinator_role = TrinoRole::Coordinator;
    roles.insert(
        coordinator_role.to_string(),
        (
            config_files.clone(),
            trino
                .role(&coordinator_role)
                .with_context(|_| MissingTrinoRoleSnafu {
                    role: coordinator_role.to_string(),
                })?,
        ),
    );

    let worker_role = TrinoRole::Worker;
    roles.insert(
        worker_role.to_string(),
        (
            config_files,
            trino
                .role(&worker_role)
                .with_context(|_| MissingTrinoRoleSnafu {
                    role: worker_role.to_string(),
                })?,
        ),
    );

    let role_config =
        transform_all_roles_to_config(trino, &roles).context(ProductConfigTransformSnafu)?;

    validate_all_roles_and_groups_config(version, &role_config, product_config, false, false)
        .context(InvalidProductConfigSnafu)
}

/// New validator: produces the typed [`super::ValidatedCluster`].
///
/// Replaces the legacy product-config-driven `validate` pipeline. See Task 4 of the
/// product-config removal plan. Wired up in Task 14.
#[allow(dead_code)]
pub fn validate_v2(
    trino: &v1alpha1::TrinoCluster,
    dereferenced_objects: &super::dereference::DereferencedObjects,
    operator_environment: &OperatorEnvironmentOptions,
) -> Result<super::ValidatedCluster> {
    use std::str::FromStr;

    use stackable_operator::kube::ResourceExt as _;

    let resolved_product_image = trino
        .spec
        .image
        .resolve(
            super::CONTAINER_IMAGE_BASE_NAME,
            &operator_environment.image_repository,
            crate::built_info::PKG_VERSION,
        )
        .context(ResolveProductImageSnafu)?;

    let product_version = u16::from_str(&resolved_product_image.product_version).context(
        ParseTrinoVersionSnafu {
            product_version: resolved_product_image.product_version.clone(),
        },
    )?;

    let trino_authentication_config = TrinoAuthenticationConfig::new(
        &resolved_product_image,
        TrinoAuthenticationTypes::try_from(
            dereferenced_objects.resolved_authentication_classes.clone(),
        )
        .context(UnsupportedAuthenticationConfigSnafu)?,
    )
    .context(InvalidAuthenticationConfigSnafu)?;

    if dereferenced_objects
        .resolved_client_protocol_config
        .is_some()
        && resolved_product_image.product_version.starts_with("45")
    {
        return Err(Error::ClientSpoolingProtocolTrinoVersion {
            product_version: resolved_product_image.product_version.clone(),
        });
    }

    let mut role_group_configs: std::collections::BTreeMap<
        TrinoRole,
        std::collections::BTreeMap<super::RoleGroupName, super::TrinoRoleGroupConfig>,
    > = std::collections::BTreeMap::new();

    for trino_role in [TrinoRole::Coordinator, TrinoRole::Worker] {
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
        let mut groups = std::collections::BTreeMap::new();
        for (rg_name, rg) in &role.role_groups {
            let validated_rg = crate::framework::role_utils::with_validated_config::<
                v1alpha1::TrinoConfig,
                stackable_operator::role_utils::JavaCommonConfig,
                v1alpha1::TrinoConfigFragment,
                stackable_operator::role_utils::GenericRoleConfig,
                v1alpha1::TrinoConfigOverrides,
            >(rg, &role, &default_config)
            .context(InvalidConfigFragmentSnafu)?;
            groups.insert(rg_name.clone(), validated_rg);
        }
        role_group_configs.insert(trino_role, groups);
    }

    let coordinator_pod_refs = trino
        .coordinator_pods()
        .context(CoordinatorPodsSnafu)?
        .collect();

    Ok(super::ValidatedCluster {
        metadata: stackable_operator::k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
            name: trino.metadata.name.clone(),
            namespace: trino.metadata.namespace.clone(),
            uid: trino.metadata.uid.clone(),
            ..Default::default()
        },
        name: trino.metadata.name.clone().unwrap_or_default(),
        namespace: trino.metadata.namespace.clone().unwrap_or_default(),
        uid: trino.metadata.uid.clone().unwrap_or_default(),
        image: resolved_product_image,
        product_version,
        server_tls: trino.get_server_tls().map(String::from),
        internal_tls: trino.get_internal_tls().map(String::from),
        authentication_enabled: trino.authentication_enabled(),
        catalog_label_selector: trino.spec.cluster_config.catalog_label_selector.clone(),
        cluster_operation: trino.spec.cluster_operation.clone(),
        object_overrides: trino.spec.object_overrides.clone(),
        trino_authentication_config,
        trino_opa_config: dereferenced_objects.trino_opa_config.clone(),
        resolved_fte_config: dereferenced_objects.resolved_fte_config.clone(),
        resolved_client_protocol_config: dereferenced_objects
            .resolved_client_protocol_config
            .clone(),
        catalogs: dereferenced_objects.catalogs.clone(),
        coordinator_pod_refs,
        role_group_configs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_v2_minimal_cluster() {
        let trino_yaml = r#"
        apiVersion: trino.stackable.tech/v1alpha1
        kind: TrinoCluster
        metadata:
          name: simple-trino
          namespace: default
          uid: "42"
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
        let trino: v1alpha1::TrinoCluster =
            serde_yaml::from_str(trino_yaml).expect("invalid test input");

        let derefs = super::super::dereference::DereferencedObjects {
            resolved_authentication_classes: Vec::new(),
            catalog_definitions: Vec::new(),
            catalogs: Vec::new(),
            trino_opa_config: None,
            resolved_fte_config: None,
            resolved_client_protocol_config: None,
        };
        let operator_env = stackable_operator::cli::OperatorEnvironmentOptions {
            operator_namespace: "stackable-operators".to_string(),
            operator_service_name: "trino-operator".to_string(),
            image_repository: "oci.example.org".to_string(),
        };

        let validated =
            validate_v2(&trino, &derefs, &operator_env).expect("validate_v2 should succeed");

        assert_eq!(validated.name, "simple-trino");
        assert_eq!(validated.namespace, "default");
        assert_eq!(validated.product_version, 479);
        assert!(!validated.authentication_enabled);
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
