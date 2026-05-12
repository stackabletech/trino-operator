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
    #[snafu(display("trino cluster {name:?} has no namespace"))]
    MissingTrinoNamespace {
        source: crate::crd::Error,
        name: String,
    },

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
}

type Result<T, E = Error> = std::result::Result<T, E>;

/// Synchronous inputs the rest of `reconcile_trino` needs after dereferencing.
pub struct ValidatedInputs {
    pub namespace: String,
    pub resolved_product_image: ResolvedProductImage,
    pub trino_authentication_config: TrinoAuthenticationConfig,
    pub validated_role_config: ValidatedRoleConfigByPropertyKind,
}

/// Validates the cluster spec and the dereferenced inputs.
pub fn validate(
    trino: &v1alpha1::TrinoCluster,
    product_config: &ProductConfigManager,
    operator_environment: &OperatorEnvironmentOptions,
    dereferenced: &DereferencedObjects,
) -> Result<ValidatedInputs> {
    let namespace = trino.namespace_r().context(MissingTrinoNamespaceSnafu {
        name: stackable_operator::kube::ResourceExt::name_any(trino),
    })?;

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
            dereferenced.resolved_authentication_classes.clone(),
        )
        .context(UnsupportedAuthenticationConfigSnafu)?,
    )
    .context(InvalidAuthenticationConfigSnafu)?;

    if dereferenced.resolved_client_protocol_config.is_some()
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
        namespace,
        resolved_product_image,
        trino_authentication_config,
        validated_role_config,
    })
}

fn validated_product_config(
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
