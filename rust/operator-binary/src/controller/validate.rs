//! The validate step in the TrinoCluster controller
//!
//! Synchronously validates inputs that don't require a Kubernetes client. Produces
//! [`super::ValidatedCluster`], consumed by the rest of `reconcile_trino`.

use snafu::{ResultExt, Snafu};
use stackable_operator::{
    cli::OperatorEnvironmentOptions, commons::product_image_selection,
};
use strum::{EnumDiscriminants, IntoStaticStr};

use crate::{
    authentication::{self, TrinoAuthenticationConfig, TrinoAuthenticationTypes},
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

/// Validates the cluster spec and the dereferenced inputs, producing the typed
/// [`super::ValidatedCluster`].
pub fn validate(
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
    fn validate_minimal_cluster() {
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
            validate(&trino, &derefs, &operator_env).expect("validate should succeed");

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
