//! Build per-rolegroup `ConfigMap` for the Trino cluster.

use std::collections::BTreeMap;

use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::{
    builder::{configmap::ConfigMapBuilder, meta::ObjectMetaBuilder},
    k8s_openapi::api::core::v1::ConfigMap,
    kvp::ObjectLabels,
    product_logging,
    role_utils::RoleGroupRef,
    utils::cluster_info::KubernetesClusterInfo,
};

use crate::controller::{
    ValidatedCluster,
    build::properties::{
        access_control_properties, config_properties, exchange_manager_properties, log_properties,
        node_properties, security_properties, spooling_manager_properties,
        writer::to_java_properties_string,
    },
};
use crate::crd::{
    ACCESS_CONTROL_PROPERTIES, CONFIG_PROPERTIES, EXCHANGE_MANAGER_PROPERTIES, JVM_CONFIG,
    JVM_SECURITY_PROPERTIES, LOG_PROPERTIES, NODE_PROPERTIES, SPOOLING_MANAGER_PROPERTIES,
    TrinoRole, v1alpha1,
};

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("failed to build config.properties"))]
    BuildConfigProperties { source: config_properties::Error },

    #[snafu(display("failed to write {file} properties"))]
    WriteProperties {
        source: super::properties::writer::Error,
        file: String,
    },

    #[snafu(display("missing rolegroup {role_group} under role {role}"))]
    MissingRoleGroup { role: String, role_group: String },

    #[snafu(display("failed to assemble ConfigMap for {rolegroup}"))]
    Assemble {
        source: stackable_operator::builder::configmap::Error,
        rolegroup: RoleGroupRef<v1alpha1::TrinoCluster>,
    },

    #[snafu(display("metadata build failure"))]
    Metadata {
        source: stackable_operator::builder::meta::Error,
    },
}

type Result<T, E = Error> = std::result::Result<T, E>;

// Until callers exist (wired in by reconcile in Task 14), this builder is
// transient dead code. Allow the warning to keep `cargo check` clean.
#[allow(dead_code, clippy::too_many_arguments)]
pub fn build_rolegroup_config_map(
    cluster: &ValidatedCluster,
    role: TrinoRole,
    rolegroup_ref: &RoleGroupRef<v1alpha1::TrinoCluster>,
    cluster_info: &KubernetesClusterInfo,
    recommended_labels: ObjectLabels<'_, v1alpha1::TrinoCluster>,
    jvm_config: String,
    vector_toml: Option<String>,
    owner_target: &v1alpha1::TrinoCluster,
) -> Result<ConfigMap> {
    let role_group_configs =
        cluster
            .role_group_configs
            .get(&role)
            .with_context(|| MissingRoleGroupSnafu {
                role: role.to_string(),
                role_group: rolegroup_ref.role_group.clone(),
            })?;
    let rg = role_group_configs
        .get(&rolegroup_ref.role_group)
        .with_context(|| MissingRoleGroupSnafu {
            role: role.to_string(),
            role_group: rolegroup_ref.role_group.clone(),
        })?;

    let mut data: BTreeMap<String, String> = BTreeMap::new();

    // Auth files (e.g. password-authenticator file contents) — inserted FIRST
    // to match the legacy ordering in controller.rs:621.
    data.extend(cluster.trino_authentication_config.config_files(&role));

    // 1. config.properties (fallible).
    let cfg = config_properties::build(cluster, role.clone(), rg, cluster_info)
        .context(BuildConfigPropertiesSnafu)?;
    data.insert(
        CONFIG_PROPERTIES.to_string(),
        to_java_properties_string(&cfg).with_context(|_| WritePropertiesSnafu {
            file: CONFIG_PROPERTIES.to_string(),
        })?,
    );

    // 2. node.properties.
    let node = node_properties::build(cluster, rg);
    data.insert(
        NODE_PROPERTIES.to_string(),
        to_java_properties_string(&node).with_context(|_| WritePropertiesSnafu {
            file: NODE_PROPERTIES.to_string(),
        })?,
    );

    // 3. log.properties (optional — empty map → omit).
    let log = log_properties::build(cluster, role.clone(), rg);
    if !log.is_empty() {
        data.insert(
            LOG_PROPERTIES.to_string(),
            to_java_properties_string(&log).with_context(|_| WritePropertiesSnafu {
                file: LOG_PROPERTIES.to_string(),
            })?,
        );
    }

    // 4. security.properties.
    let sec = security_properties::build(rg);
    data.insert(
        JVM_SECURITY_PROPERTIES.to_string(),
        to_java_properties_string(&sec).with_context(|_| WritePropertiesSnafu {
            file: JVM_SECURITY_PROPERTIES.to_string(),
        })?,
    );

    // 5. access-control.properties (optional).
    let ac = access_control_properties::build(cluster, rg);
    if !ac.is_empty() {
        data.insert(
            ACCESS_CONTROL_PROPERTIES.to_string(),
            to_java_properties_string(&ac).with_context(|_| WritePropertiesSnafu {
                file: ACCESS_CONTROL_PROPERTIES.to_string(),
            })?,
        );
    }

    // 6. exchange-manager.properties (optional).
    let em = exchange_manager_properties::build(cluster, rg);
    if !em.is_empty() {
        data.insert(
            EXCHANGE_MANAGER_PROPERTIES.to_string(),
            to_java_properties_string(&em).with_context(|_| WritePropertiesSnafu {
                file: EXCHANGE_MANAGER_PROPERTIES.to_string(),
            })?,
        );
    }

    // 7. spooling-manager.properties (optional).
    let sm = spooling_manager_properties::build(cluster, rg);
    if !sm.is_empty() {
        data.insert(
            SPOOLING_MANAGER_PROPERTIES.to_string(),
            to_java_properties_string(&sm).with_context(|_| WritePropertiesSnafu {
                file: SPOOLING_MANAGER_PROPERTIES.to_string(),
            })?,
        );
    }

    // 8. jvm.config — passed in (still rendered by src/config/jvm.rs).
    data.insert(JVM_CONFIG.to_string(), jvm_config);

    // 9. Vector sidecar toml if enabled.
    if let Some(vector_toml) = vector_toml {
        data.insert(
            product_logging::framework::VECTOR_CONFIG_FILE.to_string(),
            vector_toml,
        );
    }

    ConfigMapBuilder::new()
        .metadata(
            ObjectMetaBuilder::new()
                .name_and_namespace(owner_target)
                .name(rolegroup_ref.object_name())
                .ownerreference_from_resource(owner_target, None, Some(true))
                .context(MetadataSnafu)?
                .with_recommended_labels(&recommended_labels)
                .context(MetadataSnafu)?
                .build(),
        )
        .data(data)
        .build()
        .with_context(|_| AssembleSnafu {
            rolegroup: rolegroup_ref.clone(),
        })
}
