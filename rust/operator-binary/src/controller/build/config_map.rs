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

use crate::{
    config::jvm,
    controller::{
        ValidatedCluster,
        build::properties::{
            ConfigFileName, access_control_properties, config_properties,
            exchange_manager_properties, log_properties, logging::get_vector_toml, node_properties,
            security_properties, spooling_manager_properties, to_java_properties_string,
        },
    },
    crd::{TrinoRole, v1alpha1},
};

// File name not exported from crd/mod.rs.
const JVM_CONFIG: &str = "jvm.config";

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("failed to build config.properties"))]
    BuildConfigProperties { source: config_properties::Error },

    #[snafu(display("failed to write {file} properties"))]
    WriteProperties {
        source: stackable_operator::v2::config_file_writer::PropertiesWriterError,
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

    #[snafu(display("failed to resolve the {role} role"))]
    ReadRole {
        source: crate::crd::Error,
        role: String,
    },

    #[snafu(display("failed to build jvm.config"))]
    BuildJvmConfig { source: crate::config::jvm::Error },
}

type Result<T, E = Error> = std::result::Result<T, E>;

#[allow(clippy::too_many_arguments)]
pub fn build_rolegroup_config_map(
    cluster: &ValidatedCluster,
    role: &TrinoRole,
    rolegroup_ref: &RoleGroupRef<v1alpha1::TrinoCluster>,
    cluster_info: &KubernetesClusterInfo,
    recommended_labels: &ObjectLabels<'_, v1alpha1::TrinoCluster>,
    owner_target: &v1alpha1::TrinoCluster,
) -> Result<ConfigMap> {
    let role_group_configs =
        cluster
            .role_group_configs
            .get(role)
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
    // to match the legacy precedence.
    for (file_name, props) in cluster.cluster_config.authentication.config_files(role) {
        let rendered =
            to_java_properties_string(&props).with_context(|_| WritePropertiesSnafu {
                file: file_name.clone(),
            })?;
        data.insert(file_name, rendered);
    }

    // 1. config.properties (fallible).
    let cfg = config_properties::build(cluster, role.clone(), rg, cluster_info)
        .context(BuildConfigPropertiesSnafu)?;
    data.insert(
        ConfigFileName::Config.to_string(),
        to_java_properties_string(&cfg).with_context(|_| WritePropertiesSnafu {
            file: ConfigFileName::Config.to_string(),
        })?,
    );

    // 2. node.properties.
    let node = node_properties::build(cluster, rg);
    data.insert(
        ConfigFileName::Node.to_string(),
        to_java_properties_string(&node).with_context(|_| WritePropertiesSnafu {
            file: ConfigFileName::Node.to_string(),
        })?,
    );

    // 3. log.properties (optional — empty map → omit).
    let log = log_properties::build(rg);
    if !log.is_empty() {
        data.insert(
            ConfigFileName::Log.to_string(),
            to_java_properties_string(&log).with_context(|_| WritePropertiesSnafu {
                file: ConfigFileName::Log.to_string(),
            })?,
        );
    }

    // 4. security.properties.
    let sec = security_properties::build(rg);
    data.insert(
        ConfigFileName::Security.to_string(),
        to_java_properties_string(&sec).with_context(|_| WritePropertiesSnafu {
            file: ConfigFileName::Security.to_string(),
        })?,
    );

    // 5. access-control.properties (optional).
    let ac = access_control_properties::build(cluster, rg);
    if !ac.is_empty() {
        data.insert(
            ConfigFileName::AccessControl.to_string(),
            to_java_properties_string(&ac).with_context(|_| WritePropertiesSnafu {
                file: ConfigFileName::AccessControl.to_string(),
            })?,
        );
    }

    // 6. exchange-manager.properties (optional).
    let em = exchange_manager_properties::build(cluster, rg);
    if !em.is_empty() {
        data.insert(
            ConfigFileName::ExchangeManager.to_string(),
            to_java_properties_string(&em).with_context(|_| WritePropertiesSnafu {
                file: ConfigFileName::ExchangeManager.to_string(),
            })?,
        );
    }

    // 7. spooling-manager.properties (optional).
    let sm = spooling_manager_properties::build(cluster, rg);
    if !sm.is_empty() {
        data.insert(
            ConfigFileName::SpoolingManager.to_string(),
            to_java_properties_string(&sm).with_context(|_| WritePropertiesSnafu {
                file: ConfigFileName::SpoolingManager.to_string(),
            })?,
        );
    }

    // 8. jvm.config.
    let role_obj = owner_target.role(role).with_context(|_| ReadRoleSnafu {
        role: role.to_string(),
    })?;
    let jvm_config = jvm::jvm_config(
        cluster.product_version,
        &rg.config,
        &role_obj,
        &rolegroup_ref.role_group,
    )
    .context(BuildJvmConfigSnafu)?;
    data.insert(JVM_CONFIG.to_string(), jvm_config);

    // 9. Vector sidecar toml if enabled.
    if let Some(vector_toml) = get_vector_toml(rolegroup_ref, &rg.config.logging) {
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
                .with_recommended_labels(recommended_labels)
                .context(MetadataSnafu)?
                .build(),
        )
        .data(data)
        .build()
        .with_context(|_| AssembleSnafu {
            rolegroup: rolegroup_ref.clone(),
        })
}
