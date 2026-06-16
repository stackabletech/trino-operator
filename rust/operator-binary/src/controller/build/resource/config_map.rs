//! Build per-rolegroup `ConfigMap` for the Trino cluster.

use std::collections::BTreeMap;

use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::{
    builder::configmap::ConfigMapBuilder, k8s_openapi::api::core::v1::ConfigMap, kvp::Labels,
    product_logging::framework::VECTOR_CONFIG_FILE, utils::cluster_info::KubernetesClusterInfo,
    v2::config_file_writer::to_java_properties_string,
};

use crate::{
    config::jvm,
    controller::{
        ValidatedCluster,
        build::properties::{
            ConfigFileName, access_control_properties, config_properties,
            exchange_manager_properties, log_properties, node_properties, product_logging,
            security_properties, spooling_manager_properties,
        },
    },
    crd::TrinoRole,
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
        rolegroup: String,
    },

    #[snafu(display("failed to build jvm.config"))]
    BuildJvmConfig { source: crate::config::jvm::Error },
}

type Result<T, E = Error> = std::result::Result<T, E>;

pub fn build_rolegroup_config_map(
    cluster: &ValidatedCluster,
    role: &TrinoRole,
    role_group_name: &str,
    cluster_info: &KubernetesClusterInfo,
    recommended_labels: &Labels,
) -> Result<ConfigMap> {
    let role_group_configs =
        cluster
            .role_group_configs
            .get(role)
            .with_context(|| MissingRoleGroupSnafu {
                role: role.to_string(),
                role_group: role_group_name.to_owned(),
            })?;
    let rg = role_group_configs
        .get(role_group_name)
        .with_context(|| MissingRoleGroupSnafu {
            role: role.to_string(),
            role_group: role_group_name.to_owned(),
        })?;

    let config_map_name = cluster
        .resource_names(role, role_group_name)
        .role_group_config_map()
        .to_string();

    let mut data: BTreeMap<String, String> = BTreeMap::new();

    // Auth files (e.g. password-authenticator file contents) — inserted FIRST
    // to match the legacy precedence.
    for (file_name, props) in cluster.cluster_config.authentication.config_files(role) {
        let rendered =
            to_java_properties_string(props.iter()).with_context(|_| WritePropertiesSnafu {
                file: file_name.clone(),
            })?;
        data.insert(file_name, rendered);
    }

    // 1. config.properties (fallible).
    let cfg = config_properties::build(cluster, role.clone(), rg, cluster_info)
        .context(BuildConfigPropertiesSnafu)?;
    data.insert(
        ConfigFileName::Config.to_string(),
        to_java_properties_string(cfg.iter()).with_context(|_| WritePropertiesSnafu {
            file: ConfigFileName::Config.to_string(),
        })?,
    );

    // 2. node.properties.
    let node = node_properties::build(cluster, rg);
    data.insert(
        ConfigFileName::Node.to_string(),
        to_java_properties_string(node.iter()).with_context(|_| WritePropertiesSnafu {
            file: ConfigFileName::Node.to_string(),
        })?,
    );

    // 3. log.properties (optional — empty map → omit).
    let log = log_properties::build(rg);
    if !log.is_empty() {
        data.insert(
            ConfigFileName::Log.to_string(),
            to_java_properties_string(log.iter()).with_context(|_| WritePropertiesSnafu {
                file: ConfigFileName::Log.to_string(),
            })?,
        );
    }

    // 4. security.properties.
    let sec = security_properties::build(rg);
    data.insert(
        ConfigFileName::Security.to_string(),
        to_java_properties_string(sec.iter()).with_context(|_| WritePropertiesSnafu {
            file: ConfigFileName::Security.to_string(),
        })?,
    );

    // 5. access-control.properties (optional).
    let ac = access_control_properties::build(cluster, rg);
    if !ac.is_empty() {
        data.insert(
            ConfigFileName::AccessControl.to_string(),
            to_java_properties_string(ac.iter()).with_context(|_| WritePropertiesSnafu {
                file: ConfigFileName::AccessControl.to_string(),
            })?,
        );
    }

    // 6. exchange-manager.properties (optional).
    let em = exchange_manager_properties::build(cluster, rg);
    if !em.is_empty() {
        data.insert(
            ConfigFileName::ExchangeManager.to_string(),
            to_java_properties_string(em.iter()).with_context(|_| WritePropertiesSnafu {
                file: ConfigFileName::ExchangeManager.to_string(),
            })?,
        );
    }

    // 7. spooling-manager.properties (optional).
    let sm = spooling_manager_properties::build(cluster, rg);
    if !sm.is_empty() {
        data.insert(
            ConfigFileName::SpoolingManager.to_string(),
            to_java_properties_string(sm.iter()).with_context(|_| WritePropertiesSnafu {
                file: ConfigFileName::SpoolingManager.to_string(),
            })?,
        );
    }

    // 8. jvm.config. The role + role-group `jvmArgumentOverrides` were already merged in the
    // validate step and are carried by `product_specific_common_config`.
    let jvm_config = jvm::jvm_config(
        cluster.product_version,
        &rg.config,
        &rg.product_specific_common_config.jvm_argument_overrides,
    )
    .context(BuildJvmConfigSnafu)?;
    data.insert(JVM_CONFIG.to_string(), jvm_config);

    // 9. Vector agent config (`vector.yaml`) if the Vector agent is enabled. The file is templated
    // with environment variables injected by the v2 Vector container at runtime.
    if rg.config.logging.enable_vector_agent {
        data.insert(
            VECTOR_CONFIG_FILE.to_string(),
            product_logging::vector_config_file_content(),
        );
    }

    ConfigMapBuilder::new()
        .metadata(
            cluster
                .object_meta(&config_map_name, recommended_labels.clone())
                .build(),
        )
        .data(data)
        .build()
        .with_context(|_| AssembleSnafu {
            rolegroup: config_map_name.clone(),
        })
}

/// The rolegroup catalog [`ConfigMap`] configures the rolegroup catalog based on the configuration
/// given by the administrator
pub fn build_rolegroup_catalog_config_map(
    cluster: &ValidatedCluster,
    role: &TrinoRole,
    role_group_name: &str,
    recommended_labels: &Labels,
) -> Result<ConfigMap> {
    let catalog_config_map_name = format!(
        "{}-catalog",
        cluster
            .resource_names(role, role_group_name)
            .role_group_config_map()
    );
    ConfigMapBuilder::new()
        .metadata(
            cluster
                .object_meta(&catalog_config_map_name, recommended_labels.clone())
                .build(),
        )
        .data(
            cluster
                .cluster_config
                .catalogs
                .iter()
                .map(|catalog| {
                    let file = format!("{}.properties", catalog.name);
                    let rendered = to_java_properties_string(catalog.properties.iter())
                        .with_context(|_| WritePropertiesSnafu { file: file.clone() })?;
                    Ok((file, rendered))
                })
                .collect::<Result<_>>()?,
        )
        .build()
        .with_context(|_| AssembleSnafu {
            rolegroup: catalog_config_map_name.clone(),
        })
}
