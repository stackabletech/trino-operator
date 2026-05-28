//! Builder for `config.properties` — the main Trino server config.

use std::{collections::BTreeMap, ops::Div};

use snafu::Snafu;
use stackable_operator::{memory::BinaryMultiple, utils::cluster_info::KubernetesClusterInfo};

use crate::{
    controller::{TrinoRoleGroupConfig, ValidatedCluster},
    crd::{
        COORDINATOR, Container, DISCOVERY_URI, ENV_INTERNAL_SECRET, HTTP_PORT,
        HTTP_SERVER_AUTHENTICATION_ALLOW_INSECURE_OVER_HTTP, HTTP_SERVER_HTTP_PORT,
        HTTP_SERVER_HTTPS_ENABLED, HTTP_SERVER_HTTPS_KEYSTORE_KEY, HTTP_SERVER_HTTPS_PORT,
        HTTP_SERVER_HTTPS_TRUSTSTORE_KEY, HTTP_SERVER_KEYSTORE_PATH, HTTP_SERVER_TRUSTSTORE_PATH,
        HTTPS_PORT, INTERNAL_COMMUNICATION_HTTPS_KEYSTORE_KEY,
        INTERNAL_COMMUNICATION_HTTPS_KEYSTORE_PATH, INTERNAL_COMMUNICATION_HTTPS_TRUSTSTORE_KEY,
        INTERNAL_COMMUNICATION_HTTPS_TRUSTSTORE_PATH, INTERNAL_COMMUNICATION_SHARED_SECRET,
        LOG_COMPRESSION, LOG_FORMAT, LOG_MAX_SIZE, LOG_MAX_TOTAL_SIZE, LOG_PATH,
        MAX_TRINO_LOG_FILES_SIZE, NODE_INTERNAL_ADDRESS_SOURCE, NODE_INTERNAL_ADDRESS_SOURCE_FQDN,
        QUERY_MAX_MEMORY, QUERY_MAX_MEMORY_PER_NODE, STACKABLE_INTERNAL_TLS_DIR, STACKABLE_LOG_DIR,
        STACKABLE_SERVER_TLS_DIR, STACKABLE_TLS_STORE_PASSWORD, TrinoRole,
        discovery::{TrinoDiscovery, TrinoDiscoveryProtocol},
    },
};

// Property names not exported from crd/mod.rs.
const NODE_SCHEDULER_INCLUDE_COORDINATOR: &str = "node-scheduler.include-coordinator";
const HTTP_SERVER_LOG_ENABLED: &str = "http-server.log.enabled";

// Defaults migrated from deploy/config-spec/properties.yaml.
const DEFAULT_QUERY_MAX_MEMORY: &str = "50GB";
const DEFAULT_NODE_SCHEDULER_INCLUDE_COORDINATOR: &str = "false";

// Mirrors the private constant of the same name in `crd/mod.rs`.
const LOG_FILE_COUNT: u32 = 2;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display(
        "Trino requires client TLS to be enabled if any authentication method is enabled"
    ))]
    AuthenticationRequiresTls,
}

/// Build the `config.properties` key/value pairs.
pub fn build(
    cluster: &ValidatedCluster,
    role: TrinoRole,
    rg: &TrinoRoleGroupConfig,
    cluster_info: &KubernetesClusterInfo,
) -> Result<BTreeMap<String, String>, Error> {
    let mut props = BTreeMap::new();

    // ---- 1. Hardcoded defaults (lowest precedence) ----
    // Migrated from deploy/config-spec/properties.yaml.
    props.insert(
        QUERY_MAX_MEMORY.to_string(),
        DEFAULT_QUERY_MAX_MEMORY.to_string(),
    );
    if role == TrinoRole::Coordinator {
        props.insert(
            NODE_SCHEDULER_INCLUDE_COORDINATOR.to_string(),
            DEFAULT_NODE_SCHEDULER_INCLUDE_COORDINATOR.to_string(),
        );
    }

    // ---- 2. Operator-injected automatic values ----
    props.insert(
        COORDINATOR.to_string(),
        (role == TrinoRole::Coordinator).to_string(),
    );

    // Trino's own JSON logging output.
    props.insert(LOG_FORMAT.to_string(), "json".to_string());
    props.insert(
        LOG_PATH.to_string(),
        format!(
            "{STACKABLE_LOG_DIR}/{container}/server.airlift.json",
            container = Container::Trino
        ),
    );
    props.insert(LOG_COMPRESSION.to_string(), "none".to_string());
    props.insert(
        LOG_MAX_SIZE.to_string(),
        format!(
            // Trino uses the unit "MB" for MiB.
            "{}MB",
            MAX_TRINO_LOG_FILES_SIZE
                .scale_to(BinaryMultiple::Mebi)
                .div(LOG_FILE_COUNT as f32)
                .ceil()
                .value,
        ),
    );
    props.insert(
        LOG_MAX_TOTAL_SIZE.to_string(),
        format!(
            "{}MB",
            MAX_TRINO_LOG_FILES_SIZE
                .scale_to(BinaryMultiple::Mebi)
                .ceil()
                .value,
        ),
    );
    props.insert(HTTP_SERVER_LOG_ENABLED.to_string(), "false".to_string());
    props.insert(
        INTERNAL_COMMUNICATION_SHARED_SECRET.to_string(),
        format!("${{ENV:{ENV_INTERNAL_SECRET}}}"),
    );

    // TLS gating — mirrors the existing compute_files logic, including the
    // authentication-requires-TLS check.
    let server_tls_enabled = cluster.server_tls.is_some();
    let internal_tls_enabled = cluster.internal_tls.is_some();
    if cluster.authentication_enabled && !server_tls_enabled {
        return Err(Error::AuthenticationRequiresTls);
    }
    if server_tls_enabled || internal_tls_enabled {
        props.insert(HTTP_SERVER_HTTPS_ENABLED.to_string(), "true".to_string());
        props.insert(HTTP_SERVER_HTTPS_PORT.to_string(), HTTPS_PORT.to_string());
        let tls_store_dir = if server_tls_enabled {
            STACKABLE_SERVER_TLS_DIR
        } else {
            // allow insecure communication via the http port
            props.insert(
                HTTP_SERVER_AUTHENTICATION_ALLOW_INSECURE_OVER_HTTP.to_string(),
                "true".to_string(),
            );
            props.insert(HTTP_SERVER_HTTP_PORT.to_string(), HTTP_PORT.to_string());
            STACKABLE_INTERNAL_TLS_DIR
        };
        props.insert(
            HTTP_SERVER_KEYSTORE_PATH.to_string(),
            format!("{tls_store_dir}/keystore.p12"),
        );
        props.insert(
            HTTP_SERVER_HTTPS_KEYSTORE_KEY.to_string(),
            STACKABLE_TLS_STORE_PASSWORD.to_string(),
        );
        props.insert(
            HTTP_SERVER_TRUSTSTORE_PATH.to_string(),
            format!("{tls_store_dir}/truststore.p12"),
        );
        props.insert(
            HTTP_SERVER_HTTPS_TRUSTSTORE_KEY.to_string(),
            STACKABLE_TLS_STORE_PASSWORD.to_string(),
        );
    }
    if internal_tls_enabled {
        props.insert(
            INTERNAL_COMMUNICATION_HTTPS_KEYSTORE_PATH.to_string(),
            format!("{STACKABLE_INTERNAL_TLS_DIR}/keystore.p12"),
        );
        props.insert(
            INTERNAL_COMMUNICATION_HTTPS_KEYSTORE_KEY.to_string(),
            STACKABLE_TLS_STORE_PASSWORD.to_string(),
        );
        props.insert(
            INTERNAL_COMMUNICATION_HTTPS_TRUSTSTORE_PATH.to_string(),
            format!("{STACKABLE_INTERNAL_TLS_DIR}/truststore.p12"),
        );
        props.insert(
            INTERNAL_COMMUNICATION_HTTPS_TRUSTSTORE_KEY.to_string(),
            STACKABLE_TLS_STORE_PASSWORD.to_string(),
        );
        props.insert(
            NODE_INTERNAL_ADDRESS_SOURCE.to_string(),
            NODE_INTERNAL_ADDRESS_SOURCE_FQDN.to_string(),
        );
    }

    // Authentication properties (only contributes when authentication is enabled).
    for (k, v) in cluster.trino_authentication_config.config_properties(&role) {
        props.insert(k, v);
    }

    // Discovery URI.
    if let Some(coordinator_ref) = cluster.coordinator_pod_refs.first() {
        let protocol = if internal_tls_enabled {
            TrinoDiscoveryProtocol::Https
        } else {
            TrinoDiscoveryProtocol::Http
        };
        let discovery = TrinoDiscovery::new(coordinator_ref, protocol);
        props.insert(
            DISCOVERY_URI.to_string(),
            discovery.discovery_uri(cluster_info),
        );
    }
    // If there are no coordinator pods we silently skip — the old pipeline
    // would have errored earlier (MissingCoordinatorPods).

    // Graceful shutdown.
    for (k, v) in crate::operations::graceful_shutdown_config_properties(cluster, role) {
        props.insert(k, v);
    }

    // Fault-tolerant execution.
    if let Some(fte) = &cluster.resolved_fte_config {
        props.extend(fte.config_properties.clone());
    }
    // Client spooling protocol.
    if let Some(spooling) = &cluster.resolved_client_protocol_config {
        props.extend(spooling.config_properties.clone());
    }

    // ---- 3. merged_config CRD-spec values ----
    if let Some(qmm) = &rg.config.query_max_memory {
        props.insert(QUERY_MAX_MEMORY.to_string(), qmm.clone());
    }
    if let Some(qmmpn) = &rg.config.query_max_memory_per_node {
        props.insert(QUERY_MAX_MEMORY_PER_NODE.to_string(), qmmpn.clone());
    }

    // ---- 4. User overrides (highest precedence) ----
    if let Some(kv) = &rg.config_overrides.config_properties {
        props.extend(kv.overrides.clone());
    }

    Ok(props)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::controller::build::properties::test_support::{
        MINIMAL_TRINO_YAML, validated_cluster_from_yaml,
    };

    #[test]
    fn default_renders_includes_coordinator_default_and_query_max_memory_default() {
        let cluster = validated_cluster_from_yaml(MINIMAL_TRINO_YAML);
        let rg = cluster.role_group_configs[&TrinoRole::Coordinator]["default"].clone();
        let cluster_info = stackable_operator::utils::cluster_info::KubernetesClusterInfo {
            cluster_domain: stackable_operator::commons::networking::DomainName::try_from(
                "cluster.local",
            )
            .unwrap(),
        };
        let props = build(&cluster, TrinoRole::Coordinator, &rg, &cluster_info).unwrap();
        assert_eq!(props.get("coordinator").map(String::as_str), Some("true"));
        assert_eq!(
            props
                .get("node-scheduler.include-coordinator")
                .map(String::as_str),
            Some("false"),
        );
        assert_eq!(
            props.get("query.max-memory").map(String::as_str),
            Some("50GB")
        );
    }
}
