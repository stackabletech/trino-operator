//! Builder for the coordinator's `event-listener.properties` (the Trino OpenLineage event listener).
//!
//! The OpenLineage event listener runs on the **coordinator only**, so this builder returns an
//! empty map for every other role and the caller omits the file from those ConfigMaps. For the
//! coordinator it emits the connection-derived settings resolved in [`crate::config::lineage`],
//! adds the cluster-facing `trino.uri`, and finally merges any user `event-listener.properties`
//! overrides (highest precedence).

use std::collections::BTreeMap;

use stackable_operator::utils::cluster_info::KubernetesClusterInfo;

use crate::{
    config::lineage::OPENLINEAGE_TRINO_URI_KEY,
    controller::{TrinoRoleGroupConfig, ValidatedCluster},
    crd::{
        TrinoRole,
        discovery::{TrinoDiscovery, TrinoDiscoveryProtocol},
    },
};

/// Build the `event-listener.properties` key/value pairs.
///
/// Returns an empty map when OpenLineage is not configured and no user overrides are provided (and
/// always for non-coordinator roles). Callers should omit the file from the ConfigMap in that case.
pub fn build(
    cluster: &ValidatedCluster,
    role: TrinoRole,
    rg: &TrinoRoleGroupConfig,
    cluster_info: &KubernetesClusterInfo,
) -> BTreeMap<String, String> {
    let mut props = BTreeMap::new();

    // Event listeners only run on the coordinator.
    if role != TrinoRole::Coordinator {
        return props;
    }

    if let Some(lineage) = &cluster.cluster_config.lineage {
        // Connection-derived settings (transport type/URL, namespace and optional api-key).
        props.extend(lineage.properties.clone());

        // The URI identifying this Trino cluster in emitted lineage. Uses the same coordinator
        // address as `discovery.uri`; the scheme follows the client-facing TLS setting.
        if let Some(coordinator_ref) = cluster.cluster_config.coordinator_pod_refs.first() {
            let protocol = if cluster.tls_enabled() {
                TrinoDiscoveryProtocol::Https
            } else {
                TrinoDiscoveryProtocol::Http
            };
            let discovery = TrinoDiscovery::new(coordinator_ref, protocol);
            props.insert(
                OPENLINEAGE_TRINO_URI_KEY.to_string(),
                discovery.discovery_uri(cluster_info),
            );
        }
    }

    // User overrides (highest precedence).
    props.extend(rg.config_overrides.event_listener_properties.clone());

    props
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use stackable_operator::utils::cluster_info::KubernetesClusterInfo;

    use super::*;
    use crate::{
        config::lineage::{
            EVENT_LISTENER_NAME_KEY, OPENLINEAGE_NAMESPACE_KEY, OPENLINEAGE_TRANSPORT_API_KEY_KEY,
            OPENLINEAGE_TRANSPORT_TYPE_KEY, OPENLINEAGE_TRANSPORT_URL_KEY, ResolvedLineageConfig,
        },
        controller::{
            ValidatedCluster,
            build::properties::test_support::{MINIMAL_TRINO_YAML, empty_derefs},
        },
        crd::TrinoRole,
    };

    fn cluster_info() -> KubernetesClusterInfo {
        KubernetesClusterInfo {
            cluster_domain: "cluster.local".parse().unwrap(),
        }
    }

    /// A resolved OpenLineage config as `config::lineage` would produce it for an inline
    /// `http://marquez:5000` connection, optionally with a bearer-token api-key reference.
    fn resolved_lineage(with_auth: bool) -> ResolvedLineageConfig {
        let mut properties = BTreeMap::from([
            (
                EVENT_LISTENER_NAME_KEY.to_string(),
                "openlineage".to_string(),
            ),
            (
                OPENLINEAGE_TRANSPORT_TYPE_KEY.to_string(),
                "HTTP".to_string(),
            ),
            (
                OPENLINEAGE_TRANSPORT_URL_KEY.to_string(),
                "http://marquez:5000".to_string(),
            ),
            (OPENLINEAGE_NAMESPACE_KEY.to_string(), "default".to_string()),
        ]);
        if with_auth {
            properties.insert(
                OPENLINEAGE_TRANSPORT_API_KEY_KEY.to_string(),
                "${file:UTF-8:/stackable/openlineage_auth/apiKey}".to_string(),
            );
        }
        ResolvedLineageConfig {
            properties,
            volumes: Vec::new(),
            volume_mounts: Vec::new(),
            init_container_extra_start_commands: Vec::new(),
        }
    }

    fn cluster_with_lineage(with_auth: bool) -> ValidatedCluster {
        let mut derefs = empty_derefs();
        derefs.resolved_lineage_config = Some(resolved_lineage(with_auth));
        crate::controller::build::properties::test_support::validated_cluster_from_yaml_with_derefs(
            MINIMAL_TRINO_YAML,
            derefs,
        )
    }

    fn coordinator_rg(cluster: &ValidatedCluster) -> TrinoRoleGroupConfig {
        cluster.role_group_configs[&TrinoRole::Coordinator]
            .values()
            .next()
            .unwrap()
            .clone()
    }

    #[test]
    fn worker_role_renders_empty() {
        let cluster = cluster_with_lineage(false);
        // Reuse the coordinator role group config; the role argument alone must gate emission.
        let rg = coordinator_rg(&cluster);
        let props = build(&cluster, TrinoRole::Worker, &rg, &cluster_info());
        assert!(
            props.is_empty(),
            "event listeners must not be configured on workers"
        );
    }

    #[test]
    fn coordinator_without_lineage_renders_empty() {
        let cluster =
            crate::controller::build::properties::test_support::validated_cluster_from_yaml(
                MINIMAL_TRINO_YAML,
            );
        let rg = coordinator_rg(&cluster);
        let props = build(&cluster, TrinoRole::Coordinator, &rg, &cluster_info());
        assert!(props.is_empty());
    }

    #[test]
    fn coordinator_emits_listener_transport_and_trino_uri() {
        let cluster = cluster_with_lineage(false);
        let rg = coordinator_rg(&cluster);
        let props = build(&cluster, TrinoRole::Coordinator, &rg, &cluster_info());

        assert_eq!(props.get(EVENT_LISTENER_NAME_KEY).unwrap(), "openlineage");
        assert_eq!(props.get(OPENLINEAGE_TRANSPORT_TYPE_KEY).unwrap(), "HTTP");
        assert_eq!(
            props.get(OPENLINEAGE_TRANSPORT_URL_KEY).unwrap(),
            "http://marquez:5000"
        );
        assert_eq!(props.get(OPENLINEAGE_NAMESPACE_KEY).unwrap(), "default");
        // The default Trino cluster enables server TLS, so the recorded Trino URI is https.
        let trino_uri = props
            .get(OPENLINEAGE_TRINO_URI_KEY)
            .expect("trino.uri is set");
        assert!(
            trino_uri.starts_with("https://") && trino_uri.contains("coordinator"),
            "trino.uri should be the coordinator address, got: {trino_uri}"
        );
        // No auth configured -> no api-key.
        assert!(!props.contains_key(OPENLINEAGE_TRANSPORT_API_KEY_KEY));
    }

    #[test]
    fn coordinator_with_auth_emits_api_key_file_reference() {
        let cluster = cluster_with_lineage(true);
        let rg = coordinator_rg(&cluster);
        let props = build(&cluster, TrinoRole::Coordinator, &rg, &cluster_info());

        let api_key = props.get(OPENLINEAGE_TRANSPORT_API_KEY_KEY).unwrap();
        assert!(
            api_key.starts_with("${file:UTF-8:"),
            "the token must be referenced from a file, never inlined: {api_key}"
        );
    }
}
