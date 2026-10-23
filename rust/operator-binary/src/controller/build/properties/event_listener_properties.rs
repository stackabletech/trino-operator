//! Builder for the coordinator's `event-listener.properties` (the Trino OpenLineage event listener).
//!
//! The OpenLineage event listener runs on the **coordinator only**, so this builder returns an
//! empty map for every other role and the caller omits the file from those ConfigMaps. For the
//! coordinator it emits the settings resolved in [`crate::config::lineage`] and merges any user
//! `event-listener.properties` overrides (highest precedence).

use std::collections::BTreeMap;

use crate::{
    config::lineage::OPENLINEAGE_TRINO_URI_KEY,
    controller::{TrinoRoleGroupConfig, ValidatedCluster, build::ports},
    crd::TrinoRole,
};

/// Build the `event-listener.properties` key/value pairs.
///
/// Returns an empty map when OpenLineage is not configured and no user overrides are provided (and
/// always for non-coordinator roles). Callers should omit the file from the ConfigMap in that case.
pub fn build(
    cluster: &ValidatedCluster,
    role: TrinoRole,
    rg: &TrinoRoleGroupConfig,
) -> BTreeMap<String, String> {
    let mut props = BTreeMap::new();

    // Event listeners only run on the coordinator.
    if role != TrinoRole::Coordinator {
        return props;
    }

    if let Some(lineage) = &cluster.cluster_config.lineage {
        props.extend(lineage.properties.clone());
        props.insert(
            OPENLINEAGE_TRINO_URI_KEY.to_string(),
            dataset_namespace_uri(cluster, lineage.dataset_namespace_uri.as_deref()),
        );
    }

    // User overrides (highest precedence).
    props.extend(rg.config_overrides.event_listener_properties.clone());

    props
}

/// The `trino.uri` Trino derives the dataset namespace from: the user-provided
/// `datasetNamespaceUri`, or the address of the coordinator Service
/// (`<scheme>://<coordinator service name>:<port>`) when there is none (the CRD default).
///
/// Trino turns the URI into the dataset namespace `trino://<host>:<port>`. Other OpenLineage
/// producers that read from this Trino (e.g. Airflow's Trino connection) name the same datasets
/// after the host and port they connect to, so defaulting to the coordinator Service address makes
/// both sides report identical dataset identities.
///
/// This function intentionally returns a `String` rather than an `Url` object.
/// Behaviour change: Url normalises its input, so the rendered result differs from before:
/// - The URI gets a trailing slash, for example https://simple-trino-coordinator:8443/.
/// - A default port is dropped, so a user-provided https://trino-prod:443 becomes https://trino-prod/.
///
fn dataset_namespace_uri(cluster: &ValidatedCluster, user_provided: Option<&str>) -> String {
    match user_provided {
        Some(uri) => uri.to_string(),
        None => format!(
            "{scheme}://{cluster_name}-coordinator:{port}",
            scheme = ports::exposed_protocol(cluster),
            cluster_name = cluster.name,
            port = ports::exposed_port(cluster),
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

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
            dataset_namespace_uri: None,
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
        cluster
            .role_group_configs(&TrinoRole::Coordinator)
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
        let props = build(&cluster, TrinoRole::Worker, &rg);
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
        let props = build(&cluster, TrinoRole::Coordinator, &rg);
        assert!(props.is_empty());
    }

    #[test]
    fn coordinator_emits_listener_transport_and_trino_uri() {
        let cluster = cluster_with_lineage(false);
        let rg = coordinator_rg(&cluster);
        let props = build(&cluster, TrinoRole::Coordinator, &rg);

        assert_eq!(props.get(EVENT_LISTENER_NAME_KEY).unwrap(), "openlineage");
        assert_eq!(props.get(OPENLINEAGE_TRANSPORT_TYPE_KEY).unwrap(), "HTTP");
        assert_eq!(
            props.get(OPENLINEAGE_TRANSPORT_URL_KEY).unwrap(),
            "http://marquez:5000"
        );
        assert_eq!(props.get(OPENLINEAGE_NAMESPACE_KEY).unwrap(), "default");
        assert_eq!(
            props.get(OPENLINEAGE_TRINO_URI_KEY).unwrap(),
            "https://simple-trino-coordinator:8443"
        );
        // No auth configured -> no api-key.
        assert!(!props.contains_key(OPENLINEAGE_TRANSPORT_API_KEY_KEY));
    }

    #[test]
    fn trino_uri_defaults_to_http_coordinator_service_without_server_tls() {
        let yaml = MINIMAL_TRINO_YAML.replace(
            "catalogLabelSelector: {}",
            "catalogLabelSelector: {}\n            tls:\n              serverSecretClass: null\n              internalSecretClass: null",
        );
        let mut derefs = empty_derefs();
        derefs.resolved_lineage_config = Some(resolved_lineage(false));
        let cluster =
            crate::controller::build::properties::test_support::validated_cluster_from_yaml_with_derefs(
                &yaml,
                derefs,
            );
        let rg = coordinator_rg(&cluster);
        let props = build(&cluster, TrinoRole::Coordinator, &rg);

        assert_eq!(
            props.get(OPENLINEAGE_TRINO_URI_KEY).unwrap(),
            "http://simple-trino-coordinator:8080"
        );
    }

    #[test]
    fn trino_uri_uses_user_provided_dataset_namespace_uri() {
        let mut derefs = empty_derefs();
        let mut lineage = resolved_lineage(false);
        lineage.dataset_namespace_uri = Some("https://trino-prod:443".to_string());
        derefs.resolved_lineage_config = Some(lineage);
        let cluster =
            crate::controller::build::properties::test_support::validated_cluster_from_yaml_with_derefs(
                MINIMAL_TRINO_YAML,
                derefs,
            );
        let rg = coordinator_rg(&cluster);
        let props = build(&cluster, TrinoRole::Coordinator, &rg);

        assert_eq!(
            props.get(OPENLINEAGE_TRINO_URI_KEY).unwrap(),
            "https://trino-prod:443"
        );
    }

    #[test]
    fn coordinator_with_auth_emits_api_key_file_reference() {
        let cluster = cluster_with_lineage(true);
        let rg = coordinator_rg(&cluster);
        let props = build(&cluster, TrinoRole::Coordinator, &rg);

        let api_key = props.get(OPENLINEAGE_TRANSPORT_API_KEY_KEY).unwrap();
        assert!(
            api_key.starts_with("${file:UTF-8:"),
            "the token must be referenced from a file, never inlined: {api_key}"
        );
    }
}
