//! Per-file builders for Trino `.properties` files.
//!
//! Each `<file>.rs` module produces the rendered key/value pairs for one
//! Trino config file. The shared
//! [`stackable_operator::v2::config_file_writer`] serializes the map to the
//! Java-properties on-wire format (see [`to_java_properties_string`]).

use std::collections::BTreeMap;

use stackable_operator::v2::{
    config_file_writer::{PropertiesWriterError, to_java_properties_string},
    config_overrides::KeyValueConfigOverrides,
};

pub mod access_control_properties;
pub mod config_properties;
pub mod exchange_manager_properties;
pub mod log_properties;
pub mod logging;
pub mod node_properties;
pub mod security_properties;
pub mod spooling_manager_properties;

/// The names of the Trino `.properties` files assembled into the rolegroup ConfigMap.
#[derive(Clone, Copy, Debug, strum::Display)]
pub enum ConfigFileName {
    #[strum(serialize = "config.properties")]
    Config,
    #[strum(serialize = "node.properties")]
    Node,
    #[strum(serialize = "log.properties")]
    Log,
    #[strum(serialize = "security.properties")]
    Security,
    #[strum(serialize = "access-control.properties")]
    AccessControl,
    #[strum(serialize = "exchange-manager.properties")]
    ExchangeManager,
    #[strum(serialize = "spooling-manager.properties")]
    SpoolingManager,
}

/// Render a `key -> value` properties map to the Java `.properties` on-wire format.
///
/// The upstream [`to_java_properties_string`] consumes an iterator of
/// `(&String, &Option<String>)`, so we lift the plain `String` values into
/// `Some(..)` first.
pub(crate) fn render_java_properties(
    props: BTreeMap<String, String>,
) -> Result<String, PropertiesWriterError> {
    let props: BTreeMap<String, Option<String>> =
        props.into_iter().map(|(k, v)| (k, Some(v))).collect();
    to_java_properties_string(props.iter())
}

/// Keep only the set (`Some`) entries of a `key -> optional value` map, as `(key, value)` pairs.
fn defined_entries(
    entries: BTreeMap<String, Option<String>>,
) -> impl Iterator<Item = (String, String)> {
    entries
        .into_iter()
        .filter_map(|(key, value)| value.map(|value| (key, value)))
}

/// Resolve user-provided [`KeyValueConfigOverrides`] into the key/value pairs to merge
/// into a `.properties` file, dropping entries whose value is unset (`None`).
fn resolved_overrides(
    overrides: KeyValueConfigOverrides,
) -> impl Iterator<Item = (String, String)> {
    defined_entries(overrides.overrides)
}

#[cfg(test)]
pub(crate) mod test_support {
    use stackable_operator::cli::OperatorEnvironmentOptions;

    use crate::{
        controller::{ValidatedCluster, dereference::DereferencedObjects},
        crd::v1alpha1,
    };

    pub fn validated_cluster_from_yaml(yaml: &str) -> ValidatedCluster {
        let trino: v1alpha1::TrinoCluster = serde_yaml::from_str(yaml).expect("invalid test YAML");
        let derefs = DereferencedObjects {
            resolved_authentication_classes: Vec::new(),
            catalog_definitions: Vec::new(),
            catalogs: Vec::new(),
            trino_opa_config: None,
            resolved_fte_config: None,
            resolved_client_protocol_config: None,
        };
        let operator_env = OperatorEnvironmentOptions {
            operator_namespace: "stackable-operators".to_string(),
            operator_service_name: "trino-operator".to_string(),
            image_repository: "oci.example.org".to_string(),
        };
        crate::controller::validate::validate(&trino, &derefs, &operator_env)
            .expect("validate should succeed for the minimal fixture")
    }

    pub const MINIMAL_TRINO_YAML: &str = r#"
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
}

#[cfg(test)]
mod tests {
    use super::*;

    fn render(pairs: &[(&str, &str)]) -> String {
        let props: BTreeMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        render_java_properties(props).expect("rendering the test properties should succeed")
    }

    /// The escape behaviours pinned by the kuttl smoke snapshot
    /// (`tests/templates/kuttl/smoke/14-assert.yaml.j2`); previously asserted
    /// against the hand-rolled writer, now against the shared one.
    #[test]
    fn kuttl_pinned_escapes_are_stable() {
        assert_eq!(
            render(&[(
                "internal-communication.shared-secret",
                "${ENV:INTERNAL_SECRET}"
            )]),
            "internal-communication.shared-secret=${ENV\\:INTERNAL_SECRET}\n"
        );
        assert_eq!(
            render(&[("discovery.uri", "https://trino-coordinator.svc:8443")]),
            "discovery.uri=https\\://trino-coordinator.svc\\:8443\n"
        );
    }

    #[test]
    fn keys_are_sorted_alphabetically() {
        assert_eq!(render(&[("b", "2"), ("a", "1")]), "a=1\nb=2\n");
    }

    #[test]
    fn empty_map_renders_empty_string() {
        assert_eq!(render(&[]), "");
    }
}
