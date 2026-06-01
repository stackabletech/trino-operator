//! Per-file builders for Trino `.properties` files.
//!
//! Each `<file>.rs` module produces the rendered key/value pairs for one
//! Trino config file. The shared [`writer`] module serializes the map to the
//! Java-properties on-wire format.

use std::collections::BTreeMap;

use stackable_operator::v2::config_overrides::KeyValueConfigOverrides;

pub mod access_control_properties;
pub mod config_properties;
pub mod exchange_manager_properties;
pub mod log_properties;
pub mod node_properties;
pub mod security_properties;
pub mod spooling_manager_properties;
pub mod writer;

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
