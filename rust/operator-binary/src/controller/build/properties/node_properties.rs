//! Builder for `node.properties`.

use std::collections::BTreeMap;

use crate::controller::{TrinoRoleGroupConfig, ValidatedCluster};

const NODE_ENVIRONMENT: &str = "node.environment";

/// Build the `node.properties` key/value pairs.
///
/// `node.environment` is derived from the cluster name: lowercased, with `-`
/// replaced by `_`. Trino requires `^[a-z][a-z0-9_]*[a-z0-9]$`; cluster names
/// constrained by Kubernetes naming already satisfy this after the transform.
pub fn build(cluster: &ValidatedCluster, rg: &TrinoRoleGroupConfig) -> BTreeMap<String, String> {
    let mut props = BTreeMap::new();

    // 1. No defaults.
    // 2. Automatic — derived from cluster name.
    let node_env = cluster.name.to_ascii_lowercase().replace('-', "_");
    props.insert(NODE_ENVIRONMENT.to_string(), node_env);

    // 3. No merged_config contribution for node.properties.
    // 4. User overrides (highest precedence).
    props.extend(
        rg.config_overrides
            .node_properties
            .overrides
            .iter()
            .filter_map(|(k, v)| v.as_ref().map(|v| (k.clone(), v.clone()))),
    );

    props
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::controller::build::properties::test_support::{
        MINIMAL_TRINO_YAML, validated_cluster_from_yaml,
    };

    #[test]
    fn default_renders_node_environment_from_cluster_name() {
        let cluster = validated_cluster_from_yaml(MINIMAL_TRINO_YAML);
        let rg = cluster.role_group_configs[&crate::crd::TrinoRole::Coordinator]["default"].clone();
        let props = build(&cluster, &rg);
        assert_eq!(
            props.get("node.environment").map(String::as_str),
            Some("simple_trino"),
        );
    }
}
