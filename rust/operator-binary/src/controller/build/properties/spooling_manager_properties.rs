//! Builder for `spooling-manager.properties`.

use std::collections::BTreeMap;

use crate::controller::{TrinoRoleGroupConfig, ValidatedCluster};

/// Build the `spooling-manager.properties` key/value pairs.
///
/// Returns an empty map when client spooling is not configured and no user
/// overrides are provided — callers should omit the file from the ConfigMap
/// in that case.
pub fn build(cluster: &ValidatedCluster, rg: &TrinoRoleGroupConfig) -> BTreeMap<String, String> {
    let mut props = BTreeMap::new();

    // 1. No defaults.
    // 2. Automatic — from resolved client-spooling protocol config.
    if let Some(spooling) = &cluster.resolved_client_protocol_config {
        props.extend(spooling.spooling_manager_properties.clone());
    }

    // 3. No merged_config contribution.
    // 4. User overrides (highest precedence).
    if let Some(kv) = &rg.config_overrides.spooling_manager_properties {
        props.extend(kv.overrides.clone());
    }

    props
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        controller::build::properties::test_support::{
            MINIMAL_TRINO_YAML, validated_cluster_from_yaml,
        },
        crd::TrinoRole,
    };

    #[test]
    fn default_renders_empty_when_no_spooling() {
        let cluster = validated_cluster_from_yaml(MINIMAL_TRINO_YAML);
        let rg = cluster.role_group_configs[&TrinoRole::Coordinator]["default"].clone();
        let props = build(&cluster, &rg);
        assert!(props.is_empty());
    }
}
