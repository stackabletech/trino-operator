//! Builder for `access-control.properties`.

use std::collections::BTreeMap;

use crate::controller::{TrinoRoleGroupConfig, ValidatedCluster};

/// Build the `access-control.properties` key/value pairs.
///
/// Returns an empty map when neither OPA authorization is configured nor user overrides are provided.
/// Callers should omit the file from the ConfigMap in that case.
pub fn build(cluster: &ValidatedCluster, rg: &TrinoRoleGroupConfig) -> BTreeMap<String, String> {
    let mut props = BTreeMap::new();

    // 1. No defaults.
    // 2. Automatic OPA config when configured.
    if let Some(opa) = &cluster.cluster_config.authorization {
        props.extend(opa.as_config());
    }

    // 3. No merged_config contribution.
    // 4. User overrides (highest precedence).
    props.extend(super::resolved_overrides(
        rg.config_overrides.access_control_properties.clone(),
    ));

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
    fn default_renders_empty_when_no_opa() {
        let cluster = validated_cluster_from_yaml(MINIMAL_TRINO_YAML);
        let rg = cluster.role_group_configs[&TrinoRole::Coordinator]["default"].clone();
        let props = build(&cluster, &rg);
        assert!(props.is_empty());
    }
}
