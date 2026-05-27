//! Builder for `access-control.properties`.

use std::collections::BTreeMap;

use crate::controller::{TrinoRoleGroupConfig, ValidatedCluster};

/// Build the `access-control.properties` key/value pairs.
///
/// Returns an empty map when neither OPA authorization is configured nor
/// user overrides are provided — callers should omit the file from the
/// ConfigMap in that case.
// Until callers exist (wired in by build/config_map.rs in Task 12), this
// builder is transient dead code. Allow the warning to keep `cargo check` clean.
#[allow(dead_code)]
pub fn build(
    cluster: &ValidatedCluster,
    rg: &TrinoRoleGroupConfig,
) -> BTreeMap<String, String> {
    let mut props = BTreeMap::new();

    // 1. No defaults.
    // 2. Automatic — OPA config when configured.
    //    TrinoOpaConfig::as_config() returns BTreeMap<String, Option<String>>;
    //    drop the None values (matches old product-config write-time behavior).
    if let Some(opa) = &cluster.trino_opa_config {
        props.extend(
            opa.as_config()
                .into_iter()
                .filter_map(|(k, v)| v.map(|v| (k, v))),
        );
    }

    // 3. No merged_config contribution.
    // 4. User overrides (highest precedence).
    if let Some(kv) = &rg.config_overrides.access_control_properties {
        props.extend(kv.overrides.clone());
    }

    props
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::controller::build::properties::test_support::{
        MINIMAL_TRINO_YAML, validated_cluster_from_yaml,
    };
    use crate::crd::TrinoRole;

    #[test]
    fn default_renders_empty_when_no_opa() {
        let cluster = validated_cluster_from_yaml(MINIMAL_TRINO_YAML);
        let rg = cluster.role_group_configs[&TrinoRole::Coordinator]["default"].clone();
        let props = build(&cluster, &rg);
        assert!(props.is_empty());
    }
}
