//! Builder for `node.properties`.

use std::collections::BTreeMap;

use crate::controller::{TrinoRoleGroupConfig, ValidatedCluster};

const NODE_ENVIRONMENT: &str = "node.environment";

/// Build the `node.properties` key/value pairs.
///
/// `node.environment` is derived from the cluster name: lowercased, with `-`
/// replaced by `_`. Trino requires `^[a-z][a-z0-9_]*[a-z0-9]$`; cluster names
/// constrained by Kubernetes naming already satisfy this after the transform.
// Until callers exist (wired in by build/config_map.rs in Task 12), this
// builder is transient dead code. Allow the warning to keep `cargo check` clean.
#[allow(dead_code)]
pub fn build(
    cluster: &ValidatedCluster,
    rg: &TrinoRoleGroupConfig,
) -> BTreeMap<String, String> {
    let mut props = BTreeMap::new();

    // 1. No defaults.
    // 2. Automatic — derived from cluster name.
    let node_env = cluster.name.to_ascii_lowercase().replace('-', "_");
    props.insert(NODE_ENVIRONMENT.to_string(), node_env);

    // 3. No merged_config contribution for node.properties.
    // 4. User overrides (highest precedence).
    if let Some(kv) = &rg.config_overrides.node_properties {
        props.extend(kv.overrides.clone());
    }

    props
}

#[cfg(test)]
mod tests {
    // Tests added in Task 13 once the shared ValidatedCluster fixture exists.
}
