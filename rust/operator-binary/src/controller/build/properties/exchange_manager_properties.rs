//! Builder for `exchange-manager.properties`.

use std::collections::BTreeMap;

use crate::controller::{TrinoRoleGroupConfig, ValidatedCluster};

/// Build the `exchange-manager.properties` key/value pairs.
///
/// Returns an empty map when fault-tolerant execution is not configured and no
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
    // 2. Automatic — from resolved fault-tolerant-execution config.
    if let Some(fte) = &cluster.resolved_fte_config {
        props.extend(fte.exchange_manager_properties.clone());
    }

    // 3. No merged_config contribution.
    // 4. User overrides (highest precedence).
    if let Some(kv) = &rg.config_overrides.exchange_manager_properties {
        props.extend(kv.overrides.clone());
    }

    props
}

#[cfg(test)]
mod tests {
    // Tests added in Task 13 once the shared ValidatedCluster fixture exists.
}
