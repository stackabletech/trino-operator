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
    // Tests added in Task 13 once the shared ValidatedCluster fixture exists.
}
