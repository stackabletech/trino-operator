//! Builder for `security.properties` (Trino's JVM security properties file).

use std::collections::BTreeMap;

use crate::controller::TrinoRoleGroupConfig;

const NETWORKADDRESS_CACHE_TTL: &str = "networkaddress.cache.ttl";
const NETWORKADDRESS_CACHE_NEGATIVE_TTL: &str = "networkaddress.cache.negative.ttl";

const DEFAULT_NETWORKADDRESS_CACHE_TTL: &str = "30";
const DEFAULT_NETWORKADDRESS_CACHE_NEGATIVE_TTL: &str = "0";

/// Build the `security.properties` key/value pairs.
///
/// Both keys apply to both `coordinator` and `worker` roles.
// Until callers exist (wired in by build/config_map.rs in Task 12), this
// builder is transient dead code. Allow the warning to keep `cargo check` clean.
#[allow(dead_code)]
pub fn build(rg: &TrinoRoleGroupConfig) -> BTreeMap<String, String> {
    let mut props = BTreeMap::new();

    // 1. Defaults — migrated from deploy/config-spec/properties.yaml.
    props.insert(
        NETWORKADDRESS_CACHE_TTL.to_string(),
        DEFAULT_NETWORKADDRESS_CACHE_TTL.to_string(),
    );
    props.insert(
        NETWORKADDRESS_CACHE_NEGATIVE_TTL.to_string(),
        DEFAULT_NETWORKADDRESS_CACHE_NEGATIVE_TTL.to_string(),
    );

    // 2. No automatic operator-injected values.
    // 3. No merged_config contribution.
    // 4. User overrides (highest precedence).
    if let Some(kv) = &rg.config_overrides.security_properties {
        props.extend(kv.overrides.clone());
    }

    props
}

#[cfg(test)]
mod tests {
    // Tests added in Task 13 once the shared ValidatedCluster fixture exists.
}
