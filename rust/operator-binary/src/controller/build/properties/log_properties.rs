//! Builder for `log.properties`.

use std::collections::BTreeMap;

use crate::controller::{TrinoRoleGroupConfig, ValidatedCluster};
use crate::crd::TrinoRole;

const IO_TRINO: &str = "io.trino";
const DEFAULT_IO_TRINO: &str = "INFO";

/// Build the `log.properties` key/value pairs for `(role, rg)`.
///
/// Returns an empty map when there is nothing to write — callers
/// should omit the file from the ConfigMap if the result is empty.
pub fn build(
    cluster: &ValidatedCluster,
    role: TrinoRole,
    rg: &TrinoRoleGroupConfig,
) -> BTreeMap<String, String> {
    let mut props = BTreeMap::new();

    // 1. Defaults (lowest precedence) — migrated from deploy/config-spec/properties.yaml.
    props.insert(IO_TRINO.to_string(), DEFAULT_IO_TRINO.to_string());

    // 2. Automatic — per-container logger levels derived from rg.config.logging.
    if let Some(per_container) = crate::product_logging::get_log_property_map(&rg.config.logging) {
        props.extend(per_container);
    }

    // 3. (no merged_config contribution for log.properties beyond logging tree)
    // 4. User overrides (highest precedence).
    if let Some(kv) = &rg.config_overrides.log_properties {
        props.extend(kv.overrides.clone());
    }

    let _ = (cluster, role); // suppress unused for now; may use later for role-aware logging
    props
}

#[cfg(test)]
mod tests {
    // Tests added in Task 13 once the shared ValidatedCluster fixture exists.
}
