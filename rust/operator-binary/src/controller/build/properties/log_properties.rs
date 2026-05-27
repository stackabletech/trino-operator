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
// Until callers exist (wired in by build/config_map.rs in Task 12), this
// builder is transient dead code. Allow the warning to keep `cargo check` clean.
#[allow(dead_code)]
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
    use super::*;
    use crate::controller::build::properties::test_support::{
        MINIMAL_TRINO_YAML, validated_cluster_from_yaml,
    };

    #[test]
    fn default_renders_io_trino_info() {
        let cluster = validated_cluster_from_yaml(MINIMAL_TRINO_YAML);
        let rg = cluster.role_group_configs[&TrinoRole::Coordinator]["default"].clone();
        let props = build(&cluster, TrinoRole::Coordinator, &rg);
        assert_eq!(props.get("io.trino").map(String::as_str), Some("INFO"));
    }
}
