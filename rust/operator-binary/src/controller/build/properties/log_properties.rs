//! Builder for `log.properties`.

use std::collections::BTreeMap;

use crate::{
    controller::{TrinoRoleGroupConfig, ValidatedCluster},
    crd::TrinoRole,
};

/// Build the `log.properties` key/value pairs for `(role, rg)`.
///
/// Returns `None`-equivalent (empty map) when there is nothing to write —
/// callers should omit the file from the ConfigMap if the result is empty.
pub fn build(
    cluster: &ValidatedCluster,
    role: TrinoRole,
    rg: &TrinoRoleGroupConfig,
) -> BTreeMap<String, String> {
    let mut props = BTreeMap::new();

    // 1. No defaults — the legacy code path ignored the product-config default
    //    `io.trino=INFO`; only per-container logger config and user overrides
    //    reach the wire.
    // 2. Automatic — per-container logger levels derived from rg.config.logging.
    if let Some(per_container) = crate::product_logging::get_log_property_map(&rg.config.logging) {
        props.extend(per_container);
    }

    // 3. No merged_config contribution.
    // 4. User overrides (highest precedence).
    if let Some(kv) = &rg.config_overrides.log_properties {
        props.extend(kv.overrides.clone());
    }

    let _ = (cluster, role); // currently unused; preserved for symmetry with siblings
    props
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::controller::build::properties::test_support::{
        MINIMAL_TRINO_YAML, validated_cluster_from_yaml,
    };

    #[test]
    fn default_renders_root_logger_only() {
        let cluster = validated_cluster_from_yaml(MINIMAL_TRINO_YAML);
        let rg = cluster.role_group_configs[&TrinoRole::Coordinator]["default"].clone();
        let props = build(&cluster, TrinoRole::Coordinator, &rg);
        // Legacy behavior: only the per-container logging tree reaches the wire.
        // The ROOT logger maps to the empty-string key.
        assert_eq!(props.get("").map(String::as_str), Some("info"));
        assert!(!props.contains_key("io.trino"));
    }
}
