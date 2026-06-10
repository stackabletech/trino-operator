//! Builder for `log.properties`.

use std::collections::BTreeMap;

use crate::controller::TrinoRoleGroupConfig;

/// Build the `log.properties` key/value pairs for `(role, rg)`.
///
/// Returns `None`-equivalent (empty map) when there is nothing to write —
/// callers should omit the file from the ConfigMap if the result is empty.
pub fn build(rg: &TrinoRoleGroupConfig) -> BTreeMap<String, String> {
    let mut props = BTreeMap::new();

    // 1. No defaults
    // 2. Automatic per-container logger levels
    if let Some(per_container) = super::logging::get_log_property_map(&rg.config.logging) {
        props.extend(per_container);
    }

    // 3. No merged_config contribution.
    // 4. User overrides (highest precedence).
    props.extend(rg.config_overrides.log_properties.clone());

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
    fn default_renders_root_logger_only() {
        let cluster = validated_cluster_from_yaml(MINIMAL_TRINO_YAML);
        let rg = cluster.role_group_configs[&TrinoRole::Coordinator]["default"].clone();
        let props = build(&rg);
        assert_eq!(props.get("").map(String::as_str), Some("info"));
        assert!(!props.contains_key("io.trino"));
    }
}
