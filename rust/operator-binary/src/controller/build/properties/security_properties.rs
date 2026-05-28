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
    use super::*;
    use crate::{
        controller::build::properties::test_support::{
            MINIMAL_TRINO_YAML, validated_cluster_from_yaml,
        },
        crd::TrinoRole,
    };

    #[test]
    fn default_renders_networkaddress_cache_settings() {
        let cluster = validated_cluster_from_yaml(MINIMAL_TRINO_YAML);
        let rg = cluster.role_group_configs[&TrinoRole::Coordinator]["default"].clone();
        let props = build(&rg);
        assert_eq!(
            props.get("networkaddress.cache.ttl").map(String::as_str),
            Some("30")
        );
        assert_eq!(
            props
                .get("networkaddress.cache.negative.ttl")
                .map(String::as_str),
            Some("0")
        );
    }
}
