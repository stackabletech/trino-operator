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

    // 1. Defaults
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
    props.extend(rg.config_overrides.security_properties.clone());

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

    fn coordinator_rg(
        cluster: &crate::controller::ValidatedCluster,
    ) -> crate::controller::TrinoRoleGroupConfig {
        cluster.role_group_configs[&TrinoRole::Coordinator]
            .values()
            .next()
            .unwrap()
            .clone()
    }

    #[test]
    fn default_renders_networkaddress_cache_settings() {
        let cluster = validated_cluster_from_yaml(MINIMAL_TRINO_YAML);
        let props = build(&coordinator_rg(&cluster));
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

    #[test]
    fn user_override_wins_and_extra_key_is_added() {
        let cluster = validated_cluster_from_yaml(
            r#"
            apiVersion: trino.stackable.tech/v1alpha1
            kind: TrinoCluster
            metadata:
              name: simple-trino
              namespace: default
              uid: "e6ac237d-a6d4-43a1-8135-f36506110912"
            spec:
              image:
                productVersion: "481"
              clusterConfig:
                catalogLabelSelector: {}
              coordinators:
                roleGroups:
                  default:
                    replicas: 1
                    configOverrides:
                      security.properties:
                        networkaddress.cache.ttl: "99"
                        custom.extra.key: "myvalue"
              workers:
                roleGroups:
                  default:
                    replicas: 1
            "#,
        );
        let props = build(&coordinator_rg(&cluster));

        // User override wins over the default.
        assert_eq!(
            props.get("networkaddress.cache.ttl").map(String::as_str),
            Some("99")
        );
        // Extra (non-default) override key is added.
        assert_eq!(
            props.get("custom.extra.key").map(String::as_str),
            Some("myvalue")
        );
        // Untouched default remains.
        assert_eq!(
            props
                .get("networkaddress.cache.negative.ttl")
                .map(String::as_str),
            Some("0")
        );
    }
}
