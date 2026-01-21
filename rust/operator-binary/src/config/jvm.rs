// As of 2024-07-05 we support multiple Trino versions. Some using Java 17, some Java 21 and the latest (455) uses Java 22.
// This requires a different JVM config
use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::{
    memory::{BinaryMultiple, MemoryQuantity},
    role_utils::{self, GenericRoleConfig, JavaCommonConfig, JvmArgumentOverrides, Role},
};

use crate::crd::{
    JVM_HEAP_FACTOR, JVM_SECURITY_PROPERTIES, METRICS_PORT, RW_CONFIG_DIR_NAME,
    STACKABLE_CLIENT_TLS_DIR, STACKABLE_TLS_STORE_PASSWORD, v1alpha1,
};

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("failed to convert java heap config to unit [{unit}]"))]
    FailedToConvertMemoryResourceConfigToJavaHeap {
        source: stackable_operator::memory::Error,
        unit: String,
    },

    #[snafu(display("invalid memory resource configuration - missing default or value in crd?"))]
    MissingMemoryResourceConfig,

    #[snafu(display("could not convert / scale memory resource config to [{unit}]"))]
    FailedToConvertMemoryResourceConfig {
        source: stackable_operator::memory::Error,
        unit: String,
    },

    #[snafu(display(
        "Trino version {version} is not supported. Only specific versions are handled due to version specific JVM configuration generation"
    ))]
    TrinoVersionNotSupported { version: u16 },

    #[snafu(display("failed to merge jvm argument overrides"))]
    MergeJvmArgumentOverrides { source: role_utils::Error },
}

// Currently works for all supported versions (as of 2024-09-04) but maybe be changed
// in the future depending on the role and version.
pub fn jvm_config(
    product_version: u16,
    merged_config: &v1alpha1::TrinoConfig,
    role: &Role<v1alpha1::TrinoConfigFragment, GenericRoleConfig, JavaCommonConfig>,
    role_group: &str,
) -> Result<String, Error> {
    let memory_unit = BinaryMultiple::Mebi;
    let heap_size = MemoryQuantity::try_from(
        merged_config
            .resources
            .memory
            .limit
            .as_ref()
            .context(MissingMemoryResourceConfigSnafu)?,
    )
    .context(FailedToConvertMemoryResourceConfigSnafu {
        unit: memory_unit.to_java_memory_unit(),
    })?
    .scale_to(memory_unit)
        * JVM_HEAP_FACTOR;

    let heap = heap_size.format_for_java().context(
        FailedToConvertMemoryResourceConfigToJavaHeapSnafu {
            unit: memory_unit.to_java_memory_unit(),
        },
    )?;

    let mut jvm_args = vec![
        "-server".to_owned(),
        "# Heap settings".to_owned(),
        format!("-Xms{heap}"),
        format!("-Xmx{heap}"),
        "# Specify security.properties".to_owned(),
        format!("-Djava.security.properties={RW_CONFIG_DIR_NAME}/{JVM_SECURITY_PROPERTIES}"),
        "# Prometheus metrics exporter".to_owned(),
        format!(
            "-javaagent:/stackable/jmx/jmx_prometheus_javaagent.jar={METRICS_PORT}:/stackable/jmx/config.yaml"
        ),
        "# Truststore settings".to_owned(),
        format!("-Djavax.net.ssl.trustStore={STACKABLE_CLIENT_TLS_DIR}/truststore.p12"),
        "-Djavax.net.ssl.trustStoreType=pkcs12".to_owned(),
        format!("-Djavax.net.ssl.trustStorePassword={STACKABLE_TLS_STORE_PASSWORD}"),
    ];

    jvm_args.push("# Recommended JVM arguments from Trino".to_owned());
    jvm_args.extend(recommended_trino_jvm_args(product_version)?);

    jvm_args.push("# Arguments from jvmArgumentOverrides".to_owned());

    let operator_generated = JvmArgumentOverrides::new_with_only_additions(jvm_args);
    let merged_jvm_argument_overrides = role
        .get_merged_jvm_argument_overrides(role_group, &operator_generated)
        .context(MergeJvmArgumentOverridesSnafu)?;

    Ok(merged_jvm_argument_overrides
        .effective_jvm_config_after_merging()
        .join("\n"))
}

/// For tests we don't actually look at the Trino version, and return a single "representative"
/// JVM argument instead.
/// This enables us to write version-independent tests, which don't need updating for every new
/// Trino version.
#[cfg(test)]
fn recommended_trino_jvm_args(_product_version: u16) -> Result<Vec<String>, Error> {
    Ok(vec!["-RecommendedTrinoFlag".to_owned()])
}

#[cfg(not(test))]
fn recommended_trino_jvm_args(product_version: u16) -> Result<Vec<String>, Error> {
    match product_version {
        // Copied from:
        // - https://trino.io/docs/477/installation/deployment.html#jvm-config
        // - https://trino.io/docs/479/installation/deployment.html#jvm-config
        477 | 479 => Ok(vec![
            "-XX:InitialRAMPercentage=80".to_owned(),
            "-XX:MaxRAMPercentage=80".to_owned(),
            "-XX:G1HeapRegionSize=32M".to_owned(),
            "-XX:+ExplicitGCInvokesConcurrent".to_owned(),
            "-XX:+ExitOnOutOfMemoryError".to_owned(),
            "-XX:+HeapDumpOnOutOfMemoryError".to_owned(),
            "-XX:-OmitStackTraceInFastThrow".to_owned(),
            "-XX:ReservedCodeCacheSize=512M".to_owned(),
            "-XX:PerMethodRecompilationCutoff=10000".to_owned(),
            "-XX:PerBytecodeRecompilationCutoff=10000".to_owned(),
            "-Djdk.attach.allowAttachSelf=true".to_owned(),
            "-Djdk.nio.maxCachedBufferSize=2000000".to_owned(),
            "-Dfile.encoding=UTF-8".to_owned(),
            "-XX:+EnableDynamicAgentLoading".to_owned(),
        ]),
        _ => TrinoVersionNotSupportedSnafu {
            version: product_version,
        }
        .fail(),
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use indoc::indoc;

    use super::*;
    use crate::crd::{TrinoRole, v1alpha1};

    #[test]
    fn test_jvm_config_defaults() {
        let input = r#"
        apiVersion: trino.stackable.tech/v1alpha1
        kind: TrinoCluster
        metadata:
          name: simple-trino
        spec:
          image:
            productVersion: "479"
          clusterConfig:
            catalogLabelSelector: {}
          coordinators:
            config:
              resources:
                memory:
                  limit: 42Gi
            roleGroups:
              default:
                replicas: 1
        "#;
        let jvm_config = construct_jvm_config(input);

        assert_eq!(
            jvm_config,
            indoc! {"
              -server
              # Heap settings
              -Xms34406m
              -Xmx34406m
              # Specify security.properties
              -Djava.security.properties=/stackable/rwconfig/security.properties
              # Prometheus metrics exporter
              -javaagent:/stackable/jmx/jmx_prometheus_javaagent.jar=8081:/stackable/jmx/config.yaml
              # Truststore settings
              -Djavax.net.ssl.trustStore=/stackable/client_tls/truststore.p12
              -Djavax.net.ssl.trustStoreType=pkcs12
              -Djavax.net.ssl.trustStorePassword=changeit
              # Recommended JVM arguments from Trino
              -RecommendedTrinoFlag
              # Arguments from jvmArgumentOverrides"}
        );
    }

    #[test]
    fn test_jvm_config_jvm_argument_overrides() {
        let input = r#"
        apiVersion: trino.stackable.tech/v1alpha1
        kind: TrinoCluster
        metadata:
          name: simple-trino
        spec:
          image:
            productVersion: "479"
          clusterConfig:
            catalogLabelSelector: {}
          coordinators:
            config:
              resources:
                memory:
                  limit: 42Gi
            jvmArgumentOverrides:
              remove:
                - -XX:+HeapDumpOnOutOfMemoryError
              add:
                - -Dhttps.proxyHost=proxy.my.corp
                - -Dhttps.proxyPort=8080
                - -Djava.net.preferIPv4Stack=true
            roleGroups:
              default:
                replicas: 1
                jvmArgumentOverrides:
                  # We need more memory!
                  removeRegex:
                    - -Xmx.*
                    - -Dhttps.proxyPort=.*
                  add:
                    - -Xmx40000m
                    - -Dhttps.proxyPort=1234
        "#;
        let jvm_config = construct_jvm_config(input);

        assert_eq!(
            jvm_config,
            indoc! {"
              -server
              # Heap settings
              -Xms34406m
              # Specify security.properties
              -Djava.security.properties=/stackable/rwconfig/security.properties
              # Prometheus metrics exporter
              -javaagent:/stackable/jmx/jmx_prometheus_javaagent.jar=8081:/stackable/jmx/config.yaml
              # Truststore settings
              -Djavax.net.ssl.trustStore=/stackable/client_tls/truststore.p12
              -Djavax.net.ssl.trustStoreType=pkcs12
              -Djavax.net.ssl.trustStorePassword=changeit
              # Recommended JVM arguments from Trino
              -RecommendedTrinoFlag
              # Arguments from jvmArgumentOverrides
              -Dhttps.proxyHost=proxy.my.corp
              -Djava.net.preferIPv4Stack=true
              -Xmx40000m
              -Dhttps.proxyPort=1234"}
        );
    }

    fn construct_jvm_config(trino_cluster: &str) -> String {
        let trino: v1alpha1::TrinoCluster =
            serde_yaml::from_str(trino_cluster).expect("illegal test input");

        let role = TrinoRole::Coordinator;
        let rolegroup_ref = role.rolegroup_ref(&trino, "default");
        let merged_config = trino.merged_config(&role, &rolegroup_ref, &[]).unwrap();
        let coordinators = trino.role(&role).unwrap();

        let product_version = trino.spec.image.product_version();

        jvm_config(
            u16::from_str(product_version).expect("trino version as u16"),
            &merged_config,
            &coordinators,
            "default",
        )
        .unwrap()
    }
}
