// As of 2024-07-05 we support multiple Trino versions. Some using Java 17, some Java 21 and the latest (455) uses Java 22.
// This requires a different JVM config
use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::{
    memory::{BinaryMultiple, MemoryQuantity},
    v2::jvm_argument_overrides::JvmArgumentOverrides,
};

use crate::{
    controller::ValidatedTrinoConfig,
    crd::{
        METRICS_PORT, RW_CONFIG_DIR_NAME, STACKABLE_CLIENT_TLS_DIR, STACKABLE_TLS_STORE_PASSWORD,
    },
};

const JVM_SECURITY_PROPERTIES: &str = "security.properties";

const JVM_HEAP_FACTOR: f32 = 0.8;

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
}

// Currently works for all supported versions (as of 2024-09-04) but maybe be changed
// in the future depending on the role and version.
pub fn jvm_config(
    product_version: u16,
    merged_config: &ValidatedTrinoConfig,
    jvm_argument_overrides: &JvmArgumentOverrides,
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

    // `jvm_argument_overrides` already carries the merged role + role-group overrides (merged by
    // `with_validated_config` in the validate step). Applying them to the operator-generated args
    // layers the overrides on top, in the order: operator-generated <- role <- role group.
    Ok(jvm_argument_overrides.apply_to(jvm_args).join("\n"))
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
        477 => Ok(vec![
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
        // Copied from:
        // - https://trino.io/docs/479/installation/deployment.html#jvm-config.
        //   However, the docs are wrong: https://github.com/trinodb/trino/commit/1ddb0f9976fcd9917aaf0b689ca0acc8635e24f1.
        //   According to the commit we need to add "--add-modules=jdk.incubator.vector"
        479 => Ok(vec![
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
            "--add-modules=jdk.incubator.vector".to_owned(),
        ]),
        // Copied from:
        // - https://trino.io/docs/481/installation/deployment.html#jvm-config
        481 => Ok(vec![
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
            "--add-modules=jdk.incubator.vector".to_owned(),
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
            productVersion: "481"
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
            productVersion: "481"
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

        // Merge + validate via the shared production path; the role + role-group
        // `jvmArgumentOverrides` end up merged in `product_specific_common_config`.
        let rg = crate::controller::validate::merged_role_group_config(
            &trino,
            &TrinoRole::Coordinator,
            "default",
            &[],
        );

        let product_version =
            u16::from_str(trino.spec.image.product_version()).expect("trino version as u16");

        jvm_config(
            product_version,
            &rg.config,
            &rg.product_specific_common_config.jvm_argument_overrides,
        )
        .unwrap()
    }
}
