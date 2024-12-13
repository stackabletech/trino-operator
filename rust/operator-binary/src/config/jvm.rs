use std::collections::BTreeMap;

// As of 2024-07-05 we support multiple Trino versions. Some using Java 17, some Java 21 and the latest (455) uses Java 22.
// This requires a different JVM config
use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::{
    config::merge::Merge,
    memory::{BinaryMultiple, MemoryQuantity},
    role_utils::{JavaCommonConfig, JvmArgument},
};
use stackable_trino_crd::{
    TrinoConfig, JVM_HEAP_FACTOR, JVM_SECURITY_PROPERTIES, METRICS_PORT, RW_CONFIG_DIR_NAME,
    STACKABLE_CLIENT_TLS_DIR, STACKABLE_TLS_STORE_PASSWORD,
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

    #[snafu(display("the Trino version {version} is not supported, as we don't know the needed JVm configuration"))]
    TrinoVersionNotSupported { version: String },
}

// Currently works for all supported versions (451 and 455 as of 2024-09-04) but maybe be changed
// in the future depending on the role and version.
pub fn jvm_config(
    product_version: &str,
    merged_config: &TrinoConfig,
    java_common_config: &JavaCommonConfig,
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

    let mut jvm_args = BTreeMap::from([
        ("-server".to_owned(), JvmArgument::Flag {}),
        // Heap settings
        (format!("-Xms{heap}"), JvmArgument::Flag {}),
        (format!("-Xmx{heap}"), JvmArgument::Flag {}),
        // Truststore settings
        (
            "-Djavax.net.ssl.trustStore".to_owned(),
            JvmArgument::Argument(format!("{STACKABLE_CLIENT_TLS_DIR}/truststore.p12")),
        ),
        (
            "-Djavax.net.ssl.trustStorePassword".to_owned(),
            JvmArgument::Argument(STACKABLE_TLS_STORE_PASSWORD.to_owned()),
        ),
        (
            "-Djavax.net.ssl.trustStoreType".to_owned(),
            JvmArgument::Argument("pkcs12".to_owned()),
        ),
        // security.properties
        (
            "-Djava.security.properties".to_owned(),
            JvmArgument::Argument(format!("{RW_CONFIG_DIR_NAME}/{JVM_SECURITY_PROPERTIES}")),
        ),
        // Prometheus metrics exporter
        (
            "-javaagent:/stackable/jmx/jmx_prometheus_javaagent.jar".to_owned(),
            JvmArgument::Argument(format!("{METRICS_PORT}:/stackable/jmx/config.yaml")),
        ),
    ]);
    jvm_args.extend(recommended_trino_jvm_args(product_version)?);

    let mut merged_java_config = java_common_config.clone();
    merged_java_config.merge(&JavaCommonConfig::new(jvm_args));

    Ok(merged_java_config
        .effective_jvm_config()
        .into_iter()
        .map(|(key, value)| match value {
            Some(argument) => {
                format!("{key}={argument}")
            }
            None => key,
        })
        .collect::<Vec<String>>()
        .join("\n"))
}

fn recommended_trino_jvm_args(
    product_version: &str,
) -> Result<BTreeMap<String, JvmArgument>, Error> {
    match product_version {
        // Copied from https://trino.io/docs/451/installation/deployment.html
        "451" => Ok(BTreeMap::from([
            (
                "-XX:InitialRAMPercentage".to_owned(),
                JvmArgument::Argument("80".to_owned()),
            ),
            (
                "-XX:MaxRAMPercentage".to_owned(),
                JvmArgument::Argument("80".to_owned()),
            ),
            (
                "-XX:G1HeapRegionSize".to_owned(),
                JvmArgument::Argument("32M".to_owned()),
            ),
            (
                "-XX:+ExitOnOutOfMemoryError".to_owned(),
                JvmArgument::Flag {},
            ),
            (
                "-XX:+HeapDumpOnOutOfMemoryError".to_owned(),
                JvmArgument::Flag {},
            ),
            (
                "-XX:-OmitStackTraceInFastThrow".to_owned(),
                JvmArgument::Flag {},
            ),
            (
                "-XX:ReservedCodeCacheSize".to_owned(),
                JvmArgument::Argument("512M".to_owned()),
            ),
            (
                "-XX:PerMethodRecompilationCutoff".to_owned(),
                JvmArgument::Argument("10000".to_owned()),
            ),
            (
                "-XX:PerBytecodeRecompilationCutoff".to_owned(),
                JvmArgument::Argument("10000".to_owned()),
            ),
            (
                "-Djdk.attach.allowAttachSelf".to_owned(),
                JvmArgument::Argument("true".to_owned()),
            ),
            (
                "-Djdk.nio.maxCachedBufferSize".to_owned(),
                JvmArgument::Argument("2000000".to_owned()),
            ),
            (
                "-Dfile.encoding".to_owned(),
                JvmArgument::Argument("UTF-8".to_owned()),
            ),
            (
                "-XX:+EnableDynamicAgentLoading".to_owned(),
                JvmArgument::Flag {},
            ),
            (
                "-XX:+UnlockDiagnosticVMOptions".to_owned(),
                JvmArgument::Flag {},
            ),
            (
                "-XX:G1NumCollectionsKeepPinned".to_owned(),
                JvmArgument::Argument("10000000".to_owned()),
            ),
        ])),
        // Copied from https://trino.io/docs/455/installation/deployment.html#jvm-config
        "455" => Ok(BTreeMap::from([
            (
                "-XX:InitialRAMPercentage".to_owned(),
                JvmArgument::Argument("80".to_owned()),
            ),
            (
                "-XX:MaxRAMPercentage".to_owned(),
                JvmArgument::Argument("80".to_owned()),
            ),
            (
                "-XX:G1HeapRegionSize".to_owned(),
                JvmArgument::Argument("32M".to_owned()),
            ),
            (
                "-XX:+ExplicitGCInvokesConcurrent".to_owned(),
                JvmArgument::Flag {},
            ),
            (
                "-XX:+ExitOnOutOfMemoryError".to_owned(),
                JvmArgument::Flag {},
            ),
            (
                "-XX:+HeapDumpOnOutOfMemoryError".to_owned(),
                JvmArgument::Flag {},
            ),
            (
                "-XX:-OmitStackTraceInFastThrow".to_owned(),
                JvmArgument::Flag {},
            ),
            (
                "-XX:ReservedCodeCacheSize".to_owned(),
                JvmArgument::Argument("512M".to_owned()),
            ),
            (
                "-XX:PerMethodRecompilationCutoff".to_owned(),
                JvmArgument::Argument("10000".to_owned()),
            ),
            (
                "-XX:PerBytecodeRecompilationCutoff".to_owned(),
                JvmArgument::Argument("10000".to_owned()),
            ),
            (
                "-Djdk.attach.allowAttachSelf".to_owned(),
                JvmArgument::Argument("true".to_owned()),
            ),
            (
                "-Djdk.nio.maxCachedBufferSize".to_owned(),
                JvmArgument::Argument("2000000".to_owned()),
            ),
            (
                "-Dfile.encoding".to_owned(),
                JvmArgument::Argument("UTF-8".to_owned()),
            ),
            (
                "-XX:+EnableDynamicAgentLoading".to_owned(),
                JvmArgument::Flag {},
            ),
        ])),
        _ => TrinoVersionNotSupportedSnafu {
            version: product_version,
        }
        .fail(),
    }
}

#[cfg(test)]
mod tests {
    use indoc::indoc;
    use stackable_trino_crd::{TrinoCluster, TrinoRole};

    use super::*;

    #[test]
    fn test_jvm_config_defaults() {
        let input = r#"
        apiVersion: trino.stackable.tech/v1alpha1
        kind: TrinoCluster
        metadata:
          name: simple-trino
        spec:
          image:
            productVersion: "455"
          clusterConfig:
            catalogLabelSelector: {}
          coordinators:
            config:
              resources:
                memory:
                  limit: 42Gi
              experimentalAdditionalJvmArguments:
                -Dhttps.proxyHost: proxy.my.corp
                -Dhttps.proxyPort: "1234"
                -Dhttp.nonProxyHosts: localhost
                -Djava.net.preferIPv4Stack: "true"
                -XX:+ExitOnOutOfMemoryError: null
            roleGroups:
              default:
                replicas: 1
        "#;
        let trino: TrinoCluster = serde_yaml::from_str(input).expect("illegal test input");

        let role = TrinoRole::Coordinator;
        let rolegroup_ref = role.rolegroup_ref(&trino, "default");
        let merged_config = trino.merged_config(&role, &rolegroup_ref, &[]).unwrap();
        let java_common_config = trino
            .spec
            .coordinators
            .unwrap()
            .merged_product_specific_common_config("default")
            .unwrap();
        let jvm_config = jvm_config(
            trino.spec.image.product_version(),
            &merged_config,
            &java_common_config,
        )
        .unwrap();

        assert_eq!(
            jvm_config,
            indoc! {"
                -Dfile.encoding=UTF-8
                -Djava.security.properties=/stackable/rwconfig/security.properties
                -Djavax.net.ssl.trustStore=/stackable/client_tls/truststore.p12
                -Djavax.net.ssl.trustStorePassword=changeit
                -Djavax.net.ssl.trustStoreType=pkcs12
                -Djdk.attach.allowAttachSelf=true
                -Djdk.nio.maxCachedBufferSize=2000000
                -XX:+EnableDynamicAgentLoading
                -XX:+ExitOnOutOfMemoryError
                -XX:+ExplicitGCInvokesConcurrent
                -XX:+HeapDumpOnOutOfMemoryError
                -XX:-OmitStackTraceInFastThrow
                -XX:G1HeapRegionSize=32M
                -XX:InitialRAMPercentage=80
                -XX:MaxRAMPercentage=80
                -XX:PerBytecodeRecompilationCutoff=10000
                -XX:PerMethodRecompilationCutoff=10000
                -XX:ReservedCodeCacheSize=512M
                -Xms34406m
                -Xmx34406m
                -javaagent:/stackable/jmx/jmx_prometheus_javaagent.jar=8081:/stackable/jmx/config.yaml
                -server"}
        );
    }

    #[test]
    fn test_jvm_config_jvm_argument_overrides() {
        todo!("It's Friday...")
    }
}
