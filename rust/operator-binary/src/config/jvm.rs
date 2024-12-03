// As of 2024-07-05 we support multiple Trino versions. Some using Java 17, some Java 21 and the latest (455) uses Java 22.
// This requires a different JVM config
use indoc::formatdoc;
use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::memory::{BinaryMultiple, MemoryQuantity};
use stackable_trino_crd::{
    JvmArgument, TrinoConfig, TrinoRole, JVM_HEAP_FACTOR, JVM_SECURITY_PROPERTIES, METRICS_PORT,
    RW_CONFIG_DIR_NAME, STACKABLE_CLIENT_TLS_DIR, STACKABLE_TLS_STORE_PASSWORD,
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
    _role: &TrinoRole,
    merged_config: &TrinoConfig,
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

    let mut jvm_config = match product_version {
        // Copied from https://trino.io/docs/451/installation/deployment.html
        "451" => Ok(formatdoc!(
            "-server
            -Xms{heap}
            -Xmx{heap}

            -XX:InitialRAMPercentage=80
            -XX:MaxRAMPercentage=80
            -XX:G1HeapRegionSize=32M
            -XX:+ExplicitGCInvokesConcurrent
            -XX:+ExitOnOutOfMemoryError
            -XX:+HeapDumpOnOutOfMemoryError
            -XX:-OmitStackTraceInFastThrow
            -XX:ReservedCodeCacheSize=512M
            -XX:PerMethodRecompilationCutoff=10000
            -XX:PerBytecodeRecompilationCutoff=10000
            -Djdk.attach.allowAttachSelf=true
            -Djdk.nio.maxCachedBufferSize=2000000
            -Dfile.encoding=UTF-8
            # Allow loading dynamic agent used by JOL
            -XX:+EnableDynamicAgentLoading
            # https://bugs.openjdk.org/browse/JDK-8329528
            -XX:+UnlockDiagnosticVMOptions
            -XX:G1NumCollectionsKeepPinned=10000000

            -Djavax.net.ssl.trustStore={STACKABLE_CLIENT_TLS_DIR}/truststore.p12
            -Djavax.net.ssl.trustStorePassword={STACKABLE_TLS_STORE_PASSWORD}
            -Djavax.net.ssl.trustStoreType=pkcs12
            -Djava.security.properties={RW_CONFIG_DIR_NAME}/{JVM_SECURITY_PROPERTIES}
            ",
        )),
        // Copied from https://trino.io/docs/455/installation/deployment.html#jvm-config
        "455" => Ok(formatdoc!(
            "-server
            -Xms{heap}
            -Xmx{heap}

            -XX:InitialRAMPercentage=80
            -XX:MaxRAMPercentage=80
            -XX:G1HeapRegionSize=32M
            -XX:+ExplicitGCInvokesConcurrent
            -XX:+ExitOnOutOfMemoryError
            -XX:+HeapDumpOnOutOfMemoryError
            -XX:-OmitStackTraceInFastThrow
            -XX:ReservedCodeCacheSize=512M
            -XX:PerMethodRecompilationCutoff=10000
            -XX:PerBytecodeRecompilationCutoff=10000
            -Djdk.attach.allowAttachSelf=true
            -Djdk.nio.maxCachedBufferSize=2000000
            -Dfile.encoding=UTF-8
            # Allow loading dynamic agent used by JOL
            -XX:+EnableDynamicAgentLoading

            -Djavax.net.ssl.trustStore={STACKABLE_CLIENT_TLS_DIR}/truststore.p12
            -Djavax.net.ssl.trustStorePassword={STACKABLE_TLS_STORE_PASSWORD}
            -Djavax.net.ssl.trustStoreType=pkcs12
            -Djava.security.properties={RW_CONFIG_DIR_NAME}/{JVM_SECURITY_PROPERTIES}
            ",
        )),
        _ => TrinoVersionNotSupportedSnafu {
            version: product_version.to_owned(),
        }
        .fail(),
    }?;

    jvm_config.push_str(&formatdoc!("

        # Enable the export of Prometheus metrics on port {METRICS_PORT}
        -javaagent:/stackable/jmx/jmx_prometheus_javaagent.jar={METRICS_PORT}:/stackable/jmx/config.yaml
        "
    ));

    let additional_jvm_arguments = &merged_config.experimental_additional_jvm_arguments;
    if !additional_jvm_arguments.is_empty() {
        jvm_config.push_str("\n# Additional JVM arguments specified on Custom Resource");
        for (key, JvmArgument(value)) in additional_jvm_arguments {
            match value {
                Some(value) => {
                    jvm_config.push_str(&format!("\n{key}={value}"));
                }
                None => {
                    jvm_config.push_str(&format!("\n{key}"));
                }
            }
        }
        jvm_config.push('\n');
    }

    Ok(jvm_config)
}

#[cfg(test)]
mod tests {
    use indoc::indoc;
    use stackable_trino_crd::TrinoCluster;

    use super::*;

    #[test]
    fn test_jvm_config() {
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
        let jvm_config = jvm_config("455", &role, &merged_config).unwrap();

        assert_eq!(
            jvm_config,
            indoc! {"
                -server
                -Xms34406m
                -Xmx34406m

                -XX:InitialRAMPercentage=80
                -XX:MaxRAMPercentage=80
                -XX:G1HeapRegionSize=32M
                -XX:+ExplicitGCInvokesConcurrent
                -XX:+ExitOnOutOfMemoryError
                -XX:+HeapDumpOnOutOfMemoryError
                -XX:-OmitStackTraceInFastThrow
                -XX:ReservedCodeCacheSize=512M
                -XX:PerMethodRecompilationCutoff=10000
                -XX:PerBytecodeRecompilationCutoff=10000
                -Djdk.attach.allowAttachSelf=true
                -Djdk.nio.maxCachedBufferSize=2000000
                -Dfile.encoding=UTF-8
                # Allow loading dynamic agent used by JOL
                -XX:+EnableDynamicAgentLoading

                -Djavax.net.ssl.trustStore=/stackable/client_tls/truststore.p12
                -Djavax.net.ssl.trustStorePassword=changeit
                -Djavax.net.ssl.trustStoreType=pkcs12
                -Djava.security.properties=/stackable/rwconfig/security.properties

                # Enable the export of Prometheus metrics on port 8081
                -javaagent:/stackable/jmx/jmx_prometheus_javaagent.jar=8081:/stackable/jmx/config.yaml

                # Additional JVM arguments specified on Custom Resource
                -Dhttp.nonProxyHosts=localhost
                -Dhttps.proxyHost=proxy.my.corp
                -Dhttps.proxyPort=1234
                -Djava.net.preferIPv4Stack=true
                -XX:+ExitOnOutOfMemoryError
            "}
        );
    }
}
