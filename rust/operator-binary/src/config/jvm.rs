// As of 2024-02-07 we support multiple Trino versions. Some using Java 17 and the latest (438) uses Java 21.
// This requires a different JVM config
use indoc::formatdoc;
use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::{
    commons::product_image_selection::ResolvedProductImage,
    memory::{BinaryMultiple, MemoryQuantity},
};
use stackable_trino_crd::{
    TrinoConfig, JVM_HEAP_FACTOR, JVM_SECURITY_PROPERTIES, RW_CONFIG_DIR_NAME,
    STACKABLE_CLIENT_TLS_DIR, STACKABLE_TLS_STORE_PASSWORD,
};

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("failed to convert java heap config to unit [{unit}]"))]
    FailedToConvertMemoryResourceConfigToJavaHeap {
        source: stackable_operator::error::Error,
        unit: String,
    },
    #[snafu(display("invalid memory resource configuration - missing default or value in crd?"))]
    MissingMemoryResourceConfig,
    #[snafu(display("could not convert / scale memory resource config to [{unit}]"))]
    FailedToConvertMemoryResourceConfig {
        source: stackable_operator::error::Error,
        unit: String,
    },
}

pub fn jvm_config(
    resolved_product_image: &ResolvedProductImage,
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

    match resolved_product_image.product_version.as_str() {
        // from https://trino.io/docs/414/installation/deployment.html#jvm-config 
        "414" => {
            Ok(formatdoc!(
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
                -XX:+UnlockDiagnosticVMOptions
                -XX:+UseAESCTRIntrinsics
                # Disable Preventive GC for performance reasons (JDK-8293861)
                -XX:-G1UsePreventiveGC
                -Djavax.net.ssl.trustStore={STACKABLE_CLIENT_TLS_DIR}/truststore.p12
                -Djavax.net.ssl.trustStorePassword={STACKABLE_TLS_STORE_PASSWORD}
                -Djavax.net.ssl.trustStoreType=pkcs12
                -Djava.security.properties={RW_CONFIG_DIR_NAME}/{JVM_SECURITY_PROPERTIES}
                ",
            ))
        }
        // from https://trino.io/docs/428/installation/deployment.html#jvm-config
        "428" => {
            Ok(formatdoc!(
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
                -XX:+UnlockDiagnosticVMOptions
                -XX:+UseAESCTRIntrinsics
                -Dfile.encoding=UTF-8
                # Disable Preventive GC for performance reasons (JDK-8293861)
                -XX:-G1UsePreventiveGC  
                # Reduce starvation of threads by GClocker, recommend to set about the number of cpu cores (JDK-8192647)
                -XX:GCLockerRetryAllocationCount=32
                -Djavax.net.ssl.trustStore={STACKABLE_CLIENT_TLS_DIR}/truststore.p12
                -Djavax.net.ssl.trustStorePassword={STACKABLE_TLS_STORE_PASSWORD}
                -Djavax.net.ssl.trustStoreType=pkcs12
                -Djava.security.properties={RW_CONFIG_DIR_NAME}/{JVM_SECURITY_PROPERTIES}
                ",
            ))
        }
        // from https://trino.io/docs/438/installation/deployment.html#jvm-config
        // otherwise use the (currently) 438 one
        _ =>  {            Ok(formatdoc!(
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
            # Reduce starvation of threads by GClocker, recommend to set about the number of cpu cores (JDK-8192647)
            -XX:+UnlockDiagnosticVMOptions
            -XX:GCLockerRetryAllocationCount=32
            -Djavax.net.ssl.trustStore={STACKABLE_CLIENT_TLS_DIR}/truststore.p12
            -Djavax.net.ssl.trustStorePassword={STACKABLE_TLS_STORE_PASSWORD}
            -Djavax.net.ssl.trustStoreType=pkcs12
            -Djava.security.properties={RW_CONFIG_DIR_NAME}/{JVM_SECURITY_PROPERTIES}
            ",
        ))}

    }
}
