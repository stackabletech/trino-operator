// As of 2024-07-05 we support multiple Trino versions. Some using Java 17, some Java 21 and the latest (455) uses Java 22.
// This requires a different JVM config
use indoc::formatdoc;
use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::{
    commons::product_image_selection::ResolvedProductImage,
    memory::{BinaryMultiple, MemoryQuantity},
};
use stackable_trino_crd::{
    TrinoConfig, TrinoRole, JVM_HEAP_FACTOR, JVM_SECURITY_PROPERTIES, RW_CONFIG_DIR_NAME,
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
    resolved_product_image: &ResolvedProductImage,
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

    match resolved_product_image.product_version.as_str() {
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
            # https://bugs.openjdk.org/browse/JDK-8329528
            -XX:+UnlockDiagnosticVMOptions
            -XX:G1NumCollectionsKeepPinned=10000000

            -Djavax.net.ssl.trustStore={STACKABLE_CLIENT_TLS_DIR}/truststore.p12
            -Djavax.net.ssl.trustStorePassword={STACKABLE_TLS_STORE_PASSWORD}
            -Djavax.net.ssl.trustStoreType=pkcs12
            -Djava.security.properties={RW_CONFIG_DIR_NAME}/{JVM_SECURITY_PROPERTIES}
            ",
        )),
        _ => TrinoVersionNotSupportedSnafu {
            version: resolved_product_image.product_version.clone(),
        }
        .fail(),
    }
}
