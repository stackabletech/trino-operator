use stackable_operator::{
    product_logging::{
        framework::{create_vector_shutdown_file_command, remove_vector_shutdown_file_command},
        spec::{ContainerLogConfig, ContainerLogConfigChoice},
    },
    utils::COMMON_BASH_TRAP_FUNCTIONS,
};

use crate::{
    authentication::TrinoAuthenticationConfig,
    catalog::config::CatalogConfig,
    controller::{STACKABLE_LOG_CONFIG_DIR, STACKABLE_LOG_DIR},
    crd::{
        CONFIG_DIR_NAME, Container, LOG_PROPERTIES, RW_CONFIG_DIR_NAME, STACKABLE_CLIENT_TLS_DIR,
        STACKABLE_INTERNAL_TLS_DIR, STACKABLE_MOUNT_INTERNAL_TLS_DIR,
        STACKABLE_MOUNT_SERVER_TLS_DIR, STACKABLE_SERVER_TLS_DIR, STACKABLE_TLS_STORE_PASSWORD,
        TrinoRole, fault_tolerant_execution::ResolvedFaultTolerantExecutionConfig, v1alpha1,
    },
};

pub fn container_prepare_args(
    trino: &v1alpha1::TrinoCluster,
    catalogs: &[CatalogConfig],
    merged_config: &v1alpha1::TrinoConfig,
    resolved_fte_config: &Option<ResolvedFaultTolerantExecutionConfig>,
) -> Vec<String> {
    let mut args = vec![];

    // Copy custom logging provided `log.properties` to rw config
    if let Some(ContainerLogConfig {
        choice: Some(ContainerLogConfigChoice::Custom(_)),
    }) = merged_config.logging.containers.get(&Container::Trino)
    {
        // copy config files to a writeable empty folder
        args.push(format!(
            "echo copying {STACKABLE_LOG_CONFIG_DIR}/{LOG_PROPERTIES} {rw_conf}/{LOG_PROPERTIES}",
            rw_conf = RW_CONFIG_DIR_NAME
        ));
        args.push(format!(
            "cp -RL {STACKABLE_LOG_CONFIG_DIR}/{LOG_PROPERTIES} {rw_conf}/{LOG_PROPERTIES}",
            rw_conf = RW_CONFIG_DIR_NAME
        ));
    }

    // Create truststore that will be used when talking to external tools like S3
    // It will be populated from the system truststore so that connections against public services like AWS S3 are still possible
    // FIXME: *Technically* we should only add the system truststore in case any webPki usage is detected, wether that's in
    // S3, LDAP, OIDC, FTE or whatnot.
    args.push(format!("cert-tools generate-pkcs12-truststore --pem /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem --out {STACKABLE_CLIENT_TLS_DIR}/truststore.p12 --out-password {STACKABLE_TLS_STORE_PASSWORD}"));

    if trino.tls_enabled() {
        args.push(format!("cp {STACKABLE_MOUNT_SERVER_TLS_DIR}/truststore.p12 {STACKABLE_SERVER_TLS_DIR}/truststore.p12"));
        args.push(format!("cp {STACKABLE_MOUNT_SERVER_TLS_DIR}/keystore.p12 {STACKABLE_SERVER_TLS_DIR}/keystore.p12"));
    }

    if trino.get_internal_tls().is_some() {
        args.push(format!("cp {STACKABLE_MOUNT_INTERNAL_TLS_DIR}/truststore.p12 {STACKABLE_INTERNAL_TLS_DIR}/truststore.p12"));
        args.push(format!("cp {STACKABLE_MOUNT_INTERNAL_TLS_DIR}/keystore.p12 {STACKABLE_INTERNAL_TLS_DIR}/keystore.p12"));
        if trino.tls_enabled() {
            args.push(format!("cert-tools generate-pkcs12-truststore --pkcs12 {STACKABLE_MOUNT_SERVER_TLS_DIR}/truststore.p12:{STACKABLE_TLS_STORE_PASSWORD} --pkcs12 {STACKABLE_INTERNAL_TLS_DIR}/truststore.p12:{STACKABLE_TLS_STORE_PASSWORD} --out {STACKABLE_INTERNAL_TLS_DIR}/truststore.p12 --out-password {STACKABLE_TLS_STORE_PASSWORD}"));
        }
    }

    // Add the commands that are needed to set up the catalogs
    catalogs.iter().for_each(|catalog| {
        args.extend_from_slice(&catalog.init_container_extra_start_commands);
    });

    // Add the commands that are needed for fault tolerant execution (e.g., TLS certificates for S3)
    if let Some(resolved_fte) = resolved_fte_config {
        args.extend_from_slice(&resolved_fte.init_container_extra_start_commands);
    }

    args
}

pub fn container_trino_args(
    authentication_config: &TrinoAuthenticationConfig,
    catalogs: &[CatalogConfig],
    resolved_fte_config: &Option<ResolvedFaultTolerantExecutionConfig>,
) -> Vec<String> {
    let mut args = vec![
        // copy config files to a writeable empty folder
        format!(
            "echo copying {conf} to {rw_conf}",
            conf = CONFIG_DIR_NAME,
            rw_conf = RW_CONFIG_DIR_NAME
        ),
        format!(
            "cp -RL {conf}/* {rw_conf}",
            conf = CONFIG_DIR_NAME,
            rw_conf = RW_CONFIG_DIR_NAME
        ),
    ];

    // add required authentication commands
    args.extend(authentication_config.commands(&TrinoRole::Coordinator, &Container::Trino));

    // Add the commands that are needed to set up the catalogs
    // Don't print secret contents!
    args.push("set +x".to_string());
    catalogs.iter().for_each(|catalog| {
        for (env_name, file) in &catalog.load_env_from_files {
            args.push(format!("export {env_name}=\"$(cat {file})\""));
        }
    });

    // Add fault tolerant execution environment variables from files
    if let Some(resolved_fte) = resolved_fte_config {
        for (env_name, file) in &resolved_fte.load_env_from_files {
            args.push(format!("export {env_name}=\"$(cat {file})\""));
        }
    }

    args.push("set -x".to_string());

    // Start command
    args.push(format!(
        "\
{COMMON_BASH_TRAP_FUNCTIONS}
{remove_vector_shutdown_file_command}
prepare_signal_handlers
containerdebug --output={STACKABLE_LOG_DIR}/containerdebug-state.json --loop &
bin/launcher run --etc-dir={RW_CONFIG_DIR_NAME} &
wait_for_termination $!
{create_vector_shutdown_file_command}
",
        remove_vector_shutdown_file_command =
            remove_vector_shutdown_file_command(STACKABLE_LOG_DIR),
        create_vector_shutdown_file_command =
            create_vector_shutdown_file_command(STACKABLE_LOG_DIR),
    ));

    args
}

/// Adds a PEM file to configured PKCS12 truststore (using the [`STACKABLE_TLS_STORE_PASSWORD`]
/// password)
pub fn add_cert_to_truststore(cert_file: &str, destination_directory: &str) -> Vec<String> {
    let truststore = format!("{destination_directory}/truststore.p12");
    vec![format!(
        "cert-tools generate-pkcs12-truststore --pkcs12 {truststore}:{STACKABLE_TLS_STORE_PASSWORD} --pem {cert_file} --out {truststore} --out-password {STACKABLE_TLS_STORE_PASSWORD}"
    )]
}
