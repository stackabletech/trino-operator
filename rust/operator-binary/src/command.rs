use crate::{
    authentication::TrinoAuthenticationConfig, catalog::config::CatalogConfig,
    controller::STACKABLE_LOG_CONFIG_DIR,
};

use stackable_operator::product_logging::spec::{ContainerLogConfig, ContainerLogConfigChoice};
use stackable_trino_crd::{
    Container, TrinoCluster, TrinoConfig, TrinoRole, CONFIG_DIR_NAME, DATA_DIR_NAME,
    LOG_PROPERTIES, RW_CONFIG_DIR_NAME, STACKABLE_CLIENT_TLS_DIR, STACKABLE_INTERNAL_TLS_DIR,
    STACKABLE_MOUNT_INTERNAL_TLS_DIR, STACKABLE_MOUNT_SERVER_TLS_DIR, STACKABLE_SERVER_TLS_DIR,
    STACKABLE_TLS_STORE_PASSWORD, SYSTEM_TRUST_STORE, SYSTEM_TRUST_STORE_PASSWORD,
};

pub fn container_prepare_args(
    trino: &TrinoCluster,
    catalogs: &[CatalogConfig],
    merged_config: &TrinoConfig,
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

    if trino.tls_enabled() {
        args.extend(import_truststore(
            STACKABLE_MOUNT_SERVER_TLS_DIR,
            STACKABLE_SERVER_TLS_DIR,
        ));
        args.extend(import_keystore(
            STACKABLE_MOUNT_SERVER_TLS_DIR,
            STACKABLE_SERVER_TLS_DIR,
        ));
    }

    if trino.get_internal_tls().is_some() {
        args.extend(import_truststore(
            STACKABLE_MOUNT_INTERNAL_TLS_DIR,
            STACKABLE_INTERNAL_TLS_DIR,
        ));
        args.extend(import_keystore(
            STACKABLE_MOUNT_INTERNAL_TLS_DIR,
            STACKABLE_INTERNAL_TLS_DIR,
        ));
        // Add cert to internal truststore
        if trino.tls_enabled() {
            args.extend(import_truststore(
                STACKABLE_MOUNT_SERVER_TLS_DIR,
                STACKABLE_INTERNAL_TLS_DIR,
            ))
        }
    }

    // Create truststore that will be used when talking to external tools like S3
    // It will be populated from the system truststore so that connections against public services like AWS S3 are still possible
    args.extend(create_truststore_from_system_truststore(
        STACKABLE_CLIENT_TLS_DIR,
    ));

    // Add the commands that are needed to set up the catalogs
    catalogs.iter().for_each(|catalog| {
        args.extend_from_slice(&catalog.init_container_extra_start_commands);
    });

    args
}

pub fn container_trino_args(
    authentication_config: &TrinoAuthenticationConfig,
    catalogs: &[CatalogConfig],
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
    catalogs.iter().for_each(|catalog| {
        for (env_name, file) in &catalog.load_env_from_files {
            args.push(format!("export {env_name}=$(cat {file})"));
        }
    });

    // start command
    args.push(format!(
        "bin/launcher run --etc-dir={conf} --data-dir={data}",
        conf = RW_CONFIG_DIR_NAME,
        data = DATA_DIR_NAME
    ));

    vec![args.join(" && ")]
}

/// Generates the shell script to create key and truststores from the certificates provided
/// by the secret operator.
pub fn import_keystore(source_directory: &str, destination_directory: &str) -> Vec<String> {
    vec![
        // The source directory is a secret-op mount and we do not want to write / add anything in there
        // Therefore we import all the contents to "writeable" stores in another folder.
        // Keytool is only barking if a password is not set for the destination keystore (which we set)
        // and do not provide any password for the source keystores.
        format!("keytool -importkeystore -srckeystore {source_directory}/keystore.p12 -srcstoretype PKCS12 -srcstorepass \"\" -destkeystore {destination_directory}/keystore.p12 -deststoretype PKCS12 -deststorepass {STACKABLE_TLS_STORE_PASSWORD} -noprompt"),
    ]
}

pub fn import_truststore(source_directory: &str, destination_directory: &str) -> Vec<String> {
    vec![
        format!("keytool -importkeystore -srckeystore {source_directory}/truststore.p12 -srcstoretype PKCS12 -srcstorepass \"\" -destkeystore {destination_directory}/truststore.p12 -deststoretype PKCS12 -deststorepass {STACKABLE_TLS_STORE_PASSWORD} -noprompt"),
    ]
}

pub fn create_truststore_from_system_truststore(truststore_directory: &str) -> Vec<String> {
    vec![
        format!("echo [{truststore_directory}] Creating truststore {truststore_directory}/truststore.p12 from system truststore {SYSTEM_TRUST_STORE}"),
        format!("keytool -importkeystore -srckeystore {SYSTEM_TRUST_STORE} -srcstoretype jks -srcstorepass {SYSTEM_TRUST_STORE_PASSWORD} -destkeystore {truststore_directory}/truststore.p12 -deststoretype pkcs12 -deststorepass {STACKABLE_TLS_STORE_PASSWORD} -noprompt"),
    ]
}

pub fn add_cert_to_stackable_truststore(
    cert_file: &str,
    truststore_directory: &str,
    alias_name: &str,
) -> Vec<String> {
    vec![
        format!("echo [{truststore_directory}] Adding cert from {cert_file} to truststore {truststore_directory}/truststore.p12"),
        format!("keytool -importcert -file {cert_file} -keystore {truststore_directory}/truststore.p12 -storetype pkcs12 -noprompt -alias {alias_name} -storepass {STACKABLE_TLS_STORE_PASSWORD}"),
    ]
}
