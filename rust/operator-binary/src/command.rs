use crate::{
    authentication::TrinoAuthenticationConfig, catalog::config::CatalogConfig,
    controller::STACKABLE_LOG_CONFIG_DIR,
};

use stackable_operator::product_logging::spec::{ContainerLogConfig, ContainerLogConfigChoice};
use stackable_trino_crd::{
    Container, TrinoCluster, TrinoConfig, CONFIG_DIR_NAME, DATA_DIR_NAME, LOG_PROPERTIES,
    RW_CONFIG_DIR_NAME, STACKABLE_CLIENT_TLS_DIR, STACKABLE_INTERNAL_TLS_DIR,
    STACKABLE_MOUNT_INTERNAL_TLS_DIR, STACKABLE_MOUNT_SERVER_TLS_DIR, STACKABLE_SERVER_TLS_DIR,
    STACKABLE_TLS_STORE_PASSWORD, SYSTEM_TRUST_STORE, SYSTEM_TRUST_STORE_PASSWORD,
};

pub const STACKABLE_CLIENT_CA_CERT: &str = "stackable-client-ca-cert";
pub const STACKABLE_SERVER_CA_CERT: &str = "stackable-server-ca-cert";
pub const STACKABLE_INTERNAL_CA_CERT: &str = "stackable-internal-ca-cert";

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
        args.extend(create_key_and_trust_store(
            STACKABLE_MOUNT_SERVER_TLS_DIR,
            STACKABLE_SERVER_TLS_DIR,
            STACKABLE_SERVER_CA_CERT,
        ));
    }

    if trino.get_internal_tls().is_some() {
        args.extend(create_key_and_trust_store(
            STACKABLE_MOUNT_INTERNAL_TLS_DIR,
            STACKABLE_INTERNAL_TLS_DIR,
            STACKABLE_INTERNAL_CA_CERT,
        ));
        // Add cert to internal truststore
        if trino.tls_enabled() {
            args.extend(add_cert_to_stackable_truststore(
                format!("{STACKABLE_MOUNT_SERVER_TLS_DIR}/ca.crt").as_str(),
                STACKABLE_INTERNAL_TLS_DIR,
                STACKABLE_CLIENT_CA_CERT,
            ));
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
    _user_authentication: &TrinoAuthenticationConfig,
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
        // TODO: test
        //"echo 'admin:$2y$10$89xReovvDLacVzRGpjOyAOONnayOgDAyIS2nW9bs5DJT98q17Dy5i' > /stackable/users/password.db".to_string()
    ];

    // TODO: Fix
    // match user_authentication {
    //     Some(TrinoAuthenticationConfig::MultiUser { user_credentials }) => {
    //         // Write an extra password file if MultiUser auth requested
    //         let user_data = user_credentials
    //             .iter()
    //             .map(|(user, password)| format!("{}:{}", user, password))
    //             .collect::<Vec<_>>()
    //             .join("\n");
    //
    //         // FIXME: When we switch to AuthenticationClass static we need to fix this to not have credentials in the Pod manifest (for now they are hashes).
    //         args.push(format!(
    //             "echo '{data}' > {path}/{db}",
    //             data = user_data,
    //             path = USER_PASSWORD_DATA_DIR_NAME,
    //             db = PASSWORD_DB
    //         ));
    //     }
    //     Some(TrinoAuthenticationConfig::Ldap(ldap)) => {
    //         // Set the env vars from the mounted secrets, we read them later in the config (see config.rs)
    //         if let Some((user_path, password_path)) = ldap.bind_credentials_mount_paths() {
    //             args.push(format!("export {LDAP_USER_ENV}=$(cat {user_path})"));
    //             args.push(format!("export {LDAP_PASSWORD_ENV}=$(cat {password_path})"));
    //         }
    //     }
    //     None => (),
    // }

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
pub fn create_key_and_trust_store(
    cert_directory: &str,
    stackable_cert_directory: &str,
    alias_name: &str,
) -> Vec<String> {
    vec![
        format!("echo [{stackable_cert_directory}] Cleaning up truststore - just in case"),
        format!("rm -f {stackable_cert_directory}/truststore.p12"),
        format!("echo [{stackable_cert_directory}] Creating truststore"),
        format!("keytool -importcert -file {cert_directory}/ca.crt -keystore {stackable_cert_directory}/truststore.p12 -storetype pkcs12 -noprompt -alias {alias_name} -storepass {STACKABLE_TLS_STORE_PASSWORD}"),
        format!("echo [{stackable_cert_directory}] Creating certificate chain"),
        format!("cat {cert_directory}/ca.crt {cert_directory}/tls.crt > {stackable_cert_directory}/chain.crt"),
        format!("echo [{stackable_cert_directory}] Creating keystore"),
        format!("openssl pkcs12 -export -in {stackable_cert_directory}/chain.crt -inkey {cert_directory}/tls.key -out {stackable_cert_directory}/keystore.p12 --passout pass:{STACKABLE_TLS_STORE_PASSWORD}")
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
