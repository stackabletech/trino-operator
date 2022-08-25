use stackable_trino_crd::{
    authentication::TrinoAuthenticationConfig, TrinoCluster, CONFIG_DIR_NAME, DATA_DIR_NAME,
    PASSWORD_DB, RW_CONFIG_DIR_NAME, STACKABLE_CLIENT_TLS_DIR, STACKABLE_INTERNAL_TLS_DIR,
    STACKABLE_MOUNT_INTERNAL_TLS_DIR, STACKABLE_MOUNT_SERVER_TLS_DIR, STACKABLE_SERVER_TLS_DIR,
    STACKABLE_TLS_STORE_PASSWORD, SYSTEM_TRUST_STORE, SYSTEM_TRUST_STORE_PASSWORD,
    USER_PASSWORD_DATA_DIR_NAME,
};

use crate::catalog::CatalogConfig;

pub const STACKABLE_CLIENT_CA_CERT: &str = "stackable-client-ca-cert";
pub const STACKABLE_SERVER_CA_CERT: &str = "stackable-server-ca-cert";
pub const STACKABLE_INTERNAL_CA_CERT: &str = "stackable-internal-ca-cert";

pub fn container_prepare_args(trino: &TrinoCluster, catalogs: &[CatalogConfig]) -> Vec<String> {
    let mut args = vec![];

    // User password data
    if trino.tls_enabled() {
        args.extend(create_key_and_trust_store(
            STACKABLE_MOUNT_SERVER_TLS_DIR,
            STACKABLE_SERVER_TLS_DIR,
            STACKABLE_SERVER_CA_CERT,
        ));
    }
    if trino.get_authentication().is_some() {
        args.extend(chown_and_chmod(USER_PASSWORD_DATA_DIR_NAME));
    }

    // Chown and mod the certificates dir (this will always be created even if no TLS is required)
    args.extend(chown_and_chmod(STACKABLE_SERVER_TLS_DIR));

    if trino.get_internal_tls().is_some() {
        args.extend(create_key_and_trust_store(
            STACKABLE_MOUNT_INTERNAL_TLS_DIR,
            STACKABLE_INTERNAL_TLS_DIR,
            STACKABLE_INTERNAL_CA_CERT,
        ));
        args.extend(chown_and_chmod(STACKABLE_INTERNAL_TLS_DIR));
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
    args.extend(chown_and_chmod(STACKABLE_CLIENT_TLS_DIR));

    // Add the commands that are needed to set up the catalogs
    catalogs.iter().for_each(|catalog| {
        args.extend_from_slice(&catalog.init_container_extra_start_commands);
    });

    args.extend(chown_and_chmod(RW_CONFIG_DIR_NAME));
    args.extend(chown_and_chmod(DATA_DIR_NAME));

    vec![args.join(" && ")]
}

pub fn container_trino_args(
    user_authentication: Option<&TrinoAuthenticationConfig>,
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

    if let Some(auth) = user_authentication {
        let user_data = auth.to_trino_user_data();
        args.push(format!(
            "echo '{data}' > {path}/{db}",
            data = user_data,
            path = USER_PASSWORD_DATA_DIR_NAME,
            db = PASSWORD_DB
        ));
    }

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

/// Generates a shell script to chown and chmod the provided directory.
fn chown_and_chmod(directory: &str) -> Vec<String> {
    vec![
        format!("echo chown and chmod {dir}", dir = directory),
        format!("chown -R stackable:stackable {dir}", dir = directory),
        format!("chmod -R a=,u=rwX {dir}", dir = directory),
    ]
}
