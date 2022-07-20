use stackable_operator::commons::s3::S3ConnectionSpec;
use stackable_operator::commons::tls::{CaCert, Tls, TlsServerVerification, TlsVerification};
use stackable_trino_crd::authentication::TrinoAuthenticationConfig;
use stackable_trino_crd::{
    TrinoCluster, CONFIG_DIR_NAME, DATA_DIR_NAME, ENV_S3_ACCESS_KEY, ENV_S3_SECRET_KEY,
    HIVE_PROPERTIES, PASSWORD_DB, RW_CONFIG_DIR_NAME, S3_SECRET_DIR_NAME, SECRET_KEY_S3_ACCESS_KEY,
    SECRET_KEY_S3_SECRET_KEY, STACKABLE_INTERNAL_TLS_CERTS_DIR, STACKABLE_TLS_CERTS_DIR,
    STACKABLE_TLS_STORE_PASSWORD, SYSTEM_TRUST_STORE, SYSTEM_TRUST_STORE_PASSWORD,
    USER_PASSWORD_DATA_DIR_NAME,
};

pub fn container_prepare_args(
    trino: &TrinoCluster,
    s3_spec: Option<&S3ConnectionSpec>,
) -> Vec<String> {
    let mut args = vec![
        // Create certificates directory (required if e.g. no authentication or tls is enabled but required for S3 connection)
        format!("mkdir -p {STACKABLE_TLS_CERTS_DIR}"),
        // Copy system truststore to stackable truststore
        format!("keytool -importkeystore -srckeystore {SYSTEM_TRUST_STORE} -srcstoretype jks -srcstorepass {SYSTEM_TRUST_STORE_PASSWORD} -destkeystore {STACKABLE_TLS_CERTS_DIR}/truststore.p12 -deststoretype pkcs12 -deststorepass {STACKABLE_TLS_STORE_PASSWORD} -noprompt"),
    ];

    // Chown and mod the certificates dir (this will always be created even if no tls is required)
    args.extend(chown_and_chmod(STACKABLE_TLS_CERTS_DIR));

    // User password data
    if trino.get_authentication().is_some() {
        args.extend(create_key_and_trust_store(STACKABLE_TLS_CERTS_DIR));
        args.extend(chown_and_chmod(USER_PASSWORD_DATA_DIR_NAME));
    } else if trino.tls_enabled() {
        args.extend(create_key_and_trust_store(STACKABLE_TLS_CERTS_DIR));
    }

    if trino.get_internal_tls().is_some() {
        args.extend(create_key_and_trust_store(STACKABLE_INTERNAL_TLS_CERTS_DIR));
        args.extend(chown_and_chmod(STACKABLE_INTERNAL_TLS_CERTS_DIR));
        // add cert to global truststore
        args.push(format!("keytool -importcert -file {STACKABLE_INTERNAL_TLS_CERTS_DIR}/ca.crt -alias stackable-internal-tls -keystore {STACKABLE_TLS_CERTS_DIR}/truststore.p12 -storepass {STACKABLE_TLS_STORE_PASSWORD} -noprompt"));
    }

    // Load S3 ca to truststore if S3 TLS enabled
    if let Some(s3) = s3_spec {
        if let Some(Tls {
            verification:
                TlsVerification::Server(TlsServerVerification {
                    ca_cert: CaCert::SecretClass(secret_class),
                }),
        }) = &s3.tls
        {
            args.push(format!("keytool -importcert -file {STACKABLE_TLS_CERTS_DIR}/{s3_certs_dir}/ca.crt -alias stackable-{secret_class} -keystore {STACKABLE_TLS_CERTS_DIR}/truststore.p12 -storepass {STACKABLE_TLS_STORE_PASSWORD} -noprompt", s3_certs_dir = secret_class));
        }
    }

    args.extend(chown_and_chmod(RW_CONFIG_DIR_NAME));
    args.extend(chown_and_chmod(DATA_DIR_NAME));

    vec![args.join(" && ")]
}

pub fn container_trino_args(
    trino: &TrinoCluster,
    user_authentication: Option<&TrinoAuthenticationConfig>,
    s3_connection_spec: Option<&S3ConnectionSpec>,
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

    // We need to read the provided s3 credentials from the secret operator / secret class folder
    // and export it to the required env variables in order for trino to pick them up
    // out of the config via e.g. ${ENV:S3_ACCESS_KEY}.
    if let Some(S3ConnectionSpec {
        credentials: Some(_),
        ..
    }) = s3_connection_spec
    {
        args.extend(vec![
            format!(
                "export {env_var}=$(cat {secret_dir}/{file_name})",
                env_var = ENV_S3_ACCESS_KEY,
                secret_dir = S3_SECRET_DIR_NAME,
                file_name = SECRET_KEY_S3_ACCESS_KEY
            ),
            format!(
                "export {env_var}=$(cat {secret_dir}/{file_name})",
                env_var = ENV_S3_SECRET_KEY,
                secret_dir = S3_SECRET_DIR_NAME,
                file_name = SECRET_KEY_S3_SECRET_KEY
            ),
        ]);
    }

    // hive required?
    if trino.spec.hive_config_map_name.is_some() {
        args.extend(vec![
            format!( "echo Writing HIVE connect string \"hive.metastore.uri=${{HIVE}}\" to {rw_conf}/catalog/{hive_properties}",
                     rw_conf = RW_CONFIG_DIR_NAME, hive_properties = HIVE_PROPERTIES
            ),
            format!( "echo \"hive.metastore.uri=${{HIVE}}\" >> {rw_conf}/catalog/{hive_properties}",
                     rw_conf = RW_CONFIG_DIR_NAME, hive_properties = HIVE_PROPERTIES
            )])
    }

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
fn create_key_and_trust_store(directory: &str) -> Vec<String> {
    vec![
        format!("echo [{dir}] Creating truststore", dir = directory),
        format!("keytool -importcert -file {dir}/ca.crt -keystore {dir}/truststore.p12 -storetype pkcs12 -noprompt -alias stackable_ca_cert -storepass {password}",
                dir = directory, password = STACKABLE_TLS_STORE_PASSWORD),
        format!("echo [{dir}] Creating certificate chain", dir = directory),
        format!("cat {dir}/ca.crt {dir}/tls.crt > {dir}/chain.crt", dir = directory),
        format!("echo [{dir}] Creating keystore", dir = directory),
        format!("openssl pkcs12 -export -in {dir}/chain.crt -inkey {dir}/tls.key -out {dir}/keystore.p12 --passout pass:{password}",
                dir = directory, password = STACKABLE_TLS_STORE_PASSWORD),
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
