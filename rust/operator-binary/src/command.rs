use stackable_operator::commons::s3::S3ConnectionSpec;
use stackable_operator::commons::tls::{CaCert, TlsVerification};
use stackable_trino_crd::authentication::TrinoAuthenticationConfig;
use stackable_trino_crd::{
    TrinoCluster, CONFIG_DIR_NAME, DATA_DIR_NAME, ENV_S3_ACCESS_KEY, ENV_S3_SECRET_KEY,
    ENV_TLS_STORE_SECRET, HIVE_PROPERTIES, PASSWORD_DB, RW_CONFIG_DIR_NAME, S3_SECRET_DIR_NAME,
    SECRET_KEY_S3_ACCESS_KEY, SECRET_KEY_S3_SECRET_KEY, TLS_CERTS_DIR, USER_PASSWORD_DATA_DIR_NAME,
};

pub fn container_prepare_args(
    trino: &TrinoCluster,
    s3_spec: Option<&S3ConnectionSpec>,
) -> Vec<String> {
    let mut args = vec![];
    let mut additional_cas = vec![];

    if let Some(S3ConnectionSpec { tls: Some(tls), .. }) = s3_spec {
        if let TlsVerification::Server(server_verification) = &tls.verification {
            match &server_verification.ca_cert {
                CaCert::WebPki {} => {}
                CaCert::SecretClass(secret_class) => {
                    let certs_directory = format!("{TLS_CERTS_DIR}/{secret_class}");
                    additional_cas.push(certs_directory);
                }
            }
        }
    }

    if trino.tls_enabled() {
        // generate passwords for client and internal stores
        args.push(generate_password_to_file(
            TLS_CERTS_DIR,
            ENV_TLS_STORE_SECRET,
        ));
        // export to env var for later use (create_key_and_trust_store)
        args.push(export_var_from_file(TLS_CERTS_DIR, ENV_TLS_STORE_SECRET));

        // create TLS keystores
        args.extend(create_key_and_trust_store(
            TLS_CERTS_DIR,
            ENV_TLS_STORE_SECRET,
            &additional_cas,
        ));
        // chown and chmod keystores and user password data dirs
        args.extend(chown_and_chmod(TLS_CERTS_DIR));
        args.extend(chown_and_chmod(USER_PASSWORD_DATA_DIR_NAME));
    }

    if trino.get_authentication().is_some() {
        args.extend(chown_and_chmod(USER_PASSWORD_DATA_DIR_NAME));
    }

    args.extend(chown_and_chmod(RW_CONFIG_DIR_NAME));
    args.extend(chown_and_chmod(DATA_DIR_NAME));

    for cas in &additional_cas {
        args.extend(chown_and_chmod(cas))
    }

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

    if trino.get_tls().is_some() || user_authentication.is_some() {
        // we need to get the keystores password and export it
        args.push(export_var_from_file(TLS_CERTS_DIR, ENV_TLS_STORE_SECRET));
        // and remove
        args.push(remove_file(TLS_CERTS_DIR, ENV_TLS_STORE_SECRET));
    }

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
fn create_key_and_trust_store(
    directory: &str,
    password_secret_name: &str,
    additional_ca: &[String],
) -> Vec<String> {
    let extra_cas = additional_ca
        .iter()
        .map(|directory| format!("{}/ca.crt", directory))
        .collect::<Vec<_>>()
        .join(" ");

    vec![
        format!("echo [{dir}] Creating truststore", dir = directory),
        format!("keytool -importcert -file {dir}/ca.crt -keystore {dir}/truststore.p12 -storetype pkcs12 -noprompt -alias ca_cert -storepass ${secret}",
                dir = directory, secret = password_secret_name),
        format!("echo [{dir}] Creating certificate chain", dir = directory),
        format!("cat {other_cas} {dir}/ca.crt {dir}/tls.crt > {dir}/chain.crt", dir = directory, other_cas = extra_cas),
        //format!("cat {dir}/ca.crt {dir}/tls.crt > {dir}/chain.crt", dir = directory),
        format!("echo [{dir}] Creating keystore", dir = directory),
        format!("openssl pkcs12 -export -in {dir}/chain.crt -inkey {dir}/tls.key -out {dir}/keystore.p12 --passout pass:${secret}",
                dir = directory, secret = password_secret_name),
    ]
}

/// Generates the shell script to write a random 20 character password to a file in the directory
/// `directory` with name `file_name`.
fn generate_password_to_file(directory: &str, file_name: &str) -> String {
    format!(
        "echo $(tr -dc A-Za-z0-9 </dev/urandom | head -c 20 ; echo '') >> {dir}/{name} && cat {dir}/{name}",
        dir = directory,
        name = file_name
    )
}

/// Exports the content of the file in the directory `directory` with the name `file_name` to
/// an env variable with name `file_name`.
fn export_var_from_file(directory: &str, file_name: &str) -> String {
    format!(
        "export {env_var}=$(cat {dir}/{name})",
        env_var = file_name,
        dir = directory,
        name = file_name
    )
}

/// Generates the shell script to remove a file in the `directory` called `file_name`.
fn remove_file(directory: &str, file_name: &str) -> String {
    format!("rm {dir}/{name}", dir = directory, name = file_name)
}

/// Generates a shell script to chown and chmod the provided directory.
fn chown_and_chmod(directory: &str) -> Vec<String> {
    vec![
        format!("echo chown and chmod {dir}", dir = directory),
        format!("chown -R stackable:stackable {dir}", dir = directory),
        format!("chmod -R a=,u=rwX {dir}", dir = directory),
    ]
}
