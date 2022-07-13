use stackable_operator::commons::s3::S3ConnectionSpec;
use stackable_trino_crd::authentication::TrinoAuthenticationConfig;
use stackable_trino_crd::{
    TrinoCluster, CONFIG_DIR_NAME, DATA_DIR_NAME, ENV_S3_ACCESS_KEY, ENV_S3_SECRET_KEY,
    ENV_TLS_STORE_SECRET, HIVE_PROPERTIES, PASSWORD_DB, RW_CONFIG_DIR_NAME, S3_SECRET_DIR_NAME,
    SECRET_KEY_S3_ACCESS_KEY, SECRET_KEY_S3_SECRET_KEY, TLS_INTERNAL_CLIENT_DIR,
    TLS_INTERNAL_SHARED_SECRET_DIR, USER_PASSWORD_DATA_DIR_NAME,
};

pub fn container_prepare_args(trino: &TrinoCluster) -> Vec<String> {
    let mut args = vec![];

    // if authentication is enabled we have to create client and internal tls stores
    if trino.get_authentication().is_some() {
        // generate passwords for client and internal stores
        args.extend(generate_password_and_export(
            TLS_INTERNAL_CLIENT_DIR,
            ENV_TLS_STORE_SECRET,
        ));
        args.extend(generate_password_and_export(
            TLS_INTERNAL_SHARED_SECRET_DIR,
            ENV_TLS_STORE_SECRET,
        ));

        // create client and internal truststores
        args.extend(create_key_and_trust_store_cmd(
            TLS_INTERNAL_CLIENT_DIR,
            ENV_TLS_STORE_SECRET,
        ));
        args.extend(create_key_and_trust_store_cmd(
            TLS_INTERNAL_SHARED_SECRET_DIR,
            ENV_TLS_STORE_SECRET,
        ));
        // chown and chmod client, internal and user password data dirs
        args.extend(chown_and_chmod(TLS_INTERNAL_CLIENT_DIR));
        args.extend(chown_and_chmod(TLS_INTERNAL_SHARED_SECRET_DIR));
        args.extend(chown_and_chmod(USER_PASSWORD_DATA_DIR_NAME));
    } else {
        // client tls store
        if trino.get_client_tls().is_some() {
            args.extend(generate_password_and_export(
                TLS_INTERNAL_CLIENT_DIR,
                ENV_TLS_STORE_SECRET,
            ));
            args.extend(create_key_and_trust_store_cmd(
                TLS_INTERNAL_CLIENT_DIR,
                ENV_TLS_STORE_SECRET,
            ));
            args.extend(chown_and_chmod(TLS_INTERNAL_CLIENT_DIR));
        }
        // internal tls store
        if trino.get_internal_tls().is_some() {
            args.extend(generate_password_and_export(
                TLS_INTERNAL_SHARED_SECRET_DIR,
                ENV_TLS_STORE_SECRET,
            ));
            args.extend(create_key_and_trust_store_cmd(
                TLS_INTERNAL_SHARED_SECRET_DIR,
                ENV_TLS_STORE_SECRET,
            ));
            args.extend(chown_and_chmod(TLS_INTERNAL_SHARED_SECRET_DIR));
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
        args.extend(vec![
            format!(
                "echo Writing user data to {path}/{db}",
                path = USER_PASSWORD_DATA_DIR_NAME,
                db = PASSWORD_DB
            ),
            format!(
                "echo '{data}' > {path}/{db} ",
                data = user_data,
                path = USER_PASSWORD_DATA_DIR_NAME,
                db = PASSWORD_DB
            ),
        ]);
        // remove passwords from internal and client tls
        args.extend(export_and_remove_password_file(
            TLS_INTERNAL_CLIENT_DIR,
            ENV_TLS_STORE_SECRET,
        ));
        args.extend(export_and_remove_password_file(
            TLS_INTERNAL_SHARED_SECRET_DIR,
            ENV_TLS_STORE_SECRET,
        ));
    } else {
        if trino.get_client_tls().is_some() {
            args.extend(export_and_remove_password_file(
                TLS_INTERNAL_CLIENT_DIR,
                ENV_TLS_STORE_SECRET,
            ));
        }
        if trino.get_internal_tls().is_some() {
            args.extend(export_and_remove_password_file(
                TLS_INTERNAL_SHARED_SECRET_DIR,
                ENV_TLS_STORE_SECRET,
            ));
        }
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
fn create_key_and_trust_store_cmd(directory: &str, password_secret_name: &str) -> Vec<String> {
    vec![
        format!("echo [{dir}] Creating truststore", dir = directory),
        format!("keytool -importcert -file {dir}/ca.crt -keystore {dir}/truststore.p12 -storetype pkcs12 -noprompt -alias ca_cert -storepass ${secret}",
                dir = directory, secret = password_secret_name),
        format!("echo [{dir}] Creating certificate chain", dir = directory),
        format!("cat {dir}/ca.crt {dir}/tls.crt > {dir}/chain.crt", dir = directory),
        format!("echo [{dir}] Creating keystore", dir = directory),
        format!("openssl pkcs12 -export -in {dir}/chain.crt -inkey {dir}/tls.key -out {dir}/keystore.p12 --passout pass:${secret}",
                dir = directory, secret = password_secret_name),
    ]
}

/// Generates the shell script to write a random 20 character password to a file in the directory
/// `directory` with name `file_name`.
fn generate_password_and_export(directory: &str, file_name: &str) -> Vec<String> {
    vec![
        format!(
            //        "export {secret}=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 20 ; echo '')",
            "echo $(tr -dc A-Za-z0-9 </dev/urandom | head -c 20 ; echo '') >> {dir}/{name}",
            dir = directory,
            name = file_name
        ),
        export_var_from_file(directory, file_name),
    ]
}

fn export_var_from_file(directory: &str, file_name: &str) -> String {
    format!(
        "export {env_var}=$(cat {dir}/{name})",
        env_var = file_name,
        dir = directory,
        name = file_name
    )
}

fn export_and_remove_password_file(directory: &str, file_name: &str) -> Vec<String> {
    vec![
        format!(
            "export {env_var}=$(cat {dir}/{name})",
            env_var = file_name,
            dir = directory,
            name = file_name
        ),
        remove_file(directory, file_name),
    ]
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
