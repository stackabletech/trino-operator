use std::fmt::Display;

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
        TrinoRole, v1alpha1,
    },
};

pub fn container_prepare_args(
    trino: &v1alpha1::TrinoCluster,
    catalogs: &[CatalogConfig],
    merged_config: &v1alpha1::TrinoConfig,
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
    args.push(format!("openssl pkcs12 -export -nokeys -in /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem -password pass:{STACKABLE_TLS_STORE_PASSWORD} -out {STACKABLE_CLIENT_TLS_DIR}/truststore.p12"));
    // args.extend(import_system_truststore(STACKABLE_CLIENT_TLS_DIR));

    if trino.tls_enabled() {
        args.push(format!("cp {STACKABLE_MOUNT_SERVER_TLS_DIR}/truststore.p12 {STACKABLE_SERVER_TLS_DIR}/truststore.p12"));
        args.push(format!("cp {STACKABLE_MOUNT_SERVER_TLS_DIR}/keystore.p12 {STACKABLE_SERVER_TLS_DIR}/keystore.p12"));
        // args.extend(import_truststore(
        //     STACKABLE_MOUNT_SERVER_TLS_DIR,
        //     STACKABLE_SERVER_TLS_DIR,
        // ));
        // args.extend(import_keystore(
        //     STACKABLE_MOUNT_SERVER_TLS_DIR,
        //     STACKABLE_SERVER_TLS_DIR,
        // ));
    }

    if trino.get_internal_tls().is_some() {
        args.push(format!("cp {STACKABLE_MOUNT_INTERNAL_TLS_DIR}/truststore.p12 {STACKABLE_INTERNAL_TLS_DIR}/truststore.p12"));
        args.push(format!("cp {STACKABLE_MOUNT_INTERNAL_TLS_DIR}/keystore.p12 {STACKABLE_INTERNAL_TLS_DIR}/keystore.p12"));

        // args.extend(import_truststore(
        //     STACKABLE_MOUNT_INTERNAL_TLS_DIR,
        //     STACKABLE_INTERNAL_TLS_DIR,
        // ));
        // args.extend(import_keystore(
        //     STACKABLE_MOUNT_INTERNAL_TLS_DIR,
        //     STACKABLE_INTERNAL_TLS_DIR,
        // ));

        if trino.tls_enabled() {
            args.extend(import_pkcs12_into_another_pkcs12_commands(
                format!("{STACKABLE_MOUNT_SERVER_TLS_DIR}/truststore.p12"),
                format!("{STACKABLE_INTERNAL_TLS_DIR}/truststore.p12"),
            ));
            // args.extend(import_truststore(
            //     STACKABLE_MOUNT_SERVER_TLS_DIR,
            //     STACKABLE_INTERNAL_TLS_DIR,
            // ))
        }
    }

    // Add the commands that are needed to set up the catalogs
    catalogs.iter().for_each(|catalog| {
        args.extend_from_slice(&catalog.init_container_extra_start_commands);
    });

    if trino.get_internal_tls().is_some() {
        args.extend(javafy_pkcs12_truststore_commands(format!(
            "{STACKABLE_INTERNAL_TLS_DIR}/truststore.p12"
        )));
    }
    args.extend(javafy_pkcs12_truststore_commands(format!(
        "{STACKABLE_CLIENT_TLS_DIR}/truststore.p12"
    )));

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
    // Don't print secret contents!
    args.push("set +x".to_string());
    catalogs.iter().for_each(|catalog| {
        for (env_name, file) in &catalog.load_env_from_files {
            args.push(format!("export {env_name}=\"$(cat {file})\""));
        }
    });
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

/// Adds a CA file from `cert_file` into a truststore named `truststore.p12` in `destination_directory`
/// under the alias `alias_name`.
pub fn add_cert_to_truststore(
    cert_file: &str,
    destination_directory: &str,
    alias_name: &str,
) -> Vec<String> {
    vec![
        format!(
            "echo Adding cert from {cert_file} to truststore {destination_directory}/truststore.p12"
        ),
        format!(
            "keytool -importcert -file {cert_file} -keystore {destination_directory}/truststore.p12 -storetype pkcs12 -noprompt -alias {alias_name} -storepass {STACKABLE_TLS_STORE_PASSWORD}"
        ),
    ]
}

fn import_pkcs12_into_another_pkcs12_commands(src: impl Display, dst: impl Display) -> Vec<String> {
    vec![
        "temp_dir=$(mktemp -d)".to_owned(),
        format!("echo Importing {src} into {dst}"),
        format!(
            "openssl pkcs12 -in {src} -out ${{temp_dir}}/ca-certs1.pem -password pass:{STACKABLE_TLS_STORE_PASSWORD} -legacy"
        ),
        format!(
            "openssl pkcs12 -in {dst} -out ${{temp_dir}}/ca-certs2.pem -password pass:{STACKABLE_TLS_STORE_PASSWORD} -legacy"
        ),
        "cat ${temp_dir}/ca-certs1.pem ${temp_dir}/ca-certs2.pem > ${temp_dir}/ca-certs.pem"
            .to_owned(),
        format!(
            "openssl pkcs12 -export -nokeys -in ${{temp_dir}}/ca-certs.pem -password pass:{STACKABLE_TLS_STORE_PASSWORD} -out {dst}"
        ),
    ]
}

// openssl pkcs12 -in src.p12 -nokeys -password pass:changeit -out /tmp/tmp-certs.pem -legacy && \
// csplit -z /tmp/tmp-certs.pem '/-----BEGIN CERTIFICATE-----/' '{*}' && \
// i=1 && \
// > /tmp/named-certs.pem && \
// for f in xx*; do \
//   echo -e "Bag Attributes\n    friendlyName: $i" >> /tmp/named-certs.pem && cat "$f" >> /tmp/named-certs.pem && ((i++)); \
// done && \
// openssl pkcs12 -export -nokeys -in /tmp/named-certs.pem -out dst.p12 -password pass:changeit

fn javafy_pkcs12_truststore_commands(truststore: impl Display) -> Vec<String> {
    vec![
        format!("keytool -list -storepass changeit -keystore {truststore}"), // DEBUG
        "temp_dir=$(mktemp -d)".to_owned(),
        "cd ${temp_dir}".to_owned(),
        format!(
            "openssl pkcs12 -in {truststore} -nokeys -out ca-certs.pem -legacy -password pass:{STACKABLE_TLS_STORE_PASSWORD}"
        ),
        // "csplit -z ca-certs.pem '/-----BEGIN CERTIFICATE-----/' '{*}'".to_owned(),
        // "csplit -z ca-certs.pem '/Bag Attributes: .*/' '{*}'".to_owned(),
        "csplit -sz -f cert- -b '%04d.pem' ca-certs.pem '/^-----END CERTIFICATE-----$/+1' '{*}'"
            .to_owned(),
        "i=1".to_owned(),
        "for file in cert-*.pem; do".to_owned(),
        // "  echo -e \"Bag Attributes\\n    friendlyName: $i\" >> named-certs.pem && cat $file >> named-certs.pem".to_owned(),
        "  sed 's/^Bag Attributes: <No Attributes>$/Bag Attributes\\n    friendlyName: '$i'/' $file >> named-certs.pem"
            .to_owned(),
        "  ((i++))".to_owned(),
        "done".to_owned(),
        "cat ca-certs.pem".to_owned(),    // DEBUG
        "cat named-certs.pem".to_owned(), // DEBUG
        format!(
            "openssl pkcs12 -export -nokeys -in named-certs.pem -out {truststore} -password pass:{STACKABLE_TLS_STORE_PASSWORD}"
        ),
        "ls -la ${temp_dir}".to_owned(), // DEBUG
        format!("keytool -list -storepass changeit -keystore {truststore}"), // DEBUG
    ]
}

// /// Generates the shell script to import a secret operator provided keystore without password
// /// into a new keystore with password in a writeable empty dir
// ///
// /// # Arguments
// /// - `source_directory`: The directory of the source keystore. Should usually be a secret operator volume mount.
// /// - `destination_directory`: The directory of the destination keystore. Should usually be an empty dir.
// fn import_keystore(source_directory: &str, destination_directory: &str) -> Vec<String> {
//     vec![
//         // The source directory is a secret-op mount and we do not want to write / add anything in there
//         // Therefore we import all the contents to a keystore in "writeable" empty dirs.
//         // Keytool is only barking if a password is not set for the destination keystore (which we set)
//         // and do provide an empty password for the source keystore coming from the secret-operator.
//         // Using no password will result in a warning.
//         format!(
//             "echo Importing {source_directory}/keystore.p12 to {destination_directory}/keystore.p12"
//         ),
//         format!(
//             "keytool -importkeystore -srckeystore {source_directory}/keystore.p12 -srcstoretype PKCS12 -srcstorepass \"\" -destkeystore {destination_directory}/keystore.p12 -deststoretype PKCS12 -deststorepass {STACKABLE_TLS_STORE_PASSWORD} -noprompt"
//         ),
//     ]
// }

// /// Generates the shell script to import a secret operator provided truststore without password
// /// into a new truststore with password in a writeable empty dir
// ///
// /// # Arguments
// /// - `source_directory`: The directory of the source truststore. Should usually be a secret operator volume mount.
// /// - `destination_directory`: The directory of the destination truststore. Should usually be an empty dir.
// fn import_truststore(source_directory: &str, destination_directory: &str) -> Vec<String> {
//     vec![
//         // The source directory is a secret-op mount and we do not want to write / add anything in there
//         // Therefore we import all the contents to a truststore in "writeable" empty dirs.
//         // Keytool is only barking if a password is not set for the destination truststore (which we set)
//         // and do provide an empty password for the source truststore coming from the secret-operator.
//         // Using no password will result in a warning.
//         // All secret-op generated truststores have one entry with alias "1". We generate a UUID for
//         // the destination truststore to avoid conflicts when importing multiple secret-op generated
//         // truststores. We do not use the UUID rust crate since this will continuously change the STS... and
//         // leads to never-ending reconciles.
//         format!(
//             "echo Importing {source_directory}/truststore.p12 to {destination_directory}/truststore.p12"
//         ),
//         format!(
//             "keytool -importkeystore -srckeystore {source_directory}/truststore.p12 -srcstoretype PKCS12 -srcstorepass \"\" -srcalias 1 -destkeystore {destination_directory}/truststore.p12 -deststoretype PKCS12 -deststorepass {STACKABLE_TLS_STORE_PASSWORD} -destalias $(cat /proc/sys/kernel/random/uuid) -noprompt"
//         ),
//     ]
// }

// /// Import the system truststore to a truststore named `truststore.p12` in `destination_directory`.
// fn import_system_truststore(destination_directory: &str) -> Vec<String> {
//     vec![
//         format!("echo Importing {SYSTEM_TRUST_STORE} to {destination_directory}/truststore.p12"),
//         format!(
//             "keytool -importkeystore -srckeystore {SYSTEM_TRUST_STORE} -srcstoretype jks -srcstorepass {SYSTEM_TRUST_STORE_PASSWORD} -destkeystore {destination_directory}/truststore.p12 -deststoretype pkcs12 -deststorepass {STACKABLE_TLS_STORE_PASSWORD} -noprompt"
//         ),
//     ]
// }

// pub mod operator_rs {
//     fn ubi9_system_truststore_as_pkcs12_command() -> Vec<String> {
//         system_truststore_as_pkcs12_command("/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem")
//     }

//     fn system_truststore_as_pkcs12_command(destination_truststore: &str) -> Vec<String> {
//         format!("echo Importing system trust {SYSTEM_TRUST_STORE} to {destination_directory}/truststore.p12"),
//     }
// }
