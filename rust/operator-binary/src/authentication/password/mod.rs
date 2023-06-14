pub mod file;
pub mod ldap;

use crate::authentication::{
    password::{file::FileAuthenticator, ldap::LdapAuthenticator},
    TrinoAuthenticationConfig,
};

use snafu::{ResultExt, Snafu};
use stackable_operator::{commons::product_image_selection::ResolvedProductImage, product_config};
use stackable_trino_crd::{Container, TrinoRole, RW_CONFIG_DIR_NAME};
use std::collections::BTreeMap;
use tracing::debug;

// Trino properties
const PASSWORD_AUTHENTICATOR_CONFIG_FILES: &str = "password-authenticator.config-files";
const PASSWORD_AUTHENTICATOR_NAME: &str = "password-authenticator.name";
// file handling
const CONFIG_FILE_NAME_SUFFIX: &str = ".properties";

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("Failed to configure LDAP password authentication"))]
    InvalidLdapAuthenticationConfiguration { source: ldap::Error },
    #[snafu(display("Failed to write password authentication config file"))]
    FailedToWritePasswordAuthenticationFile {
        source: product_config::writer::PropertiesWriterError,
    },
}

#[derive(Clone, Debug, Default)]
pub struct TrinoPasswordAuthentication {
    authenticators: Vec<TrinoPasswordAuthenticator>,
}

#[derive(Clone, Debug)]
pub enum TrinoPasswordAuthenticator {
    File(FileAuthenticator),
    Ldap(LdapAuthenticator),
}

impl TrinoPasswordAuthentication {
    pub fn new(authenticators: Vec<TrinoPasswordAuthenticator>) -> Self {
        Self { authenticators }
    }

    pub fn password_authentication_config(
        &self,
        resolved_product_image: &ResolvedProductImage,
    ) -> Result<TrinoAuthenticationConfig, Error> {
        let mut password_authentication_config = TrinoAuthenticationConfig::default();
        // Represents password-authenticator.config-files property
        // password-authenticator.config-files=/stackable/.../file-authenticator.properties,/stackable/.../ldap.properties,...
        let mut password_authenticator_config_file_names = vec![];
        // if we have to build the file auth side car container
        let mut has_file_authenticator = false;
        // we need to collect the mounts for the side car to add them later
        // password file empty dir mount for file updater
        let mut pw_file_update_container_volume_mounts =
            vec![FileAuthenticator::password_db_volume_mount()];

        for authenticator in &self.authenticators {
            match authenticator {
                TrinoPasswordAuthenticator::File(file_authenticator) => {
                    has_file_authenticator = true;
                    let config_file_name = file_authenticator.config_file_name();
                    // config file name to trino config properties (see end of method)
                    password_authenticator_config_file_names
                        .push(format!("{RW_CONFIG_DIR_NAME}/{config_file_name}"));

                    // authenticator property file
                    password_authentication_config.add_config_file(
                        TrinoRole::Coordinator,
                        config_file_name,
                        product_config::writer::to_java_properties_string(
                            file_authenticator
                                .config_file_data()
                                .into_iter()
                                .map(|(k, v)| (k, Some(v)))
                                .collect::<BTreeMap<String, Option<String>>>()
                                .iter(),
                        )
                        .context(FailedToWritePasswordAuthenticationFileSnafu)?,
                    );
                    // required volumes
                    password_authentication_config.add_volume(file_authenticator.secret_volume());
                    password_authentication_config
                        .add_volume(FileAuthenticator::password_db_volume());

                    // required volume mounts
                    // secret mount for pw file updater
                    pw_file_update_container_volume_mounts
                        .push(file_authenticator.secret_volume_mount());

                    // password file empty dir mount for trino container
                    password_authentication_config.add_volume_mount(
                        TrinoRole::Coordinator,
                        Container::Trino,
                        FileAuthenticator::password_db_volume_mount(),
                    );
                }
                TrinoPasswordAuthenticator::Ldap(ldap_authenticator) => {
                    let config_file_name = ldap_authenticator.config_file_name();
                    // config file name to trino config properties (see end of method)
                    password_authenticator_config_file_names
                        .push(format!("{RW_CONFIG_DIR_NAME}/{config_file_name}",));

                    // authenticator property file
                    password_authentication_config.add_config_file(
                        TrinoRole::Coordinator,
                        config_file_name,
                        product_config::writer::to_java_properties_string(
                            ldap_authenticator
                                .config_file_data()
                                .context(InvalidLdapAuthenticationConfigurationSnafu)?
                                .into_iter()
                                .map(|(k, v)| (k, Some(v)))
                                .collect::<BTreeMap<String, Option<String>>>()
                                .iter(),
                        )
                        .context(FailedToWritePasswordAuthenticationFileSnafu)?,
                    );

                    // extra commands
                    password_authentication_config.add_commands(
                        TrinoRole::Coordinator,
                        stackable_trino_crd::Container::Trino,
                        ldap_authenticator.commands(),
                    );

                    let (volumes, volume_mounts) = ldap_authenticator.volumes_and_mounts();
                    // required volumes
                    for volume in volumes {
                        password_authentication_config.add_volume(volume)
                    }

                    // required volume mounts
                    for volume_mount in volume_mounts {
                        password_authentication_config.add_volume_mount(
                            TrinoRole::Coordinator,
                            stackable_trino_crd::Container::Trino,
                            volume_mount.clone(),
                        );
                        password_authentication_config.add_volume_mount(
                            TrinoRole::Coordinator,
                            stackable_trino_crd::Container::Prepare,
                            volume_mount.clone(),
                        );
                    }
                }
            }
        }

        // add file authentication password db update container if required
        if has_file_authenticator {
            password_authentication_config.add_sidecar_container(
                TrinoRole::Coordinator,
                file::build_password_file_update_container(
                    resolved_product_image,
                    pw_file_update_container_volume_mounts,
                ),
            );
        }

        password_authentication_config.add_config_property(
            TrinoRole::Coordinator,
            PASSWORD_AUTHENTICATOR_CONFIG_FILES.to_string(),
            password_authenticator_config_file_names.join(","),
        );

        debug!(
            "Final Password authentication config: {:?}",
            password_authentication_config
        );

        Ok(password_authentication_config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stackable_operator::commons::authentication::{
        static_::UserCredentialsSecretRef, LdapAuthenticationProvider, StaticAuthenticationProvider,
    };

    const FILE_AUTH_CLASS_1: &str = "file-auth-1";
    const FILE_AUTH_CLASS_2: &str = "file-auth-2";
    const LDAP_AUTH_CLASS_1: &str = "ldap-auth-1";
    const LDAP_AUTH_CLASS_2: &str = "ldap-auth-2";

    fn ldap_provider() -> LdapAuthenticationProvider {
        LdapAuthenticationProvider {
            hostname: "".to_string(),
            port: None,
            search_base: "".to_string(),
            search_filter: "".to_string(),
            ldap_field_names: Default::default(),
            bind_credentials: None,
            tls: None,
        }
    }

    fn setup() -> TrinoAuthenticationConfig {
        let mut authenticators = vec![];

        authenticators.push(TrinoPasswordAuthenticator::File(FileAuthenticator::new(
            FILE_AUTH_CLASS_1.to_string(),
            StaticAuthenticationProvider {
                user_credentials_secret: UserCredentialsSecretRef {
                    name: FILE_AUTH_CLASS_1.to_string(),
                },
            },
        )));

        authenticators.push(TrinoPasswordAuthenticator::File(FileAuthenticator::new(
            FILE_AUTH_CLASS_2.to_string(),
            StaticAuthenticationProvider {
                user_credentials_secret: UserCredentialsSecretRef {
                    name: FILE_AUTH_CLASS_2.to_string(),
                },
            },
        )));

        authenticators.push(TrinoPasswordAuthenticator::Ldap(LdapAuthenticator::new(
            LDAP_AUTH_CLASS_1.to_string(),
            ldap_provider(),
        )));

        authenticators.push(TrinoPasswordAuthenticator::Ldap(LdapAuthenticator::new(
            LDAP_AUTH_CLASS_2.to_string(),
            ldap_provider(),
        )));

        TrinoPasswordAuthentication::new(authenticators)
            .password_authentication_config(&ResolvedProductImage {
                product_version: "".to_string(),
                app_version_label: "".to_string(),
                image: "".to_string(),
                image_pull_policy: "".to_string(),
                pull_secrets: None,
            })
            .unwrap()
    }

    #[test]
    fn test_password_authentication_config_properties() {
        let auth_config = setup();

        assert_eq!(
            auth_config
                .config_properties(&TrinoRole::Coordinator)
                .get(PASSWORD_AUTHENTICATOR_CONFIG_FILES),
            Some(format!(
                "{RW_CONFIG_DIR_NAME}/{FILE_AUTH_CLASS_1}-password-file-auth{CONFIG_FILE_NAME_SUFFIX},\
                 {RW_CONFIG_DIR_NAME}/{FILE_AUTH_CLASS_2}-password-file-auth{CONFIG_FILE_NAME_SUFFIX},\
                 {RW_CONFIG_DIR_NAME}/{LDAP_AUTH_CLASS_1}-password-ldap-auth{CONFIG_FILE_NAME_SUFFIX},\
                 {RW_CONFIG_DIR_NAME}/{LDAP_AUTH_CLASS_2}-password-ldap-auth{CONFIG_FILE_NAME_SUFFIX}",
            ))
            .as_ref()
        );
    }

    #[test]
    fn test_password_authentication_config_files() {
        let auth_config = setup();
        let config_files = auth_config.config_files(&TrinoRole::Coordinator);

        // We expect 4 config files (2 for file-authenticator, 2 for ldap-authenticator)
        assert_eq!(config_files.len(), 4);
        // First element should be the file authentication
        assert_eq!(
            config_files
                .get(&format!(
                    "{FILE_AUTH_CLASS_1}-password-file-auth{CONFIG_FILE_NAME_SUFFIX}"
                ))
                .unwrap(),
            &FileAuthenticator::new(
                FILE_AUTH_CLASS_1.to_string(),
                StaticAuthenticationProvider {
                    user_credentials_secret: UserCredentialsSecretRef {
                        name: "".to_string()
                    }
                }
            )
            .config_file_name()
        );
        // Second element should be ldap authentication
        assert_eq!(
            config_files
                .get(&format!(
                    "{FILE_AUTH_CLASS_1}-password-file-auth{CONFIG_FILE_NAME_SUFFIX}"
                ))
                .unwrap(),
            &format!("{FILE_AUTH_CLASS_2}-password-ldap-auth{CONFIG_FILE_NAME_SUFFIX}")
        );
        // Third element should be ldap authentication
        assert_eq!(
            config_files
                .get(&format!(
                    "{LDAP_AUTH_CLASS_1}-password-ldap-auth{CONFIG_FILE_NAME_SUFFIX}"
                ))
                .unwrap(),
            &format!("{FILE_AUTH_CLASS_2}-password-ldap-auth{CONFIG_FILE_NAME_SUFFIX}")
        );
    }
}
