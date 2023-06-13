pub mod file;
pub mod ldap;

use crate::authentication::{
    password::{file::FileAuthenticator, ldap::LdapAuthenticator},
    TrinoAuthenticationConfig,
};

use snafu::{ResultExt, Snafu};
use stackable_operator::builder::ContainerBuilder;
use stackable_operator::{
    builder::{VolumeBuilder, VolumeMountBuilder},
    k8s_openapi::api::core::v1::{Volume, VolumeMount},
    product_config,
};
use stackable_trino_crd::TrinoRole::Coordinator;
use stackable_trino_crd::{Container, TrinoRole, RW_CONFIG_DIR_NAME};
use std::collections::{BTreeMap, HashMap};
use tracing::debug;

// Trino properties
const PASSWORD_AUTHENTICATOR_CONFIG_FILES: &str = "password-authenticator.config-files";
const PASSWORD_AUTHENTICATOR_NAME: &str = "password-authenticator.name";
// file handling
const CONFIG_FILE_NAME_SUFFIX: &str = ".properties";
const USER_PASSWORD_DB_MOUNT_NAME: &str = "file-auth-users";

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

impl TrinoPasswordAuthenticator {
    pub fn config_file_name(&self) -> String {
        match &self {
            TrinoPasswordAuthenticator::File(file_authenticator) => {
                file_authenticator.config_file_name()
            }
            TrinoPasswordAuthenticator::Ldap(ldap_authenticator) => {
                ldap_authenticator.config_file_name()
            }
        }
    }
}

impl TrinoPasswordAuthentication {
    pub fn new(authenticators: Vec<TrinoPasswordAuthenticator>) -> Self {
        Self { authenticators }
    }
}

impl TrinoPasswordAuthentication {
    pub fn password_authentication_config(&self) -> Result<TrinoAuthenticationConfig, Error> {
        let mut password_authentication_config = TrinoAuthenticationConfig::default();
        // Represents password-authenticator.config-files property
        // password-authenticator.config-files=/stackable/.../file-authenticator.properties,/stackable/.../ldap.properties,...
        let mut password_authenticator_config_file_names = vec![];

        for authenticator in &self.authenticators {
            match authenticator {
                TrinoPasswordAuthenticator::File(file_authenticator) => {
                    let config_file_name = file_authenticator.config_file_name();
                    // config file name to trino config properties (see end of method)
                    password_authenticator_config_file_names
                        .push(format!("{RW_CONFIG_DIR_NAME}/{config_file_name}",));

                    // authenticator property file
                    password_authentication_config.add_config_file(
                        TrinoRole::Coordinator,
                        config_file_name,
                        product_config::writer::to_java_properties_string(
                            file_authenticator
                                .config_file_data()
                                .into_iter()
                                .map(|(k, v)| (k, Some(v)))
                                .collect::<HashMap<String, Option<String>>>()
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
                    password_authentication_config.add_volume_mount(
                        TrinoRole::Coordinator,
                        Container::PasswordFileUpdater,
                        file_authenticator.secret_volume_mount(),
                    );
                    let password_db_volume_mount = FileAuthenticator::password_db_volume_mount();
                    // password file empty dir mount for file updater
                    password_authentication_config.add_volume_mount(
                        TrinoRole::Coordinator,
                        Container::PasswordFileUpdater,
                        password_db_volume_mount.clone(),
                    );
                    // password file empty dir mount for trino container
                    password_authentication_config.add_volume_mount(
                        TrinoRole::Coordinator,
                        Container::Trino,
                        password_db_volume_mount,
                    );

                    // required containers
                    password_authentication_config.add_sidecar_container(
                        TrinoRole::Coordinator,
                        FileAuthenticator::file_update_container(),
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
                                .collect::<HashMap<String, Option<String>>>()
                                .iter(),
                        )
                        .context(FailedToWritePasswordAuthenticationFileSnafu)?,
                    );

                    // TODO: fixme
                    // required volumes

                    // required volume mounts
                }
            }
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
    use file::FILE_AUTHENTICATOR_PROPERTIES_NAME;
    use stackable_operator::commons::authentication::static_::UserCredentialsSecretRef;

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

    fn setup() -> TrinoPasswordAuthentication {
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

        TrinoPasswordAuthentication { authenticators }
    }

    #[test]
    fn test_password_authentication_config_files_properties() {
        let password_authentication = setup();

        assert_eq!(
            password_authentication
                .config_properties()
                .get(PASSWORD_AUTHENTICATOR_CONFIG_FILES),
            Some(format!(
                "{RW_CONFIG_DIR_NAME}/{FILE_AUTHENTICATOR_PROPERTIES_NAME}{PASSWORD_CONFIG_FILE_NAME_SUFFIX},\
                 {RW_CONFIG_DIR_NAME}/{LDAP_AUTH_CLASS_1}-ldap-authenticator{PASSWORD_CONFIG_FILE_NAME_SUFFIX},\
                 {RW_CONFIG_DIR_NAME}/{LDAP_AUTH_CLASS_2}-ldap-authenticator{PASSWORD_CONFIG_FILE_NAME_SUFFIX}",
            ))
            .as_ref()
        );
    }

    #[test]
    fn test_password_authentication_config_files() {
        let password_authentication = setup();
        let config_files = password_authentication.config_files().unwrap();

        // We expect 3 config files (1 for file-authenticator (1 filtered out), 2 for ldap-authenticator)
        assert_eq!(config_files.len(), 3);
        // First element should be the file authentication
        assert_eq!(
            config_files.get(0).unwrap().name(),
            FileAuthenticator::new(StaticAuthenticationProvider {
                user_credentials_secret: UserCredentialsSecretRef {
                    name: "".to_string()
                }
            })
            .config_file_name()
        );
        // Second element should be ldap authentication
        assert_eq!(
            config_files.get(1).unwrap().name(),
            format!("{LDAP_AUTH_CLASS_1}-ldap-authenticator{PASSWORD_CONFIG_FILE_NAME_SUFFIX}")
        );
        // Third element should be ldap authentication
        assert_eq!(
            config_files.get(2).unwrap().name(),
            format!("{LDAP_AUTH_CLASS_2}-ldap-authenticator{PASSWORD_CONFIG_FILE_NAME_SUFFIX}")
        );
    }
}
