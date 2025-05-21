//! This module computes all resources required for Trino PASSWORD authentication.
//!
//! This includes file based authentication and LDAP.
//!
//! Computes a `TrinoAuthenticationConfig` containing all required resources like
//! - config properties
//! - config files
//! - volume and volume mounts
//! - extra containers and commands
//!
use std::collections::BTreeMap;

use snafu::{ResultExt, Snafu};
use stackable_operator::commons::product_image_selection::ResolvedProductImage;
use tracing::trace;

use crate::{
    authentication::{
        TrinoAuthenticationConfig,
        password::{file::FileAuthenticator, ldap::LdapAuthenticator},
    },
    crd::{Container, RW_CONFIG_DIR_NAME, TrinoRole},
};

pub mod file;
pub mod ldap;

// Trino properties
pub(crate) const PASSWORD_AUTHENTICATOR_CONFIG_FILES: &str = "password-authenticator.config-files";
const PASSWORD_AUTHENTICATOR_NAME: &str = "password-authenticator.name";

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("failed to configure LDAP password authentication"))]
    InvalidLdapAuthenticationConfiguration { source: ldap::Error },

    #[snafu(display("failed to write password authentication config file"))]
    WritePasswordAuthenticationFile {
        source: product_config::writer::PropertiesWriterError,
    },

    #[snafu(display("failed to create LDAP Volumes and VolumeMounts"))]
    LdapVolumeAndVolumeMounts { source: ldap::Error },

    #[snafu(display("failed to create LDAP Volumes and VolumeMounts"))]
    BuildPasswordFileUpdateContainer { source: file::Error },
}

#[derive(Clone, Debug, Default)]
pub struct TrinoPasswordAuthentication {
    authenticators: Vec<TrinoPasswordAuthenticator>,
}

#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum TrinoPasswordAuthenticator {
    File(FileAuthenticator),
    Ldap(LdapAuthenticator),
}

impl TrinoPasswordAuthentication {
    pub fn new(authenticators: Vec<TrinoPasswordAuthenticator>) -> Self {
        Self { authenticators }
    }

    /// Return a `TrinoAuthenticationConfig` containing all required resources for each
    /// PASSWORD authenticator.
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
                        .context(WritePasswordAuthenticationFileSnafu)?,
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
                        .context(WritePasswordAuthenticationFileSnafu)?,
                    );

                    // extra commands
                    password_authentication_config.add_commands(
                        TrinoRole::Coordinator,
                        crate::crd::Container::Trino,
                        ldap_authenticator.commands(),
                    );

                    let (volumes, volume_mounts) = ldap_authenticator
                        .volumes_and_mounts()
                        .context(LdapVolumeAndVolumeMountsSnafu)?;
                    // required volumes
                    for volume in volumes {
                        password_authentication_config.add_volume(volume)
                    }

                    // required volume mounts
                    for volume_mount in volume_mounts {
                        password_authentication_config.add_volume_mount(
                            TrinoRole::Coordinator,
                            crate::crd::Container::Trino,
                            volume_mount.clone(),
                        );
                        password_authentication_config.add_volume_mount(
                            TrinoRole::Coordinator,
                            crate::crd::Container::Prepare,
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
                )
                .context(BuildPasswordFileUpdateContainerSnafu)?,
            );
        }

        password_authentication_config.add_config_property(
            TrinoRole::Coordinator,
            PASSWORD_AUTHENTICATOR_CONFIG_FILES.to_string(),
            password_authenticator_config_file_names.join(","),
        );

        trace!(
            "Final Password authentication config: {:?}",
            password_authentication_config
        );

        Ok(password_authentication_config)
    }
}

#[cfg(test)]
mod tests {
    use stackable_operator::crd::authentication::{ldap, r#static};

    use super::*;

    const FILE_AUTH_CLASS_1: &str = "file-auth-1";
    const FILE_AUTH_CLASS_2: &str = "file-auth-2";
    const LDAP_AUTH_CLASS_1: &str = "ldap-auth-1";
    const LDAP_AUTH_CLASS_2: &str = "ldap-auth-2";

    fn ldap_provider() -> ldap::v1alpha1::AuthenticationProvider {
        serde_yaml::from_str::<ldap::v1alpha1::AuthenticationProvider>(
            "
            hostname: my-ldap
            ",
        )
        .unwrap()
    }

    fn setup() -> TrinoAuthenticationConfig {
        let authenticators = vec![
            TrinoPasswordAuthenticator::File(FileAuthenticator::new(
                FILE_AUTH_CLASS_1.to_string(),
                r#static::v1alpha1::AuthenticationProvider {
                    user_credentials_secret: r#static::v1alpha1::UserCredentialsSecretRef {
                        name: FILE_AUTH_CLASS_1.to_string(),
                    },
                },
            )),
            TrinoPasswordAuthenticator::File(FileAuthenticator::new(
                FILE_AUTH_CLASS_2.to_string(),
                r#static::v1alpha1::AuthenticationProvider {
                    user_credentials_secret: r#static::v1alpha1::UserCredentialsSecretRef {
                        name: FILE_AUTH_CLASS_2.to_string(),
                    },
                },
            )),
            TrinoPasswordAuthenticator::Ldap(LdapAuthenticator::new(
                LDAP_AUTH_CLASS_1.to_string(),
                ldap_provider(),
            )),
            TrinoPasswordAuthenticator::Ldap(LdapAuthenticator::new(
                LDAP_AUTH_CLASS_2.to_string(),
                ldap_provider(),
            )),
        ];
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
                "{RW_CONFIG_DIR_NAME}/{FILE_AUTH_CLASS_1}-password-file-auth.properties,\
                 {RW_CONFIG_DIR_NAME}/{FILE_AUTH_CLASS_2}-password-file-auth.properties,\
                 {RW_CONFIG_DIR_NAME}/{LDAP_AUTH_CLASS_1}-password-ldap-auth.properties,\
                 {RW_CONFIG_DIR_NAME}/{LDAP_AUTH_CLASS_2}-password-ldap-auth.properties",
            ))
            .as_ref()
        );
    }

    #[test]
    fn test_password_authentication_config_files() {
        let file_auth_1 = FileAuthenticator::new(
            FILE_AUTH_CLASS_1.to_string(),
            r#static::v1alpha1::AuthenticationProvider {
                user_credentials_secret: r#static::v1alpha1::UserCredentialsSecretRef {
                    name: FILE_AUTH_CLASS_1.to_string(),
                },
            },
        );
        let ldap_auth_1 = LdapAuthenticator::new(LDAP_AUTH_CLASS_1.to_string(), ldap_provider());

        let auth_config = setup();
        let config_files = auth_config.config_files(&TrinoRole::Coordinator);

        // We expect 4 config files (2 for file-authenticator, 2 for ldap-authenticator)
        assert_eq!(config_files.len(), 4);
        // check file auth
        assert_eq!(
            config_files.get(&file_auth_1.config_file_name()).unwrap(),
            &format!(
                "file.password-file=/stackable/users/{FILE_AUTH_CLASS_1}.db\npassword-authenticator.name=file\n"
            )
        );
        // check ldap
        assert!(
            config_files
                .get(&ldap_auth_1.config_file_name())
                .unwrap()
                .contains("password-authenticator.name=ldap")
        );

        // Coordinator
        assert!(
            !auth_config
                .volume_mounts(&TrinoRole::Coordinator, &Container::Trino)
                .is_empty()
        );
        assert!(!auth_config.volumes().is_empty());

        // Nothing to be set for workers
        assert!(
            auth_config
                .volume_mounts(&TrinoRole::Worker, &Container::Trino)
                .is_empty()
        );
        assert!(auth_config.config_files(&TrinoRole::Worker).is_empty());
    }
}
