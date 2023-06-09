mod file;
mod ldap;

use crate::authentication::{
    password::{file::FileAuthenticator, ldap::LdapAuthenticator},
    HasTrinoConfigFiles, HasTrinoConfigProperties, TrinoConfigFile,
};

use super::Result;
use snafu::{ResultExt, Snafu};
use stackable_operator::commons::authentication::{
    LdapAuthenticationProvider, StaticAuthenticationProvider,
};
use stackable_operator::product_config;
use stackable_trino_crd::{Container, TrinoRole, RW_CONFIG_DIR_NAME};
use std::collections::BTreeMap;
use tracing::debug;

// Trino properties
pub(crate) const PASSWORD_AUTHENTICATOR_CONFIG_FILES: &str = "password-authenticator.config-files";
pub(crate) const PASSWORD_AUTHENTICATOR_NAME: &str = "password-authenticator.name";
// file handling
pub(crate) const PASSWORD_CONFIG_FILE_NAME_SUFFIX: &str = ".properties";

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("Failed to format trino password authentication java properties"))]
    FailedToWriteJavaProperties {
        source: stackable_operator::product_config::writer::PropertiesWriterError,
    },
    #[snafu(display("Failed to configure LDAP password authentication"))]
    InvalidLdapAuthenticationConfiguration { source: ldap::Error },
    #[snafu(display("Failed to configure FILE password authentication"))]
    InvalidFileAuthenticationConfiguration { source: file::Error },
}

trait PasswordAuthenticator {
    fn name(&self) -> &str;
    fn config_file_content(&self) -> Result<BTreeMap<String, String>>;
    fn config_file_name(&self) -> String;
    fn config_file_path(&self) -> String {
        format!(
            "{RW_CONFIG_DIR_NAME}/{name}",
            name = self.config_file_name()
        )
    }
}

#[derive(Clone, Debug, Default)]
pub struct TrinoPasswordAuthentication {
    authenticators: Vec<TrinoPasswordAuthenticator>,
}

#[derive(Clone, Debug)]
struct TrinoPasswordAuthenticationConfigFile {
    name: String,
    role: stackable_trino_crd::TrinoRole,
    container: stackable_trino_crd::Container,
    content: BTreeMap<String, String>,
}

impl TrinoConfigFile for TrinoPasswordAuthenticationConfigFile {
    fn file_name(&self) -> String {
        self.name.clone()
    }

    fn content(&self) -> Result<String> {
        Ok(product_config::writer::to_java_properties_string(
            self.content
                .clone()
                .into_iter()
                .map(|(k, v)| (k, Some(v)))
                .collect::<BTreeMap<String, Option<String>>>()
                .iter(),
        )
        .context(FailedToWriteJavaPropertiesSnafu)?)
    }
}

impl HasTrinoConfigProperties for TrinoPasswordAuthentication {
    fn config_properties(&self) -> BTreeMap<String, String> {
        let mut config_files = vec![];

        for authenticator in &self.authenticators {
            match authenticator {
                TrinoPasswordAuthenticator::File(file_authenticator) => {
                    // There will only be one file authenticator pointing to a user password
                    // database that is collected from all userCredentialSecrets and we therefore
                    // only collect one.
                    let file_path = file_authenticator.config_file_path();
                    if !config_files.contains(&file_path) {
                        config_files.push(file_path);
                    }
                }
                TrinoPasswordAuthenticator::Ldap(ldap_authenticator) => {
                    config_files.push(ldap_authenticator.config_file_path());
                }
            }
        }

        let mut config = BTreeMap::new();
        // password-authenticator.config-files=/stackable/.../file-authenticator.properties,/stackable/.../ldap.properties,...
        config.insert(
            PASSWORD_AUTHENTICATOR_CONFIG_FILES.to_string(),
            config_files.join(","),
        );

        debug!(
            "Final Password authentication config properties: {:?}",
            config
        );

        config
    }
}

impl HasTrinoConfigFiles for TrinoPasswordAuthentication {
    fn config_files(&self) -> Result<Vec<Box<dyn TrinoConfigFile>>> {
        let mut config_files = vec![];
        let mut added_file_authenticator = false;

        for authenticator in &self.authenticators {
            match authenticator {
                TrinoPasswordAuthenticator::File(file_authenticator) => {
                    // we only use one file authenticator properties file and therefore
                    // only add it once here
                    if !added_file_authenticator {
                        added_file_authenticator = true;

                        config_files.push(Box::new(TrinoPasswordAuthenticationConfigFile {
                            name: file_authenticator.config_file_name(),
                            role: TrinoRole::Coordinator,
                            container: Container::Trino,
                            content: file_authenticator.config_file_properties(),
                        }) as Box<dyn TrinoConfigFile>);
                    }
                }
                TrinoPasswordAuthenticator::Ldap(ldap_authenticator) => {
                    config_files.push(Box::new(TrinoPasswordAuthenticationConfigFile {
                        name: ldap_authenticator.config_file_name(),
                        role: TrinoRole::Coordinator,
                        container: Container::Trino,
                        content: ldap_authenticator.config_file_content()?,
                    }) as Box<dyn TrinoConfigFile>)
                }
            }
        }

        Ok(config_files)
    }
}

impl TrinoPasswordAuthentication {
    pub fn is_required(&self) -> bool {
        !self.authenticators.is_empty()
    }
}

#[derive(Clone, Debug)]
pub enum TrinoPasswordAuthenticator {
    File(FileAuthenticator),
    Ldap(LdapAuthenticator),
}

#[derive(Clone, Debug, Default)]
pub struct TrinoPasswordAuthenticationBuilder {
    authenticators: Vec<TrinoPasswordAuthenticator>,
}

impl TrinoPasswordAuthenticationBuilder {
    pub fn new() -> TrinoPasswordAuthenticationBuilder {
        TrinoPasswordAuthenticationBuilder::default()
    }

    pub fn add_file_authenticator(&mut self, provider: StaticAuthenticationProvider) -> &mut Self {
        self.authenticators
            .push(TrinoPasswordAuthenticator::File(FileAuthenticator::new(
                provider,
            )));
        self
    }

    pub fn add_ldap_authenticator(
        &mut self,
        name: String,
        provider: LdapAuthenticationProvider,
    ) -> &mut Self {
        self.authenticators
            .push(TrinoPasswordAuthenticator::Ldap(LdapAuthenticator::new(
                name, provider,
            )));
        self
    }

    pub fn build(&self) -> TrinoPasswordAuthentication {
        TrinoPasswordAuthentication {
            authenticators: self.authenticators.clone(),
        }
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
        let mut auth_builder = TrinoPasswordAuthenticationBuilder::default();

        auth_builder.add_file_authenticator(StaticAuthenticationProvider {
            user_credentials_secret: UserCredentialsSecretRef {
                name: FILE_AUTH_CLASS_1.to_string(),
            },
        });
        auth_builder.add_file_authenticator(StaticAuthenticationProvider {
            user_credentials_secret: UserCredentialsSecretRef {
                name: FILE_AUTH_CLASS_2.to_string(),
            },
        });
        auth_builder.add_ldap_authenticator(LDAP_AUTH_CLASS_1.to_string(), ldap_provider());
        auth_builder.add_ldap_authenticator(LDAP_AUTH_CLASS_2.to_string(), ldap_provider());

        auth_builder.build()
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
            config_files.get(0).unwrap().file_name(),
            FileAuthenticator::new(StaticAuthenticationProvider {
                user_credentials_secret: UserCredentialsSecretRef {
                    name: "".to_string()
                }
            })
            .config_file_name()
        );
        // Second element should be ldap authentication
        assert_eq!(
            config_files.get(1).unwrap().file_name(),
            format!("{LDAP_AUTH_CLASS_1}-ldap-authenticator{PASSWORD_CONFIG_FILE_NAME_SUFFIX}")
        );
        // Third element should be ldap authentication
        assert_eq!(
            config_files.get(2).unwrap().file_name(),
            format!("{LDAP_AUTH_CLASS_2}-ldap-authenticator{PASSWORD_CONFIG_FILE_NAME_SUFFIX}")
        );
    }
}
