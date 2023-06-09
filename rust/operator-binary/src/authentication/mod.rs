mod password;

use crate::authentication::password::{
    TrinoPasswordAuthentication, TrinoPasswordAuthenticationBuilder,
};
use snafu::Snafu;
use stackable_operator::{
    commons::authentication::{AuthenticationClass, AuthenticationClassProvider},
    kube::{runtime::reflector::ObjectRef, ResourceExt},
};
use stackable_trino_crd::{Container, TrinoRole};
use std::collections::BTreeMap;
use tracing::debug;

pub(crate) type Result<T, E = Box<dyn std::error::Error>> = std::result::Result<T, E>;

// trino properties
const HTTP_SERVER_AUTHENTICATION_TYPE: &str = "http-server.authentication.type";

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("The Trino Operator does not support the AuthenticationClass provider {authentication_class_provider} from AuthenticationClass {authentication_class} yet."))]
    AuthenticationClassProviderNotSupported {
        authentication_class_provider: String,
        authentication_class: ObjectRef<AuthenticationClass>,
    },
    #[snafu(display("Invalid password authentication configuration"))]
    InvalidPasswordAuthenticationConfig { source: password::Error },
}

trait HasTrinoConfigProperties {
    fn config_properties(&self) -> BTreeMap<String, String>;
}

trait HasTrinoConfigFiles {
    fn config_files(&self) -> Result<Vec<Box<dyn TrinoConfigFile>>>;
}

trait TrinoConfigFile {
    fn file_name(&self) -> String;
    fn role(&self) -> TrinoRole {
        TrinoRole::Coordinator
    }
    fn container(&self) -> Container {
        Container::Trino
    }
    fn content(&self) -> Result<String>;
}

#[derive(Clone, Debug, strum::Display)]
pub enum TrinoAuthenticationType {
    // #[strum(serialize = "CERTIFICATE")]
    // Certificate,
    // #[strum(serialize = "HEADER")]
    // Header,
    // #[strum(serialize = "JWT")]
    // Jwt,
    // #[strum(serialize = "KERBEROS")]
    // Kerberos,
    // #[strum(serialize = "OAUTH2")]
    // Oauth2,
    #[strum(serialize = "PASSWORD")]
    Password(TrinoPasswordAuthentication),
}

#[derive(Clone, Debug, Default)]
pub struct TrinoAuthenticationConfig {
    // All authentication classes sorted into the Trino interpretation
    authentication_types: Vec<TrinoAuthenticationType>,
}

impl TrinoAuthenticationConfig {
    pub fn additional_config_properties(&self) -> BTreeMap<String, String> {
        let mut config = BTreeMap::new();

        // Represents properties of "http-server.authentication.type".
        // Must be maintained at top level to keep the order of the provided authentication classes.
        // Since Trino will check the authentication types in the order they were provided, the first
        // provided authentication class should also be the the first to be evaluated by Trino.
        let mut http_server_authentication_types = vec![];

        for auth_type in &self.authentication_types {
            // collect and add later
            http_server_authentication_types.push(auth_type.to_string());

            match auth_type {
                TrinoAuthenticationType::Password(password_auth) => {
                    config.extend(password_auth.config_properties());
                }
            }
        }

        // http-server.authentication.type=PASSWORD,CERTIFICATE,...
        config.insert(
            HTTP_SERVER_AUTHENTICATION_TYPE.to_string(),
            http_server_authentication_types.join(","),
        );

        debug!("Final authentication config properties: {:?}", config);

        config
    }

    pub fn additional_config_files(
        &self,
        role: TrinoRole,
        container: Container,
    ) -> Result<BTreeMap<String, String>> {
        let mut filtered_config_files = BTreeMap::new();

        for file in self.config_files()? {
            // filter role and container
            if role == file.role() && container == file.container() {
                filtered_config_files.insert(file.file_name(), file.content()?);
            }
        }
        Ok(filtered_config_files)
    }

    fn config_files(&self) -> Result<Vec<Box<dyn TrinoConfigFile>>> {
        let mut files = vec![];
        for auth_type in &self.authentication_types {
            match auth_type {
                TrinoAuthenticationType::Password(password_auth) => {
                    files.extend(password_auth.config_files()?);
                }
            }
        }

        Ok(files)
    }
}

impl TryFrom<Vec<AuthenticationClass>> for TrinoAuthenticationConfig {
    type Error = Error;

    fn try_from(auth_classes: Vec<AuthenticationClass>) -> std::result::Result<Self, Self::Error> {
        let mut authentication_types = vec![];

        let mut password_auth_builder: TrinoPasswordAuthenticationBuilder =
            TrinoPasswordAuthenticationBuilder::new();

        for auth_class in auth_classes {
            let auth_class_name = auth_class.name_any();
            match auth_class.spec.provider {
                AuthenticationClassProvider::Static(provider) => {
                    password_auth_builder.add_file_authenticator(provider);
                }

                AuthenticationClassProvider::Ldap(provider) => {
                    password_auth_builder.add_ldap_authenticator(auth_class_name, provider);
                }
                _ => AuthenticationClassProviderNotSupportedSnafu {
                    authentication_class_provider: auth_class.spec.provider.to_string(),
                    authentication_class: ObjectRef::<AuthenticationClass>::from_obj(&auth_class),
                }
                .fail()?,
            }
        }

        let password_authentication = password_auth_builder.build();
        if password_authentication.is_required() {
            authentication_types.push(TrinoAuthenticationType::Password(password_authentication));
        }

        Ok(TrinoAuthenticationConfig {
            authentication_types,
        })
    }
}

///////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;
    use password::PASSWORD_CONFIG_FILE_NAME_SUFFIX;
    use stackable_operator::{
        commons::authentication::{
            static_::UserCredentialsSecretRef, AuthenticationClassSpec, LdapAuthenticationProvider,
            StaticAuthenticationProvider,
        },
        kube::core::ObjectMeta,
    };
    use stackable_trino_crd::RW_CONFIG_DIR_NAME;

    const FILE_AUTH_CLASS_1: &str = "file-auth-1";
    const FILE_AUTH_CLASS_2: &str = "file-auth-2";
    const LDAP_AUTH_CLASS_1: &str = "ldap-auth-1";
    const LDAP_AUTH_CLASS_2: &str = "ldap-auth-2";

    fn setup_file_auth_class(name: &str) -> AuthenticationClass {
        AuthenticationClass {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                ..ObjectMeta::default()
            },
            spec: AuthenticationClassSpec {
                provider: AuthenticationClassProvider::Static(StaticAuthenticationProvider {
                    user_credentials_secret: UserCredentialsSecretRef {
                        name: format!("{name}-secret"),
                    },
                }),
            },
        }
    }

    fn setup_ldap_auth_class(name: &str) -> AuthenticationClass {
        AuthenticationClass {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                ..ObjectMeta::default()
            },
            spec: AuthenticationClassSpec {
                provider: AuthenticationClassProvider::Ldap(LdapAuthenticationProvider {
                    hostname: "".to_string(),
                    port: None,
                    search_base: "".to_string(),
                    search_filter: "".to_string(),
                    ldap_field_names: Default::default(),
                    bind_credentials: None,
                    tls: None,
                }),
            },
        }
    }

    fn setup_authentication_classes() -> Vec<AuthenticationClass> {
        vec![
            setup_file_auth_class(FILE_AUTH_CLASS_1),
            setup_file_auth_class(FILE_AUTH_CLASS_2),
            setup_ldap_auth_class(LDAP_AUTH_CLASS_1),
            setup_ldap_auth_class(LDAP_AUTH_CLASS_2),
        ]
    }

    #[test]
    fn test_trino_password_authenticator_config_properties() {
        let trino_config_properties =
            TrinoAuthenticationConfig::try_from(setup_authentication_classes())
                .unwrap()
                .additional_config_properties();

        assert_eq!(
            trino_config_properties.get(HTTP_SERVER_AUTHENTICATION_TYPE),
            Some("PASSWORD".to_string()).as_ref(),
        );
        assert!(trino_config_properties
            .get(password::PASSWORD_AUTHENTICATOR_CONFIG_FILES)
            .is_some());
    }

    #[test]
    fn test_trino_password_authenticator_config_files() {
        let trino_config_files =
            TrinoAuthenticationConfig::try_from(setup_authentication_classes())
                .unwrap()
                .additional_config_files(TrinoRole::Coordinator, Container::Trino)
                .unwrap();

        assert_eq!(
            trino_config_files.get("file-authenticator.properties"),
            Some("file.password-file=/stackable/users/password.db\npassword-authenticator.name=file\n".to_string()).as_ref()
        );

        assert_eq!(
            trino_config_files.get("ldap-auth-1-ldap-authenticator.properties"),
            Some("ldap.allow-insecure=true\nldap.group-auth-pattern=(&(uid\\=${USER}))\nldap.url=ldap\\://\\:389\nldap.user-base-dn=\"\"\npassword-authenticator.name=ldap\n".to_string()).as_ref()
        );

        assert_eq!(
            trino_config_files.get("ldap-auth-2-ldap-authenticator.properties"),
            Some("ldap.allow-insecure=true\nldap.group-auth-pattern=(&(uid\\=${USER}))\nldap.url=ldap\\://\\:389\nldap.user-base-dn=\"\"\npassword-authenticator.name=ldap\n".to_string()).as_ref()
        );
    }
}
