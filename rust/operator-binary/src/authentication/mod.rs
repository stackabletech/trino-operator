mod password;

use crate::authentication::password::{TrinoPasswordAuthenticator, TrinoPasswordAuthenticatorType};

use snafu::{ResultExt, Snafu};
use stackable_operator::k8s_openapi::api::core::v1::Container;
use stackable_operator::{
    commons::authentication::{AuthenticationClass, AuthenticationClassProvider},
    kube::{runtime::reflector::ObjectRef, ResourceExt},
};
use stackable_trino_crd::{HTTP_SERVER_AUTHENTICATION_TYPE, RW_CONFIG_DIR_NAME};
use std::collections::BTreeMap;
use tracing::debug;

const PASSWORD_AUTHENTICATOR_CONFIG_FILES: &str = "password-authenticator.config-files";

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("The Trino Operator does not support the AuthenticationClass provider {authentication_class_provider} from AuthenticationClass {authentication_class} yet."))]
    AuthenticationClassProviderNotSupported {
        authentication_class_provider: String,
        authentication_class: ObjectRef<AuthenticationClass>,
    },
    #[snafu(display("Invalid authentication configuration"))]
    InvalidPasswordAuthenticationConfig { source: password::Error },
}

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Clone, Debug)]
pub struct TrinoAuthenticatorConfig {
    authenticators: Vec<TrinoAuthenticator>,
}

#[derive(Clone, Debug, strum::Display)]
pub enum TrinoAuthenticator {
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
    Password(TrinoPasswordAuthenticator),
}

impl TrinoAuthenticatorConfig {
    pub fn additional_trino_config_properties(&self) -> Result<TrinoAuthenticationProperties> {
        let mut config = BTreeMap::new();
        // The vec is to have only unique authentication types in the "http-server.authentication.type"
        // property, but to preserve the order of the provided authentication classes.
        // (This will be the order Trino will try to authenticate against as well)
        let mut http_server_authentication_types = vec![];
        // The vec is to store all file paths for password authenticators
        let mut password_authenticator_config_files = vec![];
        // Additional config files to create in the etc folder for the authenticator configuration
        let mut config_files = BTreeMap::new();
        // Additional sidecar containers
        let mut sidecar_containers = vec![];

        for authenticator in &self.authenticators {
            // The authenticator name (e.g. PASSWORD)
            let authenticator_name = authenticator.to_string();
            // Keep the authenticator types uniquely
            if !http_server_authentication_types.contains(&authenticator_name) {
                http_server_authentication_types.push(authenticator_name)
            }

            match authenticator {
                TrinoAuthenticator::Password(password_authenticator) => {
                    let file_name = password_authenticator.file_name();
                    // collect password authenticator config files paths
                    password_authenticator_config_files
                        .push(format!("{RW_CONFIG_DIR_NAME}/{file_name}"));
                    // collect required authenticator properties
                    config_files.insert(
                        file_name,
                        password_authenticator
                            .java_properties_string()
                            .context(InvalidPasswordAuthenticationConfigSnafu)?,
                    );
                    // add sidecar container to poll mounted user credentials and collect
                    // in a password data file.
                    // TODO: finish
                    sidecar_containers.push(Container::default());
                }
            }
        }

        if !http_server_authentication_types.is_empty() {
            debug!(
                "Final [{HTTP_SERVER_AUTHENTICATION_TYPE}]: {:?}.",
                http_server_authentication_types
            );
            // http-server.authentication.type=PASSWORD,CERTIFICATE,...
            config.insert(
                HTTP_SERVER_AUTHENTICATION_TYPE.to_string(),
                http_server_authentication_types.join(","),
            );
        }

        if !password_authenticator_config_files.is_empty() {
            debug!(
                "Final [{PASSWORD_AUTHENTICATOR_CONFIG_FILES}]: {:?}.",
                password_authenticator_config_files
            );
            // password-authenticator.config-files=/stackable/.../etc/file.properties,/stackable/.../etc/ldap.properties,...
            config.insert(
                PASSWORD_AUTHENTICATOR_CONFIG_FILES.to_string(),
                password_authenticator_config_files.join(","),
            );
        }

        Ok(TrinoAuthenticationProperties {
            trino_config_properties: config,
            config_files,
            sidecar_containers,
        })
    }
}

impl TryFrom<Vec<AuthenticationClass>> for TrinoAuthenticatorConfig {
    type Error = Error;

    fn try_from(auth_classes: Vec<AuthenticationClass>) -> std::result::Result<Self, Self::Error> {
        let mut authenticators = vec![];
        for auth_class in auth_classes {
            let auth_class_name = auth_class.name_any();
            match auth_class.spec.provider {
                AuthenticationClassProvider::Static(provider) => authenticators.push(
                    TrinoAuthenticator::Password(TrinoPasswordAuthenticator::new(
                        auth_class_name,
                        TrinoPasswordAuthenticatorType::File(provider),
                    )),
                ),
                AuthenticationClassProvider::Ldap(provider) => authenticators.push(
                    TrinoAuthenticator::Password(TrinoPasswordAuthenticator::new(
                        auth_class_name,
                        TrinoPasswordAuthenticatorType::Ldap(provider),
                    )),
                ),
                _ => AuthenticationClassProviderNotSupportedSnafu {
                    authentication_class_provider: auth_class.spec.provider.to_string(),
                    authentication_class: ObjectRef::<AuthenticationClass>::from_obj(&auth_class),
                }
                .fail()?,
            }
        }

        Ok(TrinoAuthenticatorConfig { authenticators })
    }
}

#[derive(Clone, Debug)]
pub struct TrinoAuthenticationProperties {
    trino_config_properties: BTreeMap<String, String>,
    config_files: BTreeMap<String, String>,
    sidecar_containers: Vec<Container>,
    // init_containers: ...
    // command line args: ...
    // env vars ...
    //
}

impl TrinoAuthenticationProperties {
    /// Return the trino config properties as used in the ConfigMap creation in the controller
    pub fn get_config_properties_for_product_config(&self) -> BTreeMap<String, Option<String>> {
        self.trino_config_properties
            .iter()
            .map(|(k, v)| (k.clone(), Some(v.clone())))
            .collect()
    }

    /// Return the trino config properties as used in the ConfigMap creation in the controller
    pub fn get_authenticator_config_files(&self) -> BTreeMap<String, String> {
        self.config_files.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stackable_operator::{
        commons::authentication::{
            static_::UserCredentialsSecretRef, AuthenticationClassSpec, LdapAuthenticationProvider,
            StaticAuthenticationProvider,
        },
        kube::core::ObjectMeta,
    };
    use stackable_trino_crd::RW_CONFIG_DIR_NAME;

    const AUTH_CLASS_0_FILE_1: &str = "file-1";
    const AUTH_CLASS_1_LDAP_1: &str = "ldap-1";
    const AUTH_CLASS_2_FILE_2: &str = "file-2";
    const FILE_SUFFIX: &str = ".properties";
    const LDAP_SEARCH_BASE: &str = "ou=users,dc=example,dc=org";

    fn setup_authentication_classes() -> Vec<AuthenticationClass> {
        vec![
            AuthenticationClass {
                metadata: ObjectMeta {
                    name: Some(AUTH_CLASS_0_FILE_1.to_string()),
                    ..ObjectMeta::default()
                },
                spec: AuthenticationClassSpec {
                    provider: AuthenticationClassProvider::Static(StaticAuthenticationProvider {
                        user_credentials_secret: UserCredentialsSecretRef {
                            name: "user-credential-secret".to_string(),
                        },
                    }),
                },
            },
            AuthenticationClass {
                metadata: ObjectMeta {
                    name: Some(AUTH_CLASS_1_LDAP_1.to_string()),
                    ..ObjectMeta::default()
                },
                spec: AuthenticationClassSpec {
                    provider: AuthenticationClassProvider::Ldap(LdapAuthenticationProvider {
                        hostname: "ldap.default.svc.cluster.local".to_string(),
                        port: Some(1389),
                        search_base: LDAP_SEARCH_BASE.to_string(),
                        search_filter: "".to_string(),
                        ldap_field_names: Default::default(),
                        bind_credentials: None,
                        tls: None,
                    }),
                },
            },
            AuthenticationClass {
                metadata: ObjectMeta {
                    name: Some(AUTH_CLASS_2_FILE_2.to_string()),
                    ..ObjectMeta::default()
                },
                spec: AuthenticationClassSpec {
                    provider: AuthenticationClassProvider::Static(StaticAuthenticationProvider {
                        user_credentials_secret: UserCredentialsSecretRef {
                            name: "user-credential-secret-2".to_string(),
                        },
                    }),
                },
            },
        ]
    }

    #[test]
    fn test_trino_authenticator() {
        let trino_auth_config =
            TrinoAuthenticatorConfig::try_from(setup_authentication_classes()).unwrap();

        let trino_config_properties = trino_auth_config
            .additional_trino_config_properties()
            .unwrap();

        assert_eq!(
            trino_config_properties
                .trino_config_properties
                .get(HTTP_SERVER_AUTHENTICATION_TYPE),
            Some("PASSWORD".to_string()).as_ref(),
        );

        assert_eq!(
            trino_config_properties
                .trino_config_properties
                .get(PASSWORD_AUTHENTICATOR_CONFIG_FILES),
            Some(format!(
                "{RW_CONFIG_DIR_NAME}/{AUTH_CLASS_0_FILE_1}{FILE_SUFFIX},\
                 {RW_CONFIG_DIR_NAME}/{AUTH_CLASS_1_LDAP_1}{FILE_SUFFIX},\
                 {RW_CONFIG_DIR_NAME}/{AUTH_CLASS_2_FILE_2}{FILE_SUFFIX}",
            ))
            .as_ref()
        );
    }
}
