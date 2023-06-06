mod password;

use crate::authentication::password::{TrinoPasswordAuthenticator, TrinoPasswordAuthenticatorType};

use snafu::Snafu;
use stackable_operator::{
    commons::authentication::{AuthenticationClass, AuthenticationClassProvider},
    kube::{runtime::reflector::ObjectRef, ResourceExt},
};
use stackable_trino_crd::{
    FILE_PASSWORD_FILE, HTTP_SERVER_AUTHENTICATION_TYPE, LDAP_ALLOW_INSECURE, LDAP_BIND_DN,
    LDAP_BIND_PASSWORD, LDAP_GROUP_AUTH_PATTERN, LDAP_PASSWORD_ENV, LDAP_SSL_TRUST_STORE_PATH,
    LDAP_URL, LDAP_USER_BASE_DN, LDAP_USER_ENV, PASSWORD_AUTHENTICATOR_NAME,
    USER_PASSWORD_DATA_DIR_NAME,
};
use std::collections::BTreeMap;

const PASSWORD_AUTHENTICATOR_CONFIG_FILES: &str = "password-authenticator.config-files";
const STACKABLE_CONFIG_ETC_DIR: &str = "/stackable/config/etc";

const FILE_AUTHENTICATOR_NAME: &str = "file";
const LDAP_AUTHENTICATOR_NAME: &str = "ldap";

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("The Trino Operator does not support the AuthenticationClass provider {authentication_class_provider} from AuthenticationClass {authentication_class} yet."))]
    AuthenticationClassProviderNotSupported {
        authentication_class_provider: String,
        authentication_class: ObjectRef<AuthenticationClass>,
    },
    #[snafu(display("Trino does not support unverified TLS connections to LDAP"))]
    UnverifiedLdapTlsConnectionNotSupported,
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

#[derive(Clone, Debug)]
pub struct TrinoAuthenticationProperties {
    trino_config_properties: BTreeMap<String, String>,
    config_files: BTreeMap<String, BTreeMap<String, Option<String>>>,
    // init_containers: ...
    // command line args: ...
    // env vars ...
    //
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

        for authenticator in &self.authenticators {
            // The authenticator name (e.g. PASSWORD)
            let authenticator_name = authenticator.to_string();
            if !http_server_authentication_types.contains(&authenticator_name) {
                http_server_authentication_types.push(authenticator_name)
            }

            match authenticator {
                TrinoAuthenticator::Password(password_authenticator) => {
                    let properties_file_name = password_authenticator.file_name();

                    let mut config_file_data = BTreeMap::new();

                    password_authenticator_config_files
                        .push(format!("{STACKABLE_CONFIG_ETC_DIR}/{properties_file_name}"));

                    match &password_authenticator.authenticator() {
                        TrinoPasswordAuthenticatorType::File(_) => {
                            config_file_data.insert(
                                PASSWORD_AUTHENTICATOR_NAME.to_string(),
                                Some(FILE_AUTHENTICATOR_NAME.to_string()),
                            );
                            config_file_data.insert(
                                FILE_PASSWORD_FILE.to_string(),
                                Some(format!(
                                    "{USER_PASSWORD_DATA_DIR_NAME}/{password_authenticator_name}.db",
                                    password_authenticator_name = password_authenticator.name()
                                )),
                            );
                        }
                        TrinoPasswordAuthenticatorType::Ldap(ldap) => {
                            config_file_data.insert(
                                PASSWORD_AUTHENTICATOR_NAME.to_string(),
                                Some(LDAP_AUTHENTICATOR_NAME.to_string()),
                            );
                            config_file_data.insert(
                                LDAP_URL.to_string(),
                                Some(format!(
                                    "{protocol}{server_hostname}:{server_port}",
                                    protocol = match ldap.tls {
                                        None => "ldap://",
                                        Some(_) => "ldaps://",
                                    },
                                    server_hostname = ldap.hostname,
                                    server_port = ldap.port.unwrap_or_else(|| ldap.default_port()),
                                )),
                            );

                            config_file_data.insert(
                                LDAP_USER_BASE_DN.to_string(),
                                Some(ldap.search_base.clone()),
                            );

                            config_file_data.insert(
                                LDAP_GROUP_AUTH_PATTERN.to_string(),
                                Some(format!(
                                    "(&({id}=${{USER}}))",
                                    id = ldap.ldap_field_names.uid
                                )),
                            );

                            // If bind credentials provided we have to mount the secret volume into env variables
                            // in the container and reference the DN and password in the config
                            if ldap.bind_credentials.is_some() {
                                config_file_data.insert(
                                    LDAP_BIND_DN.to_string(),
                                    Some(format!("${{ENV:{user}}}", user = LDAP_USER_ENV)),
                                );
                                config_file_data.insert(
                                    LDAP_BIND_PASSWORD.to_string(),
                                    Some(format!("${{ENV:{pw}}}", pw = LDAP_PASSWORD_ENV)),
                                );
                            }

                            if ldap.use_tls() {
                                if !ldap.use_tls_verification() {
                                    // Use TLS but don't verify LDAP server ca => not supported
                                    return Err(Error::UnverifiedLdapTlsConnectionNotSupported);
                                }
                                // If there is a custom certificate, configure it.
                                // There might also be TLS verification using web PKI
                                if let Some(path) = ldap.tls_ca_cert_mount_path() {
                                    config_file_data
                                        .insert(LDAP_SSL_TRUST_STORE_PATH.to_string(), Some(path));
                                }
                            } else {
                                // No TLS used, allow insure LDAP
                                config_file_data.insert(
                                    LDAP_ALLOW_INSECURE.to_string(),
                                    Some("true".to_string()),
                                );
                            }
                        }
                    }

                    config_files.insert(properties_file_name, config_file_data);
                }
            }
        }

        if !http_server_authentication_types.is_empty() {
            // http-server.authentication.type=PASSWORD,CERTIFICATE,...
            config.insert(
                HTTP_SERVER_AUTHENTICATION_TYPE.to_string(),
                http_server_authentication_types.join(","),
            );
        }

        if !password_authenticator_config_files.is_empty() {
            // password-authenticator.config-files=/stackable/.../etc/file.properties,/stackable/.../etc/ldap.properties,...
            config.insert(
                PASSWORD_AUTHENTICATOR_CONFIG_FILES.to_string(),
                password_authenticator_config_files.join(","),
            );
        }

        Ok(TrinoAuthenticationProperties {
            trino_config_properties: config,
            config_files,
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

#[cfg(test)]
mod tests {
    use super::*;
    use stackable_operator::{
        commons::{
            authentication::{
                static_::UserCredentialsSecretRef, AuthenticationClassSpec,
                LdapAuthenticationProvider, StaticAuthenticationProvider,
                TlsAuthenticationProvider,
            },
            secret_class::SecretClassVolume,
        },
        kube::core::ObjectMeta,
    };

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
                "{STACKABLE_CONFIG_ETC_DIR}/{AUTH_CLASS_0_FILE_1}{FILE_SUFFIX},\
                 {STACKABLE_CONFIG_ETC_DIR}/{AUTH_CLASS_1_LDAP_1}{FILE_SUFFIX},\
                 {STACKABLE_CONFIG_ETC_DIR}/{AUTH_CLASS_2_FILE_2}{FILE_SUFFIX}",
            ))
            .as_ref()
        );

        assert_eq!(
            trino_config_properties
                .config_files
                .get(&format!("{AUTH_CLASS_0_FILE_1}{FILE_SUFFIX}"))
                .unwrap()
                .get(PASSWORD_AUTHENTICATOR_NAME)
                .unwrap()
                .as_deref(),
            Some(FILE_AUTHENTICATOR_NAME)
        );

        assert_eq!(
            trino_config_properties
                .config_files
                .get(&format!("{AUTH_CLASS_1_LDAP_1}{FILE_SUFFIX}"))
                .unwrap()
                .get(PASSWORD_AUTHENTICATOR_NAME)
                .unwrap()
                .as_deref(),
            Some(LDAP_AUTHENTICATOR_NAME)
        );

        assert_eq!(
            trino_config_properties
                .config_files
                .get(&format!("{AUTH_CLASS_1_LDAP_1}{FILE_SUFFIX}"))
                .unwrap()
                .get(LDAP_USER_BASE_DN)
                .unwrap()
                .as_deref(),
            Some(LDAP_SEARCH_BASE)
        );

        assert_eq!(
            trino_config_properties
                .config_files
                .get(&format!("{AUTH_CLASS_2_FILE_2}{FILE_SUFFIX}"))
                .unwrap()
                .get(PASSWORD_AUTHENTICATOR_NAME)
                .unwrap()
                .as_deref(),
            Some(FILE_AUTHENTICATOR_NAME)
        );
    }
}
