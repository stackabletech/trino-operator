use snafu::{ResultExt, Snafu};
use stackable_operator::{
    commons::authentication::{LdapAuthenticationProvider, StaticAuthenticationProvider},
    product_config,
};
use std::collections::BTreeMap;
use tracing::debug;

// where the password db file is located
pub const USER_PASSWORD_DATA_DIR_NAME: &str = "/stackable/users";
// file handling
const AUTHENTICATOR_FILE_SUFFIX: &str = ".properties";
const PASSWORD_DB_FILE_NAME: &str = "password.db";
const PASSWORD_DB_FILE_SUFFIX: &str = ".db";
// properties
const PASSWORD_AUTHENTICATOR_NAME: &str = "password-authenticator.name";
// file
const PASSWORD_AUTHENTICATOR_NAME_FILE: &str = "file";
const FILE_PASSWORD_FILE: &str = "file.password-file";
// ldap
const PASSWORD_AUTHENTICATOR_NAME_LDAP: &str = "ldap";
const LDAP_URL: &str = "ldap.url";
const LDAP_BIND_DN: &str = "ldap.bind-dn";
const LDAP_BIND_PASSWORD: &str = "ldap.bind-password";
const LDAP_USER_BASE_DN: &str = "ldap.user-base-dn";
const LDAP_GROUP_AUTH_PATTERN: &str = "ldap.group-auth-pattern";
const LDAP_ALLOW_INSECURE: &str = "ldap.allow-insecure";
const LDAP_SSL_TRUST_STORE_PATH: &str = "ldap.ssl.truststore.path";
const LDAP_USER_ENV: &str = "LDAP_USER";
const LDAP_PASSWORD_ENV: &str = "LDAP_PASSWORD";

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("Trino does not support unverified TLS connections to LDAP"))]
    UnverifiedLdapTlsConnectionNotSupported,
    #[snafu(display("Failed to format trino password authentication java properties"))]
    FailedToWriteJavaProperties {
        source: stackable_operator::product_config::writer::PropertiesWriterError,
    },
}

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Clone, Debug)]
pub struct TrinoPasswordAuthenticator {
    name: String,
    authenticator: TrinoPasswordAuthenticatorType,
}

impl TrinoPasswordAuthenticator {
    pub fn new(auth_class_name: String, authenticator: TrinoPasswordAuthenticatorType) -> Self {
        Self {
            name: auth_class_name,
            authenticator,
        }
    }

    pub fn name(&self) -> &str {
        self.name.as_ref()
    }

    pub fn file_name(&self) -> String {
        format!("{name}{AUTHENTICATOR_FILE_SUFFIX}", name = self.name)
    }

    fn password_db_file_name(&self) -> String {
        format!("{name}{PASSWORD_DB_FILE_SUFFIX}", name = self.name)
    }

    fn password_db_file_path(&self) -> String {
        format!(
            "{USER_PASSWORD_DATA_DIR_NAME}/{db_file_name}",
            db_file_name = self.password_db_file_name()
        )
    }

    pub fn java_properties_string(&self) -> Result<String> {
        Ok(product_config::writer::to_java_properties_string(
            self.properties()?
                .into_iter()
                .map(|(k, v)| (k, Some(v)))
                .collect::<BTreeMap<String, Option<String>>>()
                .iter(),
        )
        .context(FailedToWriteJavaPropertiesSnafu)?)
    }

    pub fn properties(&self) -> Result<BTreeMap<String, String>> {
        let mut config_data = BTreeMap::new();
        match &self.authenticator {
            TrinoPasswordAuthenticatorType::File(_) => {
                config_data.insert(
                    PASSWORD_AUTHENTICATOR_NAME.to_string(),
                    PASSWORD_AUTHENTICATOR_NAME_FILE.to_string(),
                );
                config_data.insert(FILE_PASSWORD_FILE.to_string(), self.password_db_file_path());
            }
            TrinoPasswordAuthenticatorType::Ldap(ldap) => {
                config_data.insert(
                    PASSWORD_AUTHENTICATOR_NAME.to_string(),
                    PASSWORD_AUTHENTICATOR_NAME_LDAP.to_string(),
                );
                config_data.insert(
                    LDAP_URL.to_string(),
                    format!(
                        "{protocol}{server_hostname}:{server_port}",
                        protocol = match ldap.tls {
                            None => "ldap://",
                            Some(_) => "ldaps://",
                        },
                        server_hostname = ldap.hostname,
                        server_port = ldap.port.unwrap_or_else(|| ldap.default_port()),
                    ),
                );

                config_data.insert(LDAP_USER_BASE_DN.to_string(), ldap.search_base.clone());

                config_data.insert(
                    LDAP_GROUP_AUTH_PATTERN.to_string(),
                    format!("(&({id}=${{USER}}))", id = ldap.ldap_field_names.uid),
                );

                // If bind credentials provided we have to mount the secret volume into env variables
                // in the container and reference the DN and password in the config
                // TODO: adapt to multiple ldaps
                if ldap.bind_credentials.is_some() {
                    config_data.insert(
                        LDAP_BIND_DN.to_string(),
                        format!("${{ENV:{user}}}", user = LDAP_USER_ENV),
                    );
                    config_data.insert(
                        LDAP_BIND_PASSWORD.to_string(),
                        format!("${{ENV:{pw}}}", pw = LDAP_PASSWORD_ENV),
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
                        config_data.insert(LDAP_SSL_TRUST_STORE_PATH.to_string(), path);
                    }
                } else {
                    // No TLS used, allow insure LDAP
                    config_data.insert(LDAP_ALLOW_INSECURE.to_string(), "true".to_string());
                }
            }
        }

        debug!(
            "Final PASSWORD authenticator config properties for [{name}]: {config_data:?}",
            name = self.name
        );

        Ok(config_data)
    }
}

#[derive(Clone, Debug)]
pub enum TrinoPasswordAuthenticatorType {
    File(StaticAuthenticationProvider),
    Ldap(LdapAuthenticationProvider),
}

#[cfg(test)]
mod tests {
    use super::*;
    use stackable_operator::commons::{
        authentication::{
            static_::UserCredentialsSecretRef,
            tls::{CaCert, Tls, TlsServerVerification, TlsVerification},
        },
        secret_class::SecretClassVolume,
    };

    #[test]
    fn test_file_password_authenticator() {
        let auth_class_name = "test";
        let authenticator = TrinoPasswordAuthenticator::new(
            auth_class_name.to_string(),
            TrinoPasswordAuthenticatorType::File(StaticAuthenticationProvider {
                user_credentials_secret: UserCredentialsSecretRef {
                    name: "secret".to_string(),
                },
            }),
        );

        assert_eq!(
            authenticator.java_properties_string().unwrap(),
            format!(
                "{FILE_PASSWORD_FILE}={USER_PASSWORD_DATA_DIR_NAME}/{auth_class_name}{PASSWORD_DB_FILE_SUFFIX}\n{PASSWORD_AUTHENTICATOR_NAME}={PASSWORD_AUTHENTICATOR_NAME_FILE}\n"
            )
        )
    }

    #[test]
    fn test_ldap_password_authenticator() {
        let auth_class_name = "test";
        let host = "ldap";
        let search_base = "ou=users,dc=example,dc=org";
        let secret_class = "test-secret-class";

        let authenticator = TrinoPasswordAuthenticator::new(
            auth_class_name.to_string(),
            TrinoPasswordAuthenticatorType::Ldap(LdapAuthenticationProvider {
                hostname: host.to_string(),
                port: None,
                search_base: search_base.to_string(),
                search_filter: "".to_string(),
                ldap_field_names: Default::default(),
                bind_credentials: Some(SecretClassVolume {
                    secret_class: "tls".to_string(),
                    scope: None,
                }),
                tls: Some(Tls {
                    verification: TlsVerification::Server {
                        0: TlsServerVerification {
                            ca_cert: CaCert::SecretClass(secret_class.to_string()),
                        },
                    },
                }),
            }),
        );

        let properties = authenticator.properties().unwrap();

        assert_eq!(
            properties.get(PASSWORD_AUTHENTICATOR_NAME),
            Some(PASSWORD_AUTHENTICATOR_NAME_LDAP.to_string()).as_ref()
        );
        assert_eq!(
            properties.get(LDAP_URL),
            Some(format!("ldaps://{host}:636")).as_ref()
        );
        assert_eq!(
            properties.get(LDAP_USER_BASE_DN),
            Some(search_base.to_string()).as_ref()
        );
        assert_eq!(
            properties.get(LDAP_SSL_TRUST_STORE_PATH),
            Some(format!("/stackable/secrets/{secret_class}/ca.crt")).as_ref()
        );
        // TODO: fixme
        assert_eq!(
            properties.get(LDAP_BIND_PASSWORD),
            Some("${ENV:LDAP_PASSWORD}".to_string()).as_ref()
        );
    }
}
