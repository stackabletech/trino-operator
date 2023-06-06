use crate::authentication::{FILE_AUTHENTICATOR_NAME, LDAP_AUTHENTICATOR_NAME};

use snafu::Snafu;
use stackable_operator::commons::authentication::{
    LdapAuthenticationProvider, StaticAuthenticationProvider,
};
use stackable_trino_crd::{
    FILE_PASSWORD_FILE, LDAP_ALLOW_INSECURE, LDAP_BIND_DN, LDAP_BIND_PASSWORD,
    LDAP_GROUP_AUTH_PATTERN, LDAP_PASSWORD_ENV, LDAP_SSL_TRUST_STORE_PATH, LDAP_URL,
    LDAP_USER_BASE_DN, LDAP_USER_ENV, PASSWORD_AUTHENTICATOR_NAME, USER_PASSWORD_DATA_DIR_NAME,
};
use std::collections::BTreeMap;

const AUTHENTICATOR_FILE_SUFFIX: &str = ".properties";

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("Trino does not support unverified TLS connections to LDAP"))]
    UnverifiedLdapTlsConnectionNotSupported,
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

    pub fn properties(&self) -> Result<BTreeMap<String, Option<String>>> {
        let mut config_data = BTreeMap::new();
        match &self.authenticator {
            TrinoPasswordAuthenticatorType::File(_) => {
                config_data.insert(
                    PASSWORD_AUTHENTICATOR_NAME.to_string(),
                    Some(FILE_AUTHENTICATOR_NAME.to_string()),
                );
                config_data.insert(
                    FILE_PASSWORD_FILE.to_string(),
                    Some(format!(
                        "{USER_PASSWORD_DATA_DIR_NAME}/{password_authenticator_name}.db",
                        password_authenticator_name = self.name
                    )),
                );
            }
            TrinoPasswordAuthenticatorType::Ldap(ldap) => {
                config_data.insert(
                    PASSWORD_AUTHENTICATOR_NAME.to_string(),
                    Some(LDAP_AUTHENTICATOR_NAME.to_string()),
                );
                config_data.insert(
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

                config_data.insert(
                    LDAP_USER_BASE_DN.to_string(),
                    Some(ldap.search_base.clone()),
                );

                config_data.insert(
                    LDAP_GROUP_AUTH_PATTERN.to_string(),
                    Some(format!(
                        "(&({id}=${{USER}}))",
                        id = ldap.ldap_field_names.uid
                    )),
                );

                // If bind credentials provided we have to mount the secret volume into env variables
                // in the container and reference the DN and password in the config
                if ldap.bind_credentials.is_some() {
                    config_data.insert(
                        LDAP_BIND_DN.to_string(),
                        Some(format!("${{ENV:{user}}}", user = LDAP_USER_ENV)),
                    );
                    config_data.insert(
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
                        config_data.insert(LDAP_SSL_TRUST_STORE_PATH.to_string(), Some(path));
                    }
                } else {
                    // No TLS used, allow insure LDAP
                    config_data.insert(LDAP_ALLOW_INSECURE.to_string(), Some("true".to_string()));
                }
            }
        }

        Ok(config_data)
    }
}

#[derive(Clone, Debug)]
pub enum TrinoPasswordAuthenticatorType {
    File(StaticAuthenticationProvider),
    Ldap(LdapAuthenticationProvider),
}
