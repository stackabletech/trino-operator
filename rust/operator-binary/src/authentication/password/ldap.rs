use crate::authentication::password::{
    PasswordAuthenticator, Result, PASSWORD_CONFIG_FILE_NAME_SUFFIX,
};

use snafu::Snafu;
use stackable_operator::commons::authentication::LdapAuthenticationProvider;
use std::collections::BTreeMap;

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
}

#[derive(Clone, Debug)]
pub struct LdapAuthenticator {
    name: String,
    ldap: LdapAuthenticationProvider,
}

impl LdapAuthenticator {
    pub fn new(name: String, provider: LdapAuthenticationProvider) -> Self {
        Self {
            name,
            ldap: provider,
        }
    }
}

impl PasswordAuthenticator for LdapAuthenticator {
    fn name(&self) -> &str {
        self.name.as_str()
    }

    fn config_file_content(&self) -> Result<BTreeMap<String, String>> {
        let mut config_data = BTreeMap::new();
        config_data.insert(
            crate::authentication::password::PASSWORD_AUTHENTICATOR_NAME.to_string(),
            PASSWORD_AUTHENTICATOR_NAME_LDAP.to_string(),
        );
        config_data.insert(
            LDAP_URL.to_string(),
            format!(
                "{protocol}{server_hostname}:{server_port}",
                protocol = match self.ldap.tls {
                    None => "ldap://",
                    Some(_) => "ldaps://",
                },
                server_hostname = self.ldap.hostname,
                server_port = self.ldap.port.unwrap_or_else(|| self.ldap.default_port()),
            ),
        );

        config_data.insert(LDAP_USER_BASE_DN.to_string(), self.ldap.search_base.clone());

        config_data.insert(
            LDAP_GROUP_AUTH_PATTERN.to_string(),
            format!("(&({id}=${{USER}}))", id = self.ldap.ldap_field_names.uid),
        );

        // If bind credentials provided we have to mount the secret volume into env variables
        // in the container and reference the DN and password in the config
        // TODO: adapt to multiple ldaps
        if self.ldap.bind_credentials.is_some() {
            config_data.insert(
                LDAP_BIND_DN.to_string(),
                format!("${{ENV:{user}}}", user = LDAP_USER_ENV),
            );
            config_data.insert(
                LDAP_BIND_PASSWORD.to_string(),
                format!("${{ENV:{pw}}}", pw = LDAP_PASSWORD_ENV),
            );
        }

        if self.ldap.use_tls() {
            if !self.ldap.use_tls_verification() {
                // Use TLS but don't verify LDAP server ca => not supported
                return Err(Box::new(Error::UnverifiedLdapTlsConnectionNotSupported));
            }
            // If there is a custom certificate, configure it.
            // There might also be TLS verification using web PKI
            if let Some(path) = self.ldap.tls_ca_cert_mount_path() {
                config_data.insert(LDAP_SSL_TRUST_STORE_PATH.to_string(), path);
            }
        } else {
            // No TLS used, allow insure LDAP
            config_data.insert(LDAP_ALLOW_INSECURE.to_string(), "true".to_string());
        }

        Ok(config_data)
    }

    fn config_file_name(&self) -> String {
        format!(
            "{name}-ldap-authenticator{PASSWORD_CONFIG_FILE_NAME_SUFFIX}",
            name = self.name
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authentication::password::PASSWORD_AUTHENTICATOR_NAME;
    use stackable_operator::commons::{
        authentication::tls::{CaCert, Tls, TlsServerVerification, TlsVerification},
        secret_class::SecretClassVolume,
    };

    const AUTH_CLASS_NAME: &str = "my-auth-class-name";
    const TLS_SECRET_CLASS_NAME: &str = "secret";
    const LDAP_HOST_NAME: &str = "openldap.default.svc.cluster.local";
    const LDAP_SEARCH_BASE: &str = "ou=users,dc=example,dc=org";

    fn setup_test_authenticator(tls: Option<Tls>) -> LdapAuthenticator {
        LdapAuthenticator::new(
            AUTH_CLASS_NAME.to_string(),
            LdapAuthenticationProvider {
                hostname: LDAP_HOST_NAME.to_string(),
                port: None,
                search_base: LDAP_SEARCH_BASE.to_string(),
                search_filter: "".to_string(),
                ldap_field_names: Default::default(),
                bind_credentials: Some(SecretClassVolume {
                    secret_class: "test".to_string(),
                    scope: None,
                }),
                tls,
            },
        )
    }

    #[test]
    fn test_file_authenticator() {
        let ldap_authenticator = setup_test_authenticator(Some(Tls {
            verification: TlsVerification::Server(TlsServerVerification {
                ca_cert: CaCert::SecretClass(TLS_SECRET_CLASS_NAME.to_string()),
            }),
        }));

        let config = ldap_authenticator.config_file_content().unwrap();
        assert!(config.get(LDAP_BIND_DN).is_some());
        assert_eq!(
            config.get(LDAP_USER_BASE_DN),
            Some(LDAP_SEARCH_BASE.to_string()).as_ref()
        );
        assert_eq!(
            config.get(LDAP_URL),
            Some(format!("ldaps://{LDAP_HOST_NAME}:636")).as_ref()
        );
        assert_eq!(
            config.get(PASSWORD_AUTHENTICATOR_NAME),
            Some(PASSWORD_AUTHENTICATOR_NAME_LDAP.to_string()).as_ref()
        );
        assert_eq!(
            config.get(LDAP_SSL_TRUST_STORE_PATH),
            Some(format!("/stackable/secrets/{TLS_SECRET_CLASS_NAME}/ca.crt")).as_ref()
        );
    }
}
