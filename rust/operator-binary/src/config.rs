use snafu::Snafu;
use stackable_trino_crd::{
    authentication::TrinoAuthenticationConfig, FILE_PASSWORD_FILE, LDAP_ALLOW_INSECURE,
    LDAP_BIND_DN, LDAP_BIND_PASSWORD, LDAP_GROUP_AUTH_PATTERN, LDAP_PASSWORD_ENV,
    LDAP_SSL_TRUST_STORE_PATH, LDAP_URL, LDAP_USER_BASE_DN, LDAP_USER_ENV,
    PASSWORD_AUTHENTICATOR_NAME, PASSWORD_AUTHENTICATOR_NAME_FILE,
    PASSWORD_AUTHENTICATOR_NAME_LDAP, PASSWORD_DB, USER_PASSWORD_DATA_DIR_NAME,
};
use std::collections::BTreeMap;

#[derive(Snafu, Debug)]
pub enum ConfigError {
    #[snafu(display("Trino does not support unverified TLS connections to LDAP"))]
    UnverifiedLdapTlsConnectionNotSupported,
}

pub fn password_authenticator_properties(
    config: &mut BTreeMap<String, Option<String>>,
    trino_authentication: &TrinoAuthenticationConfig,
) -> Result<(), ConfigError> {
    match &trino_authentication {
        // This requires:
        // password-authenticator.name=file
        // file.password-file=/path_to_file
        TrinoAuthenticationConfig::MultiUser { .. } => {
            config.insert(
                PASSWORD_AUTHENTICATOR_NAME.to_string(),
                Some(PASSWORD_AUTHENTICATOR_NAME_FILE.to_string()),
            );
            config.insert(
                FILE_PASSWORD_FILE.to_string(),
                Some(format!("{}/{}", USER_PASSWORD_DATA_DIR_NAME, PASSWORD_DB)),
            );
        }
        // This requires
        // password-authenticator.name=ldap
        // ldap.url=ldap://server:port
        // ...
        TrinoAuthenticationConfig::Ldap(ldap) => {
            config.insert(
                PASSWORD_AUTHENTICATOR_NAME.to_string(),
                Some(PASSWORD_AUTHENTICATOR_NAME_LDAP.to_string()),
            );
            config.insert(
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

            config.insert(
                LDAP_USER_BASE_DN.to_string(),
                Some(ldap.search_base.clone()),
            );

            config.insert(
                LDAP_GROUP_AUTH_PATTERN.to_string(),
                Some(format!(
                    "(&({id}=${{USER}}))",
                    id = ldap.ldap_field_names.uid
                )),
            );

            // If bind credentials provided we have to mount the secret volume into env variables
            // in the container and reference the DN and password in the config
            if ldap.bind_credentials.is_some() {
                config.insert(
                    LDAP_BIND_DN.to_string(),
                    Some(format!("${{ENV:{user}}}", user = LDAP_USER_ENV)),
                );
                config.insert(
                    LDAP_BIND_PASSWORD.to_string(),
                    Some(format!("${{ENV:{pw}}}", pw = LDAP_PASSWORD_ENV)),
                );
            }

            if ldap.use_tls() {
                if !ldap.use_tls_verification() {
                    // use TLS but don't verify => not supported
                    return Err(ConfigError::UnverifiedLdapTlsConnectionNotSupported);
                }
                // If there is a custom certificate, configure it.
                // There might also be TLS verification using web PKI
                if let Some(path) = ldap.tls_ca_cert_mount_path() {
                    config.insert(LDAP_SSL_TRUST_STORE_PATH.to_string(), Some(path));
                }

            } else {
                // No TLS used, allow insure LDAP
                config.insert(LDAP_ALLOW_INSECURE.to_string(), Some("true".to_string()));
            }
        }
    }

    Ok(())
}
