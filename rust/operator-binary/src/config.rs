use stackable_trino_crd::{
    authentication::TrinoAuthenticationConfig, FILE_PASSWORD_FILE, LDAP_ALLOW_INSECURE,
    LDAP_BIND_DN, LDAP_BIND_PASSWORD, LDAP_GROUP_AUTH_PATTERN, LDAP_SSL_TRUST_CERTIFICATE,
    LDAP_URL, LDAP_USER_BASE_DN, LDAP_USER_BIND_PATTERN, PASSWORD_AUTHENTICATOR_NAME,
    PASSWORD_AUTHENTICATOR_NAME_FILE, PASSWORD_AUTHENTICATOR_NAME_LDAP, PASSWORD_DB,
    USER_PASSWORD_DATA_DIR_NAME,
};
use std::collections::BTreeMap;

pub const LDAP_BIND_DN_ENV: &str = "LDAP_BIND_DN";
pub const LDAP_BIND_PASSWORD_ENV: &str = "LDAP_BIND_PASSWORD";
pub const LDAP_TRUST_CERT_PATH: &str = "/stackable/mount_ldap_tls";

pub fn password_authenticator_properties(
    config: &mut BTreeMap<String, Option<String>>,
    trino_authentication: &TrinoAuthenticationConfig,
) {
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
                LDAP_USER_BIND_PATTERN.to_string(),
                Some(format!(
                    "{id}=${{USER}},ou=users,dc=example,dc=org",
                    id = ldap.ldap_field_names.uid,
                )),
            );

            config.insert(
                LDAP_USER_BASE_DN.to_string(),
                //Some(ldap.search_base.clone()),
                Some("ou=users,dc=example,dc=org".to_string()),
            );

            config.insert(
                LDAP_GROUP_AUTH_PATTERN.to_string(),
                // ldap.group-auth-pattern=(&(<ldap.field_names.uid>=${USER})(<ldap.search_filter>))
                // Some(format!(
                //     "(&({id}=${{USER}})({filter}))",
                //     id = ldap.ldap_field_names.uid,
                //     filter = ldap.search_filter,
                // )),

                // (&(uid=${USER}))
                Some(format!(
                    //"(&(objectClass=inetOrgPerson)(uid=${{USER}})(ou=users,dc=example,dc=org))"
                    "(&(uid=${{USER}}))"
                )),
            );

            // If bind credentials provided we have to mount the secret volume into env variables
            // in the container and reference the DN and password in the config
            if ldap.bind_credentials.is_some() {
                // TODO: use constants
                config.insert(
                    LDAP_BIND_DN.to_string(),
                    Some("${ENV:LDAP_USER}".to_string()), //Some(format!("${{{}}}", LDAP_BIND_DN_ENV)),
                );
                config.insert(
                    LDAP_BIND_PASSWORD.to_string(),
                    Some("${ENV:LDAP_PASSWORD}".to_string()), //Some(format!("${{{}}}", LDAP_BIND_PASSWORD_ENV)),
                );
            }

            if ldap.tls.is_some() {
                config.insert(
                    LDAP_SSL_TRUST_CERTIFICATE.to_string(),
                    Some(format!("{}/{}", LDAP_TRUST_CERT_PATH, "ca.crt")),
                );
            } else {
                config.insert(LDAP_ALLOW_INSECURE.to_string(), Some("true".to_string()));
            }
        }
    }
}
