use crate::authentication::password::{self, CONFIG_FILE_NAME_SUFFIX};

use snafu::Snafu;
use stackable_operator::{
    builder::VolumeMountBuilder,
    commons::{
        authentication::{
            ldap::SECRET_BASE_PATH,
            tls::{CaCert, Tls, TlsServerVerification, TlsVerification},
            LdapAuthenticationProvider,
        },
        secret_class::SecretClassVolume,
    },
    k8s_openapi::api::core::v1::{Volume, VolumeMount},
};
use std::collections::HashMap;

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

    pub fn config_file_name(&self) -> String {
        format!(
            "{name}-password-ldap-auth{CONFIG_FILE_NAME_SUFFIX}",
            name = self.name
        )
    }

    pub fn config_file_data(&self) -> Result<HashMap<String, String>, Error> {
        let mut config_data = HashMap::new();
        config_data.insert(
            password::PASSWORD_AUTHENTICATOR_NAME.to_string(),
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
        if self.ldap.bind_credentials.is_some() {
            config_data.insert(
                LDAP_BIND_DN.to_string(),
                format!(
                    "${{ENV:{user}}}",
                    user = self.build_bind_credentials_env_var(LDAP_USER_ENV)
                ),
            );
            config_data.insert(
                LDAP_BIND_PASSWORD.to_string(),
                format!(
                    "${{ENV:{pw}}}",
                    pw = self.build_bind_credentials_env_var(LDAP_PASSWORD_ENV)
                ),
            );
        }

        if self.ldap.use_tls() {
            if !self.ldap.use_tls_verification() {
                // Use TLS but don't verify LDAP server ca => not supported
                return Err(Error::UnverifiedLdapTlsConnectionNotSupported);
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

    pub fn commands(&self) -> Vec<String> {
        let mut commands = vec![];

        if let Some((user_path, pw_path)) = self.ldap.bind_credentials_mount_paths() {
            commands.push(format!(
                "export {user}=$(cat {user_path}",
                user = self.build_bind_credentials_env_var(LDAP_USER_ENV)
            ));
            commands.push(format!(
                "export {pw}=$(cat {pw_path}",
                pw = self.build_bind_credentials_env_var(LDAP_PASSWORD_ENV)
            ));
        }

        commands
    }

    pub fn volumes_and_mounts(&self) -> (Vec<Volume>, Vec<VolumeMount>) {
        let mut volumes = vec![];
        let mut mounts: Vec<(String, String)> = vec![];
        if let Some(bind_credentials) = &self.ldap.bind_credentials {
            let secret_class = bind_credentials.secret_class.to_owned();
            let volume_name = format!("{secret_class}-bind-credentials");
            volumes.push(bind_credentials.to_volume(&volume_name));
            mounts.push((volume_name, secret_class));
        }
        if let Some(Tls {
            verification:
                TlsVerification::Server(TlsServerVerification {
                    ca_cert: CaCert::SecretClass(secret_class),
                }),
        }) = &self.ldap.tls
        {
            let volume_name = format!("{secret_class}-ca-cert");
            let volume = SecretClassVolume {
                secret_class: secret_class.to_string(),
                scope: None,
            }
            .to_volume(&volume_name);

            volumes.push(volume);
            mounts.push((volume_name, secret_class.to_string()));
        }

        let volume_mounts = mounts
            .into_iter()
            .map(|(mount_name, secret)| {
                VolumeMountBuilder::new(mount_name, format!("{SECRET_BASE_PATH}/{secret}")).build()
            })
            .collect::<Vec<VolumeMount>>();

        (volumes, volume_mounts)
    }

    fn build_bind_credentials_env_var(&self, prefix: &str) -> String {
        format!(
            "{prefix}-{auth_class}",
            auth_class = self.name.to_uppercase().replace("-", "_")
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
    fn test_ldap_authenticator() {
        let ldap_authenticator = setup_test_authenticator(Some(Tls {
            verification: TlsVerification::Server(TlsServerVerification {
                ca_cert: CaCert::SecretClass(TLS_SECRET_CLASS_NAME.to_string()),
            }),
        }));

        let config = ldap_authenticator.config_file_data().unwrap();
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
