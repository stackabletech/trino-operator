use crate::authentication::password;
use snafu::{ResultExt, Snafu};
use stackable_operator::{
    commons::authentication::ldap::AuthenticationProvider,
    k8s_openapi::api::core::v1::{Volume, VolumeMount},
};
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

    #[snafu(display("Failed to construct LDAP endpoint URL"))]
    LdapEndpoint {
        source: stackable_operator::commons::authentication::ldap::Error,
    },

    #[snafu(display("Failed to construct LDAP volumes and volume mounts"))]
    LdapVolumesAndMounts {
        source: stackable_operator::commons::authentication::ldap::Error,
    },
}

#[derive(Clone, Debug)]
pub struct LdapAuthenticator {
    name: String,
    ldap: AuthenticationProvider,
}

impl LdapAuthenticator {
    pub fn new(name: String, provider: AuthenticationProvider) -> Self {
        Self {
            name,
            ldap: provider,
        }
    }

    /// Return the name of the authenticator config file to register with Trino
    pub fn config_file_name(&self) -> String {
        format!("{name}-password-ldap-auth.properties", name = self.name)
    }

    /// Return the content of the authenticator config file to register with Trino
    pub fn config_file_data(&self) -> Result<BTreeMap<String, String>, Error> {
        let mut config_data = BTreeMap::new();
        self.ldap.endpoint_url().context(LdapEndpointSnafu)?;
        config_data.insert(
            password::PASSWORD_AUTHENTICATOR_NAME.to_string(),
            PASSWORD_AUTHENTICATOR_NAME_LDAP.to_string(),
        );
        config_data.insert(
            LDAP_URL.to_string(),
            self.ldap.endpoint_url().context(LdapEndpointSnafu)?.into(),
        );

        config_data.insert(LDAP_USER_BASE_DN.to_string(), self.ldap.search_base.clone());

        config_data.insert(
            LDAP_GROUP_AUTH_PATTERN.to_string(),
            format!("(&({id}=${{USER}}))", id = self.ldap.ldap_field_names.uid),
        );

        // If bind credentials provided we have to mount the secret volume into env variables
        // in the container and reference the DN and password in the config
        if self.ldap.has_bind_credentials() {
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

        if self.ldap.tls.uses_tls() {
            if !self.ldap.tls.uses_tls_verification() {
                // Use TLS but don't verify LDAP server ca => not supported
                return Err(Error::UnverifiedLdapTlsConnectionNotSupported);
            }
            // If there is a custom certificate, configure it.
            // There might also be TLS verification using web PKI
            if let Some(path) = self.ldap.tls.tls_ca_cert_mount_path() {
                config_data.insert(LDAP_SSL_TRUST_STORE_PATH.to_string(), path);
            }
        } else {
            // No TLS used, allow insure LDAP
            config_data.insert(LDAP_ALLOW_INSECURE.to_string(), "true".to_string());
        }

        Ok(config_data)
    }

    /// Return additional commands for Trino
    pub fn commands(&self) -> Vec<String> {
        let mut commands = vec![];

        if let Some((user_path, pw_path)) = self.ldap.bind_credentials_mount_paths() {
            commands.push(format!(
                "export {user}=$(cat {user_path})",
                user = self.build_bind_credentials_env_var(LDAP_USER_ENV)
            ));
            commands.push(format!(
                "export {pw}=$(cat {pw_path})",
                pw = self.build_bind_credentials_env_var(LDAP_PASSWORD_ENV)
            ));
        }

        commands
    }

    /// Required LDAP authenticator volume amd volume mounts.
    pub fn volumes_and_mounts(&self) -> Result<(Vec<Volume>, Vec<VolumeMount>), Error> {
        self.ldap
            .volumes_and_mounts()
            .context(LdapVolumesAndMountsSnafu)
    }

    /// Convert the provided authentication class name into an ENV variable.
    /// This means uppercase and replacing any '-' with '_' characters.
    fn build_bind_credentials_env_var(&self, prefix: &str) -> String {
        format!(
            "{prefix}_{auth_class}",
            auth_class = self.name.to_uppercase().replace('-', "_")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authentication::password::PASSWORD_AUTHENTICATOR_NAME;

    const AUTH_CLASS_NAME: &str = "my-auth-class-name";
    const TLS_SECRET_CLASS_NAME: &str = "secret";
    const LDAP_HOST_NAME: &str = "openldap.default.svc.cluster.local";
    const LDAP_SEARCH_BASE: &str = "ou=users,dc=example,dc=org";

    fn setup_test_authenticator() -> LdapAuthenticator {
        let auth_provider = serde_yaml::from_str::<AuthenticationProvider>(&format!(
            r#"
            hostname: {LDAP_HOST_NAME}
            searchBase: {LDAP_SEARCH_BASE}
            bindCredentials:
              secretClass: test
            tls:
              verification:
                server:
                  caCert:
                    secretClass: {TLS_SECRET_CLASS_NAME}
            "#
        ))
        .unwrap();

        LdapAuthenticator::new(AUTH_CLASS_NAME.to_string(), auth_provider)
    }

    #[test]
    fn test_ldap_authenticator() {
        let ldap_authenticator = setup_test_authenticator();

        let file_name = ldap_authenticator.config_file_name();
        assert_eq!(
            file_name,
            format!("{AUTH_CLASS_NAME}-password-ldap-auth.properties",)
        );

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
