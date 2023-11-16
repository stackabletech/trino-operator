//! This module computes all resources required for Trino OAUTH2 authentication.
//!

use crate::authentication::TrinoAuthenticationConfig;
use crate::command;
use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::commons::authentication::oidc::{
    self, CLIENT_ID_SECRET_KEY, CLIENT_SECRET_SECRET_KEY,
};
use stackable_trino_crd::{TrinoRole, STACKABLE_CLIENT_TLS_DIR};

// Trino properties
const HTTP_SERVER_AUTHENTICATION_OAUTH2_CLIENT_ID: &str =
    "http-server.authentication.oauth2.client-id";
const HTTP_SERVER_AUTHENTICATION_OAUTH2_CLIENT_SECRET: &str =
    "http-server.authentication.oauth2.client-secret";
const HTTP_SERVER_AUTHENTICATION_OAUTH2_ISSUER: &str = "http-server.authentication.oauth2.issuer";
const HTTP_SERVER_AUTHENTICATION_OAUTH2_SCOPES: &str = "http-server.authentication.oauth2.scopes";
// To enable OAuth 2.0 authentication for the Web UI, the following property must be be added:
// web-ui.authentication.type=oidc
const WEB_UI_AUTHENTICATION_TYPE: &str = "web-ui.authentication.type";

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display(
        "No OAuth2 AuthenticationClass provided. This is an internal operator failure and should not be happening."
    ))]
    NoOauth2AuthenticationClassProvided,
    #[snafu(display(
        "Trino cannot configure OAuth2 with multiple Identity providers. \
         Received the following AuthenticationClasses {authentication_class_names:?}. \
         Please only provide one OAuth2 AuthenticationClass!"
    ))]
    MultipleOauth2AuthenticationClasses {
        authentication_class_names: Vec<String>,
    },
    #[snafu(display("Failed to create OAuth2 issuer endpoint url."))]
    FailedToCreateIssuerEndpointUrl {
        source: stackable_operator::commons::authentication::oidc::Error,
    },
    #[snafu(display(
        "The OAUTH2 / OIDC AuthenticationClass {auth_class_name} requires to have a secret reference present containing \
         '{CLIENT_ID_SECRET_KEY}' and '{CLIENT_SECRET_SECRET_KEY}' fields."
    ))]
    MissingOauth2CredentialSecret { auth_class_name: String },
    #[snafu(display("Trino does not support unverified TLS connections to OIDC"))]
    UnverifiedOidcTlsConnectionNotSupported,
}

#[derive(Clone, Debug, Default)]
pub struct TrinoOidcAuthentication {
    authenticators: Vec<OidcAuthenticator>,
}

#[derive(Clone, Debug)]
pub struct OidcAuthenticator {
    name: String,
    oidc: oidc::AuthenticationProvider,
    secret: Option<String>,
}

impl OidcAuthenticator {
    pub fn new(
        name: String,
        provider: oidc::AuthenticationProvider,
        secret_ref: Option<String>,
    ) -> Self {
        Self {
            name,
            oidc: provider,
            secret: secret_ref,
        }
    }
}

impl TrinoOidcAuthentication {
    pub fn new(authenticators: Vec<OidcAuthenticator>) -> Self {
        Self { authenticators }
    }

    pub fn oauth2_authentication_config(&self) -> Result<TrinoAuthenticationConfig, Error> {
        let mut oauth2_authentication_config = TrinoAuthenticationConfig::default();

        // Check for single OAuth2 AuthenticationClass and error out if multiple were provided
        let authenticator = self.get_single_oauth2_authentication_class()?;

        // We require a secret with client credentials
        let secret_name =
            authenticator
                .secret
                .as_deref()
                .context(MissingOauth2CredentialSecretSnafu {
                    auth_class_name: authenticator.name.clone(),
                })?;

        let issuer = authenticator
            .oidc
            .endpoint_url()
            .context(FailedToCreateIssuerEndpointUrlSnafu)?;

        // Trino config.properties
        oauth2_authentication_config.add_config_property(
            TrinoRole::Coordinator,
            HTTP_SERVER_AUTHENTICATION_OAUTH2_ISSUER.to_string(),
            issuer.to_string(),
        );

        oauth2_authentication_config.add_config_property(
            TrinoRole::Coordinator,
            HTTP_SERVER_AUTHENTICATION_OAUTH2_SCOPES.to_string(),
            authenticator.oidc.scopes.join(","),
        );

        let (client_id_env, client_secret_env) =
            oidc::AuthenticationProvider::client_credentials_env_names(secret_name);

        oauth2_authentication_config.add_env_vars(
            TrinoRole::Coordinator,
            stackable_trino_crd::Container::Trino,
            oidc::AuthenticationProvider::client_credentials_env_var_mounts(
                secret_name.to_string(),
            ),
        );

        oauth2_authentication_config.add_config_property(
            TrinoRole::Coordinator,
            HTTP_SERVER_AUTHENTICATION_OAUTH2_CLIENT_ID.to_string(),
            format!("${{ENV:{client_id_env}}}",),
        );
        oauth2_authentication_config.add_config_property(
            TrinoRole::Coordinator,
            HTTP_SERVER_AUTHENTICATION_OAUTH2_CLIENT_SECRET.to_string(),
            format!("${{ENV:{client_secret_env}}}",),
        );

        // We set this if OAUTH2/OIDC is enabled. The web defaults to "FORM" which is
        // for PASSWORD authentication (file, ldap). We do want to enforce users to login
        // via OAUTH2 if this is set. The coordinator can be reached with any other configured
        // auth mechanisms and credentials via CLI etc.
        // See: https://trino.io/docs/current/security/oauth2.html#trino-server-configuration
        // See: https://trino.io/docs/current/admin/properties-web-interface.html#web-ui-authentication-type
        oauth2_authentication_config.add_config_property(
            TrinoRole::Coordinator,
            WEB_UI_AUTHENTICATION_TYPE.to_string(),
            "oauth2".to_string(),
        );

        // Volumes and VolumeMounts
        let (tls_volumes, tls_mounts) = authenticator.oidc.tls.volumes_and_mounts();
        oauth2_authentication_config.add_volumes(tls_volumes);
        oauth2_authentication_config.add_volume_mounts(
            TrinoRole::Coordinator,
            stackable_trino_crd::Container::Prepare,
            tls_mounts,
        );

        if authenticator.oidc.tls.use_tls() {
            if !authenticator.oidc.tls.use_tls_verification() {
                // TODO: this still true?
                // Use TLS but don't verify OIDC server ca => not supported
                return Err(Error::UnverifiedOidcTlsConnectionNotSupported);
            }
            // If there is a custom certificate, configure it.
            // There might also be TLS verification using web PKI
            if let Some(path) = authenticator.oidc.tls.tls_ca_cert_mount_path() {
                oauth2_authentication_config.add_commands(
                    TrinoRole::Coordinator,
                    stackable_trino_crd::Container::Prepare,
                    command::add_cert_to_truststore(&path, STACKABLE_CLIENT_TLS_DIR, "oidc-idp"),
                );
            }
        }

        Ok(oauth2_authentication_config)
    }

    /// Make sure we have exactly one authentication class
    fn get_single_oauth2_authentication_class(&self) -> Result<OidcAuthenticator, Error> {
        match self.authenticators.len() {
            // We should not reach the '0' branch, this is just a sanity check.
            0 => Err(Error::NoOauth2AuthenticationClassProvided),
            // The unwrap is safe here
            1 => Ok(self.authenticators.get(0).unwrap().clone()),
            _ => Err(Error::MultipleOauth2AuthenticationClasses {
                authentication_class_names: self
                    .authenticators
                    .iter()
                    .map(|oauth2_authenticator| oauth2_authenticator.name.clone())
                    .collect::<Vec<String>>(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stackable_trino_crd::Container;

    const IDP_PORT: u16 = 8080;
    const IDP_ROOT_PATH: &str = "/realms/master";
    const IDP_SCOPE_1: &str = "openid";
    const IDP_SCOPE_2: &str = "test";
    const AUTH_CLASS_NAME_1: &str = "trino-oidc-auth-1";
    const AUTH_CLASS_NAME_2: &str = "trino-oidc-auth-2";
    const AUTH_CLASS_CREDENTIAL_SECRET: &str = "trino-oidc-credentials";

    fn setup_test_authenticator(
        auth_class_name: &str,
        credential_secret: Option<String>,
    ) -> OidcAuthenticator {
        let input = format!(
            r#"
            hostname: keycloak
            port: {IDP_PORT}
            rootPath: {IDP_ROOT_PATH}
            scopes: ["{IDP_SCOPE_1}", "{IDP_SCOPE_2}"]
        "#
        );
        let deserializer = serde_yaml::Deserializer::from_str(&input);
        let oidc_auth_provider: oidc::AuthenticationProvider =
            serde_yaml::with::singleton_map_recursive::deserialize(deserializer).unwrap();

        OidcAuthenticator::new(
            auth_class_name.to_string(),
            oidc_auth_provider,
            credential_secret,
        )
    }

    #[test]
    fn test_oidc_authentication_limit_one_error() {
        let oidc_authentication = TrinoOidcAuthentication::new(vec![
            setup_test_authenticator(AUTH_CLASS_NAME_1, None),
            setup_test_authenticator(AUTH_CLASS_NAME_2, None),
        ]);

        assert!(oidc_authentication.oauth2_authentication_config().is_err())
    }

    #[test]
    fn test_oidc_authentication_missing_secret_error() {
        let oidc_authentication =
            TrinoOidcAuthentication::new(vec![setup_test_authenticator(AUTH_CLASS_NAME_1, None)]);

        assert!(oidc_authentication.oauth2_authentication_config().is_err());
    }

    #[test]
    fn test_oidc_authentication_settings() {
        let oidc_authentication = TrinoOidcAuthentication::new(vec![setup_test_authenticator(
            AUTH_CLASS_NAME_1,
            Some(AUTH_CLASS_CREDENTIAL_SECRET.to_string()),
        )]);

        let trino_oidc_auth = oidc_authentication.oauth2_authentication_config().unwrap();

        assert_eq!(
            Some(&format!("http://keycloak:{IDP_PORT}{IDP_ROOT_PATH}")),
            trino_oidc_auth
                .config_properties
                .get(&TrinoRole::Coordinator)
                .unwrap()
                .get(HTTP_SERVER_AUTHENTICATION_OAUTH2_ISSUER)
        );

        assert_eq!(
            Some(&format!("{IDP_SCOPE_1},{IDP_SCOPE_2}")),
            trino_oidc_auth
                .config_properties
                .get(&TrinoRole::Coordinator)
                .unwrap()
                .get(HTTP_SERVER_AUTHENTICATION_OAUTH2_SCOPES)
        );

        assert_eq!(
            Some(&"oauth2".to_string()),
            trino_oidc_auth
                .config_properties
                .get(&TrinoRole::Coordinator)
                .unwrap()
                .get(WEB_UI_AUTHENTICATION_TYPE)
        );

        // we expect 2 env variables for client id and client secret
        assert_eq!(
            2,
            trino_oidc_auth
                .env_vars
                .get(&TrinoRole::Coordinator)
                .unwrap()
                .get(&Container::Trino)
                .unwrap()
                .len()
        );
    }
}
