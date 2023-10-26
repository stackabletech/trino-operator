//! This module computes all resources required for Trino OAUTH2 authentication.
//!

use crate::authentication::TrinoAuthenticationConfig;
use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::{
    commons::authentication::OidcAuthenticationProvider,
    k8s_openapi::api::core::v1::{EnvVar, EnvVarSource, SecretKeySelector},
};
use stackable_trino_crd::TrinoRole;

// Trino properties
const HTTP_SERVER_AUTHENTICATION_OAUTH2_CLIENT_ID: &str =
    "http-server.authentication.oauth2.client-id";
const HTTP_SERVER_AUTHENTICATION_OAUTH2_CLIENT_SECRET: &str =
    "http-server.authentication.oauth2.client-secret";
const HTTP_SERVER_AUTHENTICATION_OAUTH2_ISSUER: &str = "http-server.authentication.oauth2.issuer";
const HTTP_SERVER_AUTHENTICATION_OAUTH2_PRINCIPAL_FIELD: &str =
    "http-server.authentication.oauth2.principal-field";
const HTTP_SERVER_AUTHENTICATION_OAUTH2_SCOPES: &str = "http-server.authentication.oauth2.scopes";
// To enable OAuth 2.0 authentication for the Web UI, the following property must be be added:
// web-ui.authentication.type=oidc
const WEB_UI_AUTHENTICATION_TYPE: &str = "web-ui.authentication.type";

const OAUTH2_CLIENT_ID: &str = "clientId";
const OAUTH2_CLIENT_SECRET: &str = "clientSecret";
const OAUTH2_CLIENT_ID_ENV: &str = "OAUTH2_CLIENT_ID";
const OAUTH2_CLIENT_SECRET_ENV: &str = "OAUTH2_CLIENT_SECRET";

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display(
        "No OAuth2 AuthenticationClass provided. This is an internal operator failure and should not be happening."
    ))]
    NoOauth2AuthenticationClassProvided,
    #[snafu(display(
        "Trino cannot configure OAuth2 with multiple Identity providers. \
         Received the following AuthenticationClasses {authentication_class_names:?}. \
         Please only provide one OAuth2 Authentication Class!"
    ))]
    MultipleOauth2AuthenticationClasses {
        authentication_class_names: Vec<String>,
    },
    #[snafu(display("Could not create OAuth2 issuer endpont url"))]
    FailedToCreateIssuerEndpointUrl {
        source: stackable_operator::commons::authentication::oidc::Error,
    },
    #[snafu(display(
        "The OAUTH2 / OIDC AuthenticationClass {auth_class_name} requires to have a secret reference present containing \
         '{OAUTH2_CLIENT_ID}' and '{OAUTH2_CLIENT_SECRET}' fields."
    ))]
    MissingOauth2CredentialSecret { auth_class_name: String },
}

#[derive(Clone, Debug, Default)]
pub struct TrinoOidcAuthentication {
    authenticators: Vec<TrinoOidcAuthenticator>,
}

#[derive(Clone, Debug)]
pub struct TrinoOidcAuthenticator {
    name: String,
    oidc: OidcAuthenticationProvider,
    secret: Option<String>,
}

impl TrinoOidcAuthenticator {
    pub fn new(
        name: String,
        provider: OidcAuthenticationProvider,
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
    pub fn new(authenticators: Vec<TrinoOidcAuthenticator>) -> Self {
        Self { authenticators }
    }

    pub fn oauth2_authentication_config(&self) -> Result<TrinoAuthenticationConfig, Error> {
        let mut oauth2_authentication_config = TrinoAuthenticationConfig::default();

        // Check for single OAuth2 AuthenticationClass and error out if multiple were provided
        let authenticator = self.get_single_oauth2_authentication_class()?;

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

        // TODO: do not hardcode / use constant!
        oauth2_authentication_config.add_config_property(
            TrinoRole::Coordinator,
            HTTP_SERVER_AUTHENTICATION_OAUTH2_PRINCIPAL_FIELD.to_string(),
            "preferred_username".to_string(),
        );

        oauth2_authentication_config.add_config_property(
            TrinoRole::Coordinator,
            HTTP_SERVER_AUTHENTICATION_OAUTH2_SCOPES.to_string(),
            authenticator.oidc.scopes.join(","),
        );

        let client_id_env =
            self.build_bind_credentials_env_var(OAUTH2_CLIENT_ID_ENV, &authenticator.name);
        let client_secret_env =
            self.build_bind_credentials_env_var(OAUTH2_CLIENT_SECRET_ENV, &authenticator.name);
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

        let secret_name =
            authenticator
                .secret
                .as_deref()
                .context(MissingOauth2CredentialSecretSnafu {
                    auth_class_name: authenticator.name.clone(),
                })?;

        oauth2_authentication_config.add_env_var(
            TrinoRole::Coordinator,
            stackable_trino_crd::Container::Trino,
            Self::env_var_from_secret(secret_name, OAUTH2_CLIENT_ID, &client_id_env),
        );
        oauth2_authentication_config.add_env_var(
            TrinoRole::Coordinator,
            stackable_trino_crd::Container::Trino,
            Self::env_var_from_secret(secret_name, OAUTH2_CLIENT_SECRET, &client_secret_env),
        );

        Ok(oauth2_authentication_config)
    }

    fn env_var_from_secret(secret_name: &str, key: &str, env_var: &str) -> EnvVar {
        EnvVar {
            name: env_var.to_string(),
            value_from: Some(EnvVarSource {
                secret_key_ref: Some(SecretKeySelector {
                    name: Some(secret_name.into()),
                    key: key.into(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..EnvVar::default()
        }
    }

    fn build_bind_credentials_env_var(&self, prefix: &str, auth_class_name: &str) -> String {
        format!(
            "{prefix}_{auth_class}",
            auth_class = auth_class_name.to_uppercase().replace('-', "_")
        )
    }

    /// Make sure we have exactly one authentication class
    fn get_single_oauth2_authentication_class(&self) -> Result<TrinoOidcAuthenticator, Error> {
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
    // use super::*;
    // use stackable_operator::commons::{
    //     authentication::tls::{CaCert, Tls, TlsServerVerification, TlsVerification},
    //     secret_class::SecretClassVolume,
    // };
    //
    // const AUTH_CLASS_NAME: &str = "my-auth-class-name";
    // const TLS_SECRET_CLASS_NAME: &str = "secret";
    // const LDAP_HOST_NAME: &str = "openldap.default.svc.cluster.local";
    // const LDAP_SEARCH_BASE: &str = "ou=users,dc=example,dc=org";
    //
    // fn setup_test_authenticator() -> LdapAuthenticator {
    //     LdapAuthenticator::new(
    //         AUTH_CLASS_NAME.to_string(),
    //         LdapAuthenticationProvider {
    //             hostname: LDAP_HOST_NAME.to_string(),
    //             port: None,
    //             search_base: LDAP_SEARCH_BASE.to_string(),
    //             search_filter: "".to_string(),
    //             ldap_field_names: Default::default(),
    //             bind_credentials: Some(SecretClassVolume {
    //                 secret_class: "test".to_string(),
    //                 scope: None,
    //             }),
    //             tls: Some(Tls {
    //                 verification: TlsVerification::Server(TlsServerVerification {
    //                     ca_cert: CaCert::SecretClass(TLS_SECRET_CLASS_NAME.to_string()),
    //                 }),
    //             }),
    //         },
    //     )
    // }
    //
    // #[test]
    // fn test_ldap_authenticator() {
    //     let ldap_authenticator = setup_test_authenticator();
    //
    //     let file_name = ldap_authenticator.config_file_name();
    //     assert_eq!(
    //         file_name,
    //         format!("{AUTH_CLASS_NAME}-password-ldap-auth.properties",)
    //     );
    //
    //     let config = ldap_authenticator.config_file_data().unwrap();
    //     assert!(config.get(LDAP_BIND_DN).is_some());
    //     assert_eq!(
    //         config.get(LDAP_USER_BASE_DN),
    //         Some(LDAP_SEARCH_BASE.to_string()).as_ref()
    //     );
    //     assert_eq!(
    //         config.get(LDAP_URL),
    //         Some(format!("ldaps://{LDAP_HOST_NAME}:636")).as_ref()
    //     );
    //     assert_eq!(
    //         config.get(PASSWORD_AUTHENTICATOR_NAME),
    //         Some(PASSWORD_AUTHENTICATOR_NAME_LDAP.to_string()).as_ref()
    //     );
    //     assert_eq!(
    //         config.get(LDAP_SSL_TRUST_STORE_PATH),
    //         Some(format!("/stackable/secrets/{TLS_SECRET_CLASS_NAME}/ca.crt")).as_ref()
    //     );
    // }
}
