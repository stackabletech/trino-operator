//! This module computes all resources required for Trino OAUTH2 authentication.
//!

use crate::authentication::TrinoAuthenticationConfig;
use snafu::{ResultExt, Snafu};
use stackable_operator::commons::authentication::OidcAuthenticationProvider;
use stackable_trino_crd::{Container, TrinoRole};

// Trino properties
const HTTP_SERVER_AUTHENTICATION_OAUTH2_CLIENT_ID: &str =
    "http-server.authentication.oidc.client-id";
const HTTP_SERVER_AUTHENTICATION_OAUTH2_CLIENT_SECRET: &str =
    "http-server.authentication.oidc.client-secret";
const HTTP_SERVER_AUTHENTICATION_OAUTH2_ISSUER: &str = "http-server.authentication.oidc.issuer";
const HTTP_SERVER_AUTHENTICATION_OAUTH2_PRINCIPAL_FIELD: &str =
    "http-server.authentication.oidc.principal-field";
// TODO: test with multiple autheticators (file, oidc)
// To enable OAuth 2.0 authentication for the Web UI, the following property must be be added:
// web-ui.authentication.type=oidc
const WEB_UI_AUTHENTICATION_TYPE: &str = "web-ui.authentication.type";

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
}

#[derive(Clone, Debug, Default)]
pub struct TrinoOidcAuthentication {
    authenticators: Vec<TrinoOidcAuthenticator>,
}

#[derive(Clone, Debug)]
pub struct TrinoOidcAuthenticator {
    name: String,
    oidc: OidcAuthenticationProvider,
}

impl TrinoOidcAuthenticator {
    pub fn new(name: String, provider: OidcAuthenticationProvider) -> Self {
        Self {
            name,
            oidc: provider,
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
        self.check_single_oauth2_authentication_class()?;

        // TODO: unwrap cannot fail here due to `check_single_oauth2_authentication_class` above
        //   the unwrap should be removed still.
        let authenticator = self.authenticators.get(0).unwrap();

        let issuer = authenticator
            .oidc
            .endpoint_url()
            .context(FailedToCreateIssuerEndpointUrlSnafu)?;

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
            HTTP_SERVER_AUTHENTICATION_OAUTH2_CLIENT_ID.to_string(),
            format!(
                "${{ENV:{client_id}}}",
                client_id =
                    self.build_bind_credentials_env_var(OAUTH2_CLIENT_ID_ENV, &authenticator.name)
            ),
        );

        oauth2_authentication_config.add_config_property(
            TrinoRole::Coordinator,
            HTTP_SERVER_AUTHENTICATION_OAUTH2_CLIENT_SECRET.to_string(),
            format!(
                "${{ENV:{client_secret}}}",
                client_secret = self
                    .build_bind_credentials_env_var(OAUTH2_CLIENT_SECRET_ENV, &authenticator.name)
            ),
        );

        // TODO: set client id and secret env var

        Ok(oauth2_authentication_config)
    }

    fn build_bind_credentials_env_var(&self, prefix: &str, auth_class_name: &str) -> String {
        format!(
            "{prefix}_{auth_class}",
            auth_class = auth_class_name.to_uppercase().replace('-', "_")
        )
    }

    /// Make sure we have exactly one authentication class
    fn check_single_oauth2_authentication_class(&self) -> Result<(), Error> {
        match self.authenticators.len() {
            // We should not reach the '0' branch, this is just a sanity check.
            0 => Err(Error::NoOauth2AuthenticationClassProvided),
            1 => Ok(()),
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
