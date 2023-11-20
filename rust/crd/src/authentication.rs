use snafu::{ResultExt, Snafu};
use stackable_operator::{
    client::Client,
    commons::authentication::{oidc, AuthenticationClass, ClientAuthenticationDetails},
    kube::ResourceExt,
};

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("Failed to retrieve AuthenticationClass"))]
    AuthenticationClassRetrieval {
        source: stackable_operator::error::Error,
    },

    #[snafu(display("Invalid OIDC configuration"))]
    OidcConfiguration {
        source: stackable_operator::error::Error,
    },
}

type Result<T, E = Error> = std::result::Result<T, E>;

pub struct ResolvedAuthenticationClassRef {
    pub authentication_class: AuthenticationClass,
    pub oidc: oidc::ClientAuthenticationOptions,
}

/// Retrieve all provided `AuthenticationClass` references.
pub async fn resolve_authentication_classes(
    client: &Client,
    client_authentication_details: &Vec<ClientAuthenticationDetails>,
) -> Result<Vec<ResolvedAuthenticationClassRef>> {
    let mut resolved_auth_classes = vec![];

    for client_authentication_detail in client_authentication_details {
        let resolved_auth_class = client_authentication_detail
            .resolve_class(client)
            .await
            .context(AuthenticationClassRetrievalSnafu)?;
        let auth_class_name = resolved_auth_class.name_any();

        resolved_auth_classes.push(ResolvedAuthenticationClassRef {
            authentication_class: resolved_auth_class,
            oidc: client_authentication_detail
                .oidc_or_error(auth_class_name)
                .context(OidcConfigurationSnafu)?
                .clone(),
        });
    }

    Ok(resolved_auth_classes)
}
