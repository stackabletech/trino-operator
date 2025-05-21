use snafu::{ResultExt, Snafu};
use stackable_operator::{
    client::Client,
    crd::authentication::{core, oidc},
    kube::ResourceExt,
};

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("Failed to retrieve AuthenticationClass"))]
    AuthenticationClassRetrieval {
        source: stackable_operator::client::Error,
    },

    #[snafu(display("Invalid OIDC configuration"))]
    InvalidOidcConfiguration {
        source: stackable_operator::crd::authentication::core::v1alpha1::Error,
    },
}

type Result<T, E = Error> = std::result::Result<T, E>;

pub struct ResolvedAuthenticationClassRef {
    /// An [AuthenticationClass](DOCS_BASE_URL_PLACEHOLDER/concepts/authentication) to use.
    pub authentication_class: core::v1alpha1::AuthenticationClass,
    pub client_auth_options: Option<oidc::v1alpha1::ClientAuthenticationOptions>,
}

/// Retrieve all provided AuthenticationClass references.
pub async fn resolve_authentication_classes(
    client: &Client,
    client_authentication_details: &Vec<core::v1alpha1::ClientAuthenticationDetails>,
) -> Result<Vec<ResolvedAuthenticationClassRef>> {
    let mut resolved_auth_classes = vec![];

    for client_authentication_detail in client_authentication_details {
        let resolved_auth_class = client_authentication_detail
            .resolve_class(client)
            .await
            .context(AuthenticationClassRetrievalSnafu)?;
        let auth_class_name = resolved_auth_class.name_any();

        resolved_auth_classes.push(ResolvedAuthenticationClassRef {
            client_auth_options: match &resolved_auth_class.spec.provider {
                core::v1alpha1::AuthenticationClassProvider::Oidc(_) => Some(
                    client_authentication_detail
                        .oidc_or_error(&auth_class_name)
                        .context(InvalidOidcConfigurationSnafu)?
                        .clone(),
                ),
                _ => None,
            },
            authentication_class: resolved_auth_class,
        });
    }

    Ok(resolved_auth_classes)
}
