use serde::{Deserialize, Serialize};
use snafu::{ResultExt, Snafu};
use stackable_operator::{
    client::Client,
    commons::authentication::AuthenticationClass,
    kube::runtime::reflector::ObjectRef,
    schemars::{self, JsonSchema},
};

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("Failed to retrieve AuthenticationClass {authentication_class}"))]
    AuthenticationClassRetrieval {
        source: stackable_operator::error::Error,
        authentication_class: ObjectRef<AuthenticationClass>,
    },
}

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrinoAuthenticationClassRef {
    pub authentication_class: String,
    pub secret: Option<TrinoAuthenticationSecret>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum TrinoAuthenticationSecret {
    Oidc(String),
}

pub struct ResolvedAuthenticationClassRef {
    pub authentication_class: AuthenticationClass,
    pub secret_ref: Option<String>,
}

/// Retrieve all provided `AuthenticationClass` references.
pub async fn resolve_authentication_classes(
    client: &Client,
    authentication_class_refs: &Vec<TrinoAuthenticationClassRef>,
) -> Result<Vec<ResolvedAuthenticationClassRef>> {
    let mut resolved_auth_classes = vec![];

    for auth_class in authentication_class_refs {
        let resolved_auth_class =
            AuthenticationClass::resolve(client, &auth_class.authentication_class)
                .await
                .context(AuthenticationClassRetrievalSnafu {
                    authentication_class: ObjectRef::<AuthenticationClass>::new(
                        &auth_class.authentication_class,
                    ),
                })?;

        let secret_ref = if let Some(auth_secret) = &auth_class.secret {
            match auth_secret {
                TrinoAuthenticationSecret::Oidc(secret) => Some(secret),
            }
        } else {
            None
        };

        resolved_auth_classes.push(ResolvedAuthenticationClassRef {
            authentication_class: resolved_auth_class,
            secret_ref: secret_ref.cloned(),
        });
    }

    Ok(resolved_auth_classes)
}
