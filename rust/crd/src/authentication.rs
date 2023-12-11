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
    /// An [AuthenticationClass](DOCS_BASE_URL_PLACEHOLDER/concepts/authentication) to use.
    pub authentication_class: String,
}

/// Retrieve all provided AuthenticationClass references.
pub async fn resolve_authentication_classes(
    client: &Client,
    authentication_class_refs: &Vec<TrinoAuthenticationClassRef>,
) -> Result<Vec<AuthenticationClass>> {
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

        resolved_auth_classes.push(resolved_auth_class);
    }

    Ok(resolved_auth_classes)
}
