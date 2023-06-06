use serde::{Deserialize, Serialize};
use snafu::{ResultExt, Snafu};
use stackable_operator::{
    client::Client,
    commons::authentication::AuthenticationClass,
    kube::runtime::reflector::ObjectRef,
    schemars::{self, JsonSchema},
};

#[derive(Snafu, Debug)]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    #[snafu(display("Failed to retrieve AuthenticationClass {authentication_class}"))]
    AuthenticationClassRetrieval {
        source: stackable_operator::error::Error,
        authentication_class: ObjectRef<AuthenticationClass>,
    },
}

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrinoAuthentication {
    #[serde(default, flatten)]
    authentication_classes: Vec<TrinoAuthenticationClassRef>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrinoAuthenticationClassRef {
    authentication_class: String,
}

impl TrinoAuthentication {
    /// Is true if any authentication classes are provided.
    /// Useful to determine if encryption is required.
    pub fn authentication_enabled(&self) -> bool {
        !self.authentication_classes.is_empty()
    }

    /// Retrieve all provided `AuthenticationClass` references.
    pub async fn resolve_all(&self, client: &Client) -> Result<Vec<AuthenticationClass>> {
        let mut resolved_auth_classes = vec![];

        for auth_class in &self.authentication_classes {
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
}
