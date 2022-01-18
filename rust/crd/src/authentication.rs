use serde::{Deserialize, Serialize};
use snafu::ResultExt;
use snafu::{OptionExt, Snafu};
use stackable_operator::client::Client;
use stackable_operator::k8s_openapi::api::core::v1::{Secret, SecretReference};
use stackable_operator::schemars::{self, JsonSchema};
use std::collections::BTreeMap;
use std::string::FromUtf8Error;

const USER_CREDENTIALS: &str = "userCredentials";

#[derive(Snafu, Debug)]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    #[snafu(display("Failed to find referenced secret [{}/{}]", name, namespace))]
    MissingSecret {
        source: stackable_operator::error::Error,
        name: String,
        namespace: String,
    },
    #[snafu(display(
        "A required value was not found when parsing the authentication config: [{}]",
        value
    ))]
    MissingRequiredValue { value: String },
    #[snafu(display(
        "Unable to convert from Utf8 to String when reading Secret: [{}]",
        value
    ))]
    Utf8Error {
        source: FromUtf8Error,
        value: String,
    },
}

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Authentication {
    pub method: TrinoAuthenticationMethod,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum TrinoAuthenticationMethod {
    #[serde(rename_all = "camelCase")]
    MultiUser {
        user_credentials_secret: SecretReference,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub enum TrinoAuthenticationConfig {
    MultiUser {
        user_credentials: BTreeMap<String, String>,
    },
}

impl TrinoAuthenticationMethod {
    pub async fn materialize(&self, client: &Client) -> Result<TrinoAuthenticationConfig> {
        match self {
            TrinoAuthenticationMethod::MultiUser {
                user_credentials_secret: user_credential_secret,
            } => {
                let secret_name = user_credential_secret.name.as_deref().unwrap();
                let secret_namespace = user_credential_secret.namespace.as_deref();

                let secret_content = client
                    .get::<Secret>(secret_name, secret_namespace)
                    .await
                    .with_context(|| MissingSecret {
                        name: secret_name.to_string(),
                        namespace: secret_namespace.unwrap_or("undefined"),
                    })?;

                let data = &secret_content.data.with_context(|| MissingRequiredValue {
                    value: format!("{} secret contains no data", USER_CREDENTIALS),
                })?;

                let mut users = BTreeMap::new();

                for (user_name, password) in data {
                    let pw = String::from_utf8(password.0.clone()).with_context(|| Utf8Error {
                        value: format!("{:?}", password),
                    })?;

                    users.insert(user_name.clone(), pw);
                }

                Ok(TrinoAuthenticationConfig::MultiUser {
                    user_credentials: users,
                })
            }
        }
    }
}
