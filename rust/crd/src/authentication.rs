use crate::authentication::TrinoAuthenticationMethodReference::MultiUser;
use serde::{Deserialize, Serialize};
use snafu::ResultExt;
use snafu::{OptionExt, Snafu};
use stackable_operator::client::Client;
use stackable_operator::k8s_openapi::api::core::v1::{Secret, SecretReference};
use stackable_operator::k8s_openapi::ByteString;
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
    #[snafu(display("Missing mandatory configuration key [{}] when parsing secret", key))]
    MissingKey { key: String },
    #[snafu(display(
        "Missing mandatory secret reference when parsing authentication configuration: [{}]",
        secret
    ))]
    MissingSecretReference { secret: String },
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
pub struct AuthenticationConfig<T> {
    pub method: T,
    pub config: Option<BTreeMap<String, String>>,
    pub secrets: Option<BTreeMap<String, SecretReference>>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum TrinoAuthenticationMethod {
    MultiUser,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum TrinoAuthenticationMethodReference {
    Nothing,
    MultiUser { user_reference: SecretReference },
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum TrinoAuthenticationMethodConfig {
    Nothing,
    MultiUser { users: BTreeMap<String, String> },
}

pub async fn build_auth_reference(
    config: &AuthenticationConfig<TrinoAuthenticationMethod>,
) -> Result<TrinoAuthenticationMethodReference> {
    match config.method {
        TrinoAuthenticationMethod::MultiUser => {
            let secrets = config
                .secrets
                .as_ref()
                .with_context(|| MissingSecretReference {
                    secret: "secrets".to_string(),
                })?
                .to_owned();
            let user_secret =
                secrets
                    .get(USER_CREDENTIALS)
                    .with_context(|| MissingSecretReference {
                        secret: USER_CREDENTIALS.to_string(),
                    })?;
            Ok(TrinoAuthenticationMethodReference::MultiUser {
                user_reference: user_secret.to_owned(),
            })
        }
    }
}

pub async fn materialize_auth_config(
    client: &Client,
    reference: &TrinoAuthenticationMethodReference,
) -> Result<TrinoAuthenticationMethodConfig> {
    match reference {
        MultiUser { user_reference } => {
            let secret_name = user_reference.name.as_deref().unwrap();
            let secret_namespace = user_reference.namespace.as_deref();

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

            build_multi_user_config(Some(reference), data)
        }
        _ => Ok(TrinoAuthenticationMethodConfig::Nothing),
    }
}

fn build_multi_user_config(
    _reference: Option<&TrinoAuthenticationMethodReference>,
    secret_data: &BTreeMap<String, ByteString>,
) -> Result<TrinoAuthenticationMethodConfig> {
    let mut users = BTreeMap::new();

    for (user_name, password) in secret_data {
        let pw = String::from_utf8(password.0.clone()).with_context(|| Utf8Error {
            value: format!("{:?}", password),
        })?;

        users.insert(user_name.clone(), pw);
    }

    Ok(TrinoAuthenticationMethodConfig::MultiUser { users })
}
