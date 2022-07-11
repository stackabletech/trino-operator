use serde::{Deserialize, Serialize};
use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::{
    client::Client,
    k8s_openapi::api::core::v1::{Secret, SecretReference},
    kube::runtime::reflector::ObjectRef,
    schemars::{self, JsonSchema},
};
use std::{collections::BTreeMap, string::FromUtf8Error};

const USER_CREDENTIALS: &str = "userCredentials";

#[derive(Snafu, Debug)]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    #[snafu(display("Failed to get secret name"))]
    MissingSecretName,
    #[snafu(display("Failed to find referenced {}", secret))]
    MissingSecret {
        source: stackable_operator::error::Error,
        secret: ObjectRef<Secret>,
    },
    #[snafu(display(
        "A required value was not found when parsing the authentication config: [{}]",
        value
    ))]
    MissingRequiredValue { value: String },
    #[snafu(display("Unable to parse key {} from {} as UTF8", key, secret))]
    NonUtf8Secret {
        source: FromUtf8Error,
        key: String,
        secret: ObjectRef<Secret>,
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

impl TrinoAuthenticationMethod {
    pub async fn materialize(
        &self,
        client: &Client,
        trino_namespace: &str,
    ) -> Result<TrinoAuthenticationConfig> {
        match self {
            TrinoAuthenticationMethod::MultiUser {
                user_credentials_secret: user_credential_secret,
            } => {
                let secret_name = user_credential_secret
                    .name
                    .as_deref()
                    .context(MissingSecretNameSnafu)?;
                let secret_namespace = match user_credential_secret.namespace.as_deref() {
                    Some(ns) => ns,
                    None => trino_namespace,
                };

                let secret_content = client
                    .get::<Secret>(secret_name, Some(secret_namespace))
                    .await
                    .with_context(|_| MissingSecretSnafu {
                        secret: ObjectRef::new(secret_name).within(secret_namespace),
                    })?;

                let data = secret_content
                    .data
                    .with_context(|| MissingRequiredValueSnafu {
                        value: format!("{} secret contains no data", USER_CREDENTIALS),
                    })?;

                let mut users = BTreeMap::new();

                for (user_name, password) in data {
                    let pw =
                        String::from_utf8(password.0).with_context(|_| NonUtf8SecretSnafu {
                            key: user_name.clone(),
                            secret: ObjectRef::new(secret_name).within(secret_namespace),
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

#[derive(Clone, Debug, PartialEq)]
pub enum TrinoAuthenticationConfig {
    MultiUser {
        user_credentials: BTreeMap<String, String>,
    },
}

impl TrinoAuthenticationConfig {
    /// Extracts the user and passwords provided in the `user_credentials`.
    pub fn to_trino_user_data(&self) -> String {
        match self {
            TrinoAuthenticationConfig::MultiUser { user_credentials } => user_credentials
                .iter()
                .map(|(user, password)| format!("{}:{}", user, password))
                .collect::<Vec<_>>()
                .join("\n"),
        }
    }
}
