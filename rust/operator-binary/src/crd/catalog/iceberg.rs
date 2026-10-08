use serde::{Deserialize, Serialize};
use stackable_operator::schemars::{self, JsonSchema};
use url::Url;

use super::commons::HiveMetastoreConnection;

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum IcebergCatalogConnection {
    /// (Recommended) use a REST catalog to store metadata.
    Rest(IcebergRestCatalogConnection),

    /// Use a Hive metastore to store metadata.
    HiveMetastore(HiveMetastoreConnection),

    /// The operator doesn't configure any catalog, the user needs to do that,
    /// e.g. using `configOverrides`.
    UserProvided {},
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IcebergRestCatalogConnection {
    /// URL of the rest catalog server.
    pub uri: Url,

    /// How to authenticate against the REST catalog.
    #[serde(default)]
    pub security: IcebergRestCatalogSecurity,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum IcebergRestCatalogSecurity {
    /// Don't authenticate against the REST catalog (chosen by default).
    None {},

    /// Use OAuth2 to authenticate against the REST catalog.
    ///
    /// Note that we only support configuring a subset of Trino's properties, you might need to use
    /// `configOverrides` to be able to set all [available properties](https://trino.io/docs/current/object-storage/metastores.html#iceberg-specific-metastores).
    #[serde(rename_all = "camelCase")]
    OAuth2 {
        /// The endpoint to retrieve access token from OAuth2 Server.
        server_uri: Url,

        /// The credential to present to the REST catalog.
        credential: IcebergRestCatalogOAuthCredential,
    },
}

impl Default for IcebergRestCatalogSecurity {
    fn default() -> Self {
        Self::None {}
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum IcebergRestCatalogOAuthCredential {
    /// Authenticate using a bearer token.
    ///
    /// The Secret needs to contain the `token` key.
    TokenSecretName(String),

    // The credential to exchange for a token in the OAuth2 client credentials flow with the server.
    ///
    /// The Secret needs to contain the `clientId` and `clientSecret` keys.
    CredentialSecretName(String),
}
