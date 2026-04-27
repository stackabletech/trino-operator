use serde::{Deserialize, Serialize};
use stackable_operator::{
    database_connections::databases::postgresql::PostgresqlConnection,
    schemars::{self, JsonSchema},
};

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PostgresqlConnector {
    // Docs are on the struct fields
    #[serde(flatten)]
    pub inner: PostgresqlConnection,
}
