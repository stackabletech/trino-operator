use serde::{Deserialize, Serialize};
use stackable_operator::schemars::{self, JsonSchema};

// TODO: move / use from operator-rs
#[derive(Clone, Debug, Default, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TlsRef {
    pub name: String,
    pub namespace: Option<String>,
    pub store_type: Option<String>,
}

// TODO: move to / use from operator-rs
#[derive(Clone, Debug, Default, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Authentication {
    pub basic: Option<Vec<SecretRef>>,
}

// TODO: move to / use from operator-rs
#[derive(Clone, Debug, Default, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretRef {
    pub name: String,
    pub namespace: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BasicAuthentication {
    pub user: String,
    pub password: String,
}

impl BasicAuthentication {
    /// Output the contained data in the `user:password` representation.
    pub fn combined(&self) -> String {
        return format!("{}:{}", self.user, self.password);
    }
}
