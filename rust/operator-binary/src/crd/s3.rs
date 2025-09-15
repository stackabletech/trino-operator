use serde::{Deserialize, Serialize};
use stackable_operator::schemars::{self, JsonSchema};

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct S3Config {
    /// S3 connection configuration.
    /// Learn more about S3 configuration in the [S3 concept docs](DOCS_BASE_URL_PLACEHOLDER/concepts/s3).
    pub connection: stackable_operator::crd::s3::v1alpha1::InlineConnectionOrReference,

    /// IAM role to assume for S3 access.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iam_role: Option<String>,

    /// External ID for the IAM role trust policy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
}
