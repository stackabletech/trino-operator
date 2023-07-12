// // Assemble the OPA connection string from the discovery and the given path if provided
// let opa_connect_string = if let Some(opa_config) = trino
//     .spec
//     .cluster_config
//     .authorization
//     .as_ref()
//     .and_then(|authz| authz.opa.as_ref())
// {
//     Some(
//         opa_config
//             .full_document_url_from_config_map(
//                 client,
//                 &*trino,
//                 Some("allow"),
//                 OpaApiVersion::V1,
//             )
//             .await
//             .context(InvalidOpaConfigSnafu)?,
//     )
// } else {
//     None
// };

use std::collections::BTreeMap;

use stackable_operator::{
    client::Client,
    commons::opa::{OpaApiVersion, OpaConfig},
    error::OperatorResult,
};
use stackable_trino_crd::TrinoCluster;

pub struct TrinoOpaConfig {
    not_batched_connection_string: String,
    batched_connection_string: String,
}

impl TrinoOpaConfig {
    pub async fn from_opa_config(
        client: &Client,
        trino: &TrinoCluster,
        opa_config: &OpaConfig,
    ) -> OperatorResult<Self> {
        let not_batched_connection_string = opa_config
            .full_document_url_from_config_map(client, trino, Some("allow"), OpaApiVersion::V1)
            .await?;
        let batched_connection_string = opa_config
            .full_document_url_from_config_map(client, trino, Some("extended"), OpaApiVersion::V1)
            .await?;
        Ok(TrinoOpaConfig {
            not_batched_connection_string,
            batched_connection_string,
        })
    }

    pub fn as_config(&self) -> BTreeMap<String, Option<String>> {
        BTreeMap::from([
            ("access-control.name".to_string(), Some("opa".to_string())),
            (
                "opa.policy.uri".to_string(),
                Some(self.not_batched_connection_string.clone()),
            ),
            (
                "opa.policy.batched-uri".to_string(),
                Some(self.batched_connection_string.clone()),
            ),
        ])
    }
}
