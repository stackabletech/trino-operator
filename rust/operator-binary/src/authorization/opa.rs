use std::collections::BTreeMap;

use stackable_operator::{
    client::Client,
    commons::{
        opa::{OpaApiVersion, OpaConfig},
        product_image_selection::ResolvedProductImage,
    },
    error::OperatorResult,
};
use stackable_trino_crd::TrinoCluster;

const PRODUCT_VERSIONS_WITH_OLD_AUTHORIZER: [&str; 5] = ["377", "387", "395", "396", "403"];

pub struct TrinoOpaConfig {
    opa_authorizer_name: String,
    non_batched_connection_string: String,
    batched_connection_string: Option<String>,
}

impl TrinoOpaConfig {
    pub async fn from_opa_config(
        client: &Client,
        trino: &TrinoCluster,
        resolved_product_image: &ResolvedProductImage,
        opa_config: &OpaConfig,
    ) -> OperatorResult<Self> {
        if PRODUCT_VERSIONS_WITH_OLD_AUTHORIZER
            .contains(&resolved_product_image.product_version.as_str())
        {
            // TODO: Can be removed after 23.11 has been released,
            // as support for these versions will be marked deprecated in 23.7.
            // Please also change `TrinoOpaConfig::batched_connection_string` to `String`
            // and remove `TrinoOpaConfig::opa_authorizer_name`!
            let non_batched_connection_string = opa_config
                .full_document_url_from_config_map(client, trino, Some("allow"), OpaApiVersion::V1)
                .await?;
            Ok(TrinoOpaConfig {
                opa_authorizer_name: "tech.stackable.trino.opa.OpaAuthorizer".to_string(),
                non_batched_connection_string,
                batched_connection_string: None,
            })
        } else {
            let non_batched_connection_string = opa_config
                .full_document_url_from_config_map(client, trino, Some("allow"), OpaApiVersion::V1)
                .await?;
            let batched_connection_string = opa_config
                .full_document_url_from_config_map(
                    client,
                    trino,
                    Some("extended"),
                    OpaApiVersion::V1,
                )
                .await?;
            Ok(TrinoOpaConfig {
                opa_authorizer_name: "opa".to_string(),
                non_batched_connection_string,
                batched_connection_string: Some(batched_connection_string),
            })
        }
    }

    pub fn as_config(&self) -> BTreeMap<String, Option<String>> {
        let mut config = BTreeMap::from([
            (
                "access-control.name".to_string(),
                Some(self.opa_authorizer_name.to_string()),
            ),
            (
                "opa.policy.uri".to_string(),
                Some(self.non_batched_connection_string.clone()),
            ),
        ]);
        if let Some(batched_connection_string) = &self.batched_connection_string {
            config.insert(
                "opa.policy.batched-uri".to_string(),
                Some(batched_connection_string.clone()),
            );
        }
        config
    }
}
