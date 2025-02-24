use std::collections::BTreeMap;

use stackable_operator::{
    client::Client,
    commons::opa::{OpaApiVersion, OpaConfig},
};

use crate::crd::TrinoCluster;

pub struct TrinoOpaConfig {
    /// URI for OPA policies, e.g.
    /// `http://localhost:8081/v1/data/trino/allow`
    non_batched_connection_string: String,
    /// URI for Batch OPA policies, e.g.
    /// `http://localhost:8081/v1/data/trino/batch` - if not set, a
    /// single request will be sent for each entry on filtering methods
    batched_connection_string: String,
    /// URI for fetching row filters, e.g.
    /// `http://localhost:8081/v1/data/trino/rowFilters` - if not set,
    /// no row filtering will be applied
    row_filters_connection_string: Option<String>,
    /// URI for fetching column masks, e.g.
    /// `http://localhost:8081/v1/data/trino/columnMask` - if not set,
    /// no masking will be applied
    column_masking_connection_string: Option<String>,
    /// Whether to allow permission management (GRANT, DENY, ...) and
    /// role management operations - OPA will not be queried for any
    /// such operations, they will be bulk allowed or denied depending
    /// on this setting
    allow_permission_management_operations: bool,
}

impl TrinoOpaConfig {
    pub async fn from_opa_config(
        client: &Client,
        trino: &TrinoCluster,
        opa_config: &OpaConfig,
    ) -> Result<Self, stackable_operator::commons::opa::Error> {
        let non_batched_connection_string = opa_config
            .full_document_url_from_config_map(client, trino, Some("allow"), OpaApiVersion::V1)
            .await?;
        let batched_connection_string = opa_config
            .full_document_url_from_config_map(
                client,
                trino,
                // Sticking to example https://trino.io/docs/current/security/opa-access-control.html
                Some("batch"),
                OpaApiVersion::V1,
            )
            .await?;
        let row_filters_connection_string = opa_config
            .full_document_url_from_config_map(
                client,
                trino,
                // Sticking to https://github.com/trinodb/trino/blob/455/plugin/trino-opa/src/test/java/io/trino/plugin/opa/TestOpaAccessControlDataFilteringSystem.java#L46
                Some("rowFilters"),
                OpaApiVersion::V1,
            )
            .await?;
        let column_masking_connection_string = opa_config
            .full_document_url_from_config_map(
                client,
                trino,
                // Sticking to https://github.com/trinodb/trino/blob/455/plugin/trino-opa/src/test/java/io/trino/plugin/opa/TestOpaAccessControlDataFilteringSystem.java#L47
                Some("columnMask"),
                OpaApiVersion::V1,
            )
            .await?;
        Ok(TrinoOpaConfig {
            non_batched_connection_string,
            batched_connection_string,
            row_filters_connection_string: Some(row_filters_connection_string),
            column_masking_connection_string: Some(column_masking_connection_string),
            allow_permission_management_operations: true,
        })
    }

    pub fn as_config(&self) -> BTreeMap<String, Option<String>> {
        let mut config = BTreeMap::from([
            ("access-control.name".to_string(), Some("opa".to_string())),
            (
                "opa.policy.uri".to_string(),
                Some(self.non_batched_connection_string.clone()),
            ),
            (
                "opa.policy.batched-uri".to_string(),
                Some(self.batched_connection_string.clone()),
            ),
        ]);
        if let Some(row_filters_connection_string) = &self.row_filters_connection_string {
            config.insert(
                "opa.policy.row-filters-uri".to_string(),
                Some(row_filters_connection_string.clone()),
            );
        }
        if let Some(column_masking_connection_string) = &self.column_masking_connection_string {
            config.insert(
                "opa.policy.column-masking-uri".to_string(),
                Some(column_masking_connection_string.clone()),
            );
        }
        if self.allow_permission_management_operations {
            config.insert(
                "opa.allow-permission-management-operations".to_string(),
                Some("true".to_string()),
            );
        }
        config
    }
}
