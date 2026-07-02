use std::{collections::BTreeMap, str::FromStr};

use stackable_operator::{
    client::Client,
    commons::opa::OpaApiVersion,
    k8s_openapi::api::core::v1::ConfigMap,
    v2::types::kubernetes::{NamespaceName, SecretClassName, VolumeName},
};

use crate::crd::v1alpha1;

stackable_operator::constant!(pub OPA_TLS_VOLUME_NAME: VolumeName = "opa-tls");

#[derive(Clone, Debug)]
pub struct TrinoOpaConfig {
    /// URI for OPA policies, e.g.
    /// `http://localhost:8081/v1/data/trino/allow`
    pub(crate) non_batched_connection_string: String,
    /// URI for Batch OPA policies, e.g.
    /// `http://localhost:8081/v1/data/trino/batch` - if not set, a
    /// single request will be sent for each entry on filtering methods
    pub(crate) batched_connection_string: String,
    /// URI for fetching row filters, e.g.
    /// `http://localhost:8081/v1/data/trino/rowFilters` - if not set,
    /// no row filtering will be applied
    pub(crate) row_filters_connection_string: Option<String>,
    /// URI for fetching columns masks in batches, e.g.
    /// `http://localhost:8081/v1/data/trino/batchColumnMasks` - if not set,
    /// no masking will be applied
    pub(crate) batched_column_masking_connection_string: Option<String>,
    /// Whether to allow permission management (GRANT, DENY, ...) and
    /// role management operations - OPA will not be queried for any
    /// such operations, they will be bulk allowed or denied depending
    /// on this setting
    pub(crate) allow_permission_management_operations: bool,
    /// Optional TLS secret class for OPA communication.
    /// If set, the CA certificate from this secret class will be added
    /// to Trino's truststore to make it trust OPA's TLS certificate.
    pub(crate) tls_secret_class: Option<SecretClassName>,
}

impl TrinoOpaConfig {
    pub async fn from_opa_config(
        client: &Client,
        trino: &v1alpha1::TrinoCluster,
        namespace: &NamespaceName,
        opa_config: &v1alpha1::TrinoAuthorizationOpaConfig,
    ) -> Result<Self, stackable_operator::commons::opa::Error> {
        let non_batched_connection_string = opa_config
            .opa
            .full_document_url_from_config_map(client, trino, Some("allow"), &OpaApiVersion::V1)
            .await?;
        let batched_connection_string = opa_config
            .opa
            .full_document_url_from_config_map(
                client,
                trino,
                // Sticking to example https://trino.io/docs/current/security/opa-access-control.html
                Some("batch"),
                &OpaApiVersion::V1,
            )
            .await?;
        let row_filters_connection_string = opa_config
            .opa
            .full_document_url_from_config_map(
                client,
                trino,
                // Sticking to https://github.com/trinodb/trino/blob/455/plugin/trino-opa/src/test/java/io/trino/plugin/opa/TestOpaAccessControlDataFilteringSystem.java#L46
                Some("rowFilters"),
                &OpaApiVersion::V1,
            )
            .await?;

        let batched_column_masking_connection_string = if opa_config.enable_column_masking {
            Some(
                opa_config
                    .opa
                    .full_document_url_from_config_map(
                        client,
                        trino,
                        // Sticking to https://github.com/trinodb/trino/blob/455/plugin/trino-opa/src/test/java/io/trino/plugin/opa/TestOpaAccessControlDataFilteringSystem.java#L48
                        Some("batchColumnMasks"),
                        &OpaApiVersion::V1,
                    )
                    .await?,
            )
        } else {
            None
        };

        let tls_secret_class = client
            .get::<ConfigMap>(&opa_config.opa.config_map_name, namespace.as_ref())
            .await
            .ok()
            .and_then(|cm| cm.data)
            .and_then(|mut data| data.remove("OPA_SECRET_CLASS"))
            .and_then(|secret_class| SecretClassName::from_str(&secret_class).ok());

        Ok(TrinoOpaConfig {
            non_batched_connection_string,
            batched_connection_string,
            row_filters_connection_string: Some(row_filters_connection_string),
            batched_column_masking_connection_string,
            allow_permission_management_operations: true,
            tls_secret_class,
        })
    }

    pub fn as_config(&self) -> BTreeMap<String, String> {
        let mut config = BTreeMap::from([
            ("access-control.name".to_string(), "opa".to_string()),
            (
                "opa.policy.uri".to_string(),
                self.non_batched_connection_string.clone(),
            ),
            (
                "opa.policy.batched-uri".to_string(),
                self.batched_connection_string.clone(),
            ),
        ]);
        if let Some(row_filters_connection_string) = &self.row_filters_connection_string {
            config.insert(
                "opa.policy.row-filters-uri".to_string(),
                row_filters_connection_string.clone(),
            );
        }
        if let Some(batched_column_masking_connection_string) =
            &self.batched_column_masking_connection_string
        {
            config.insert(
                "opa.policy.batch-column-masking-uri".to_string(),
                batched_column_masking_connection_string.clone(),
            );
        }
        if self.allow_permission_management_operations {
            config.insert(
                "opa.allow-permission-management-operations".to_string(),
                "true".to_string(),
            );
        }
        config
    }

    pub fn tls_mount_path(&self) -> Option<String> {
        self.tls_secret_class.as_ref().map(|_| {
            format!(
                "/stackable/secrets/{opa_tls_volume_name}",
                opa_tls_volume_name = &*OPA_TLS_VOLUME_NAME
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_opa() -> TrinoOpaConfig {
        TrinoOpaConfig {
            non_batched_connection_string: "http://opa/allow".to_string(),
            batched_connection_string: "http://opa/batch".to_string(),
            row_filters_connection_string: None,
            batched_column_masking_connection_string: None,
            allow_permission_management_operations: false,
            tls_secret_class: None,
        }
    }

    #[test]
    fn as_config_renders_only_required_keys_when_optionals_are_unset() {
        let config = minimal_opa().as_config();

        assert_eq!(
            config.get("access-control.name").map(String::as_str),
            Some("opa")
        );
        assert_eq!(
            config.get("opa.policy.uri").map(String::as_str),
            Some("http://opa/allow")
        );
        assert_eq!(
            config.get("opa.policy.batched-uri").map(String::as_str),
            Some("http://opa/batch")
        );
        assert!(!config.contains_key("opa.policy.row-filters-uri"));
        assert!(!config.contains_key("opa.policy.batch-column-masking-uri"));
        assert!(!config.contains_key("opa.allow-permission-management-operations"));
    }

    #[test]
    fn as_config_renders_optional_keys_when_set() {
        let config = TrinoOpaConfig {
            row_filters_connection_string: Some("http://opa/rowFilters".to_string()),
            batched_column_masking_connection_string: Some(
                "http://opa/batchColumnMasks".to_string(),
            ),
            allow_permission_management_operations: true,
            ..minimal_opa()
        }
        .as_config();

        assert_eq!(
            config.get("opa.policy.row-filters-uri").map(String::as_str),
            Some("http://opa/rowFilters")
        );
        assert_eq!(
            config
                .get("opa.policy.batch-column-masking-uri")
                .map(String::as_str),
            Some("http://opa/batchColumnMasks")
        );
        assert_eq!(
            config
                .get("opa.allow-permission-management-operations")
                .map(String::as_str),
            Some("true")
        );
    }
}
