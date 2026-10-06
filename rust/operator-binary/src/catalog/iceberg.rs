use async_trait::async_trait;
use stackable_operator::{
    client::Client,
    k8s_openapi::api::core::v1::{EnvVar, EnvVarSource, SecretKeySelector},
    v2::types::kubernetes::NamespaceName,
};

use crate::{
    catalog::{
        ExtendCatalogConfig, FromTrinoCatalogError, ToCatalogConfig,
        config::{CatalogConfig, calculate_env_name},
    },
    crd::catalog::{
        TrinoCatalogName,
        iceberg::{
            IcebergCatalogConnection, IcebergRestCatalogConnection,
            IcebergRestCatalogOAuthCredential, IcebergRestCatalogSecurity,
        },
        v1alpha2::IcebergConnector,
    },
};

pub const CONNECTOR_NAME: &str = "iceberg";

#[async_trait]
impl ToCatalogConfig for IcebergConnector {
    async fn to_catalog_config(
        &self,
        catalog_name: &TrinoCatalogName,
        catalog_namespace: &NamespaceName,
        client: &Client,
    ) -> Result<CatalogConfig, FromTrinoCatalogError> {
        let mut config = CatalogConfig::new(catalog_name, CONNECTOR_NAME);

        // No authorization checks are enforced at the catalog level.
        // We don't want the iceberg connector to prevent users from dropping tables.
        // We also don't want that the iceberg connector makes decisions on which user is allowed to do what.
        // This decision should be done globally (for all catalogs) by OPA.
        // See https://trino.io/docs/current/connector/iceberg.html
        config.add_property("iceberg.security", "allow-all");

        match &self.catalog {
            IcebergCatalogConnection::Rest(iceberg_rest_catalog_connection) => {
                iceberg_rest_catalog_connection
                    .extend_catalog_config(&mut config, catalog_name, catalog_namespace, client)
                    .await?;
            }
            IcebergCatalogConnection::HiveMetastore(hive_metastore_connection) => {
                hive_metastore_connection
                    .extend_catalog_config(&mut config, catalog_name, catalog_namespace, client)
                    .await?;
            }
            IcebergCatalogConnection::UserProvided {} => {
                // Nothing to do, the user will set it up
            }
        }

        if let Some(ref s3) = self.s3 {
            s3.extend_catalog_config(&mut config, catalog_name, catalog_namespace, client)
                .await?;
        }

        if let Some(ref hdfs) = self.hdfs {
            hdfs.extend_catalog_config(&mut config, catalog_name, catalog_namespace, client)
                .await?;
        }

        Ok(config)
    }
}

#[async_trait]
impl ExtendCatalogConfig for IcebergRestCatalogConnection {
    async fn extend_catalog_config(
        &self,
        catalog_config: &mut CatalogConfig,
        catalog_name: &TrinoCatalogName,
        _catalog_namespace: &NamespaceName,
        _client: &Client,
    ) -> Result<(), FromTrinoCatalogError> {
        catalog_config.add_property("iceberg.catalog.type", "rest");
        catalog_config.add_property("iceberg.rest-catalog.uri", self.uri.as_str());

        // We explicitly use a match here to catch further additions
        match &self.security {
            IcebergRestCatalogSecurity::None {} => {
                catalog_config.add_property("iceberg.rest-catalog.security", "NONE");
            }
            IcebergRestCatalogSecurity::OAuth2 {
                server_uri,
                credential,
            } => {
                catalog_config.add_property("iceberg.rest-catalog.security", "OAUTH2");
                catalog_config.add_property(
                    "iceberg.rest-catalog.oauth2.server-uri",
                    server_uri.as_str(),
                );
                match credential {
                    IcebergRestCatalogOAuthCredential::TokenSecretName(secret_name) => {
                        // We can't use `add_env_property_from_secret`, as we need to concatenate
                        // user and password in the Trino configuration. So instead we come up with
                        // our own envs and bind them.
                        let property = "iceberg.rest-catalog.oauth2.credential";
                        let base_env_name = calculate_env_name(catalog_name, property);
                        let username_env_name = format!("{base_env_name}_USERNAME");
                        let password_env_name = format!("{base_env_name}_PASSWORD");
                        catalog_config.add_property(
                            property,
                            format!("${{ENV:{username_env_name}}}:${{ENV:{password_env_name}}}"),
                        );

                        catalog_config.env_bindings.push(EnvVar {
                            name: username_env_name,
                            value_from: Some(EnvVarSource {
                                secret_key_ref: Some(SecretKeySelector {
                                    name: secret_name.to_owned(),
                                    key: "username".to_owned(),
                                    ..Default::default()
                                }),
                                ..Default::default()
                            }),
                            ..Default::default()
                        });
                        catalog_config.env_bindings.push(EnvVar {
                            name: password_env_name,
                            value_from: Some(EnvVarSource {
                                secret_key_ref: Some(SecretKeySelector {
                                    name: secret_name.to_owned(),
                                    key: "password".to_owned(),
                                    ..Default::default()
                                }),
                                ..Default::default()
                            }),
                            ..Default::default()
                        });
                    }
                    IcebergRestCatalogOAuthCredential::CredentialSecretName(secret_name) => {
                        catalog_config.add_env_property_from_secret(
                            "iceberg.rest-catalog.oauth2.token",
                            SecretKeySelector {
                                name: secret_name.to_owned(),
                                key: "token".to_owned(),
                                ..Default::default()
                            },
                        )
                    }
                }
            }
        }

        Ok(())
    }
}
