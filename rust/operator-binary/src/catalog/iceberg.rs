use async_trait::async_trait;
use snafu::ResultExt;
use stackable_operator::{
    client::Client,
    crd::authentication::oidc::{CLIENT_ID_SECRET_KEY, CLIENT_SECRET_SECRET_KEY},
    k8s_openapi::api::core::v1::SecretKeySelector,
    v2::types::kubernetes::NamespaceName,
};

use crate::{
    catalog::{
        ExtendCatalogConfig, FromTrinoCatalogError, ToCatalogConfig,
        config::{CatalogConfig, calculate_env_name},
        from_trino_catalog_error::{
            BuildIcebergRestUrlSnafu, ConfigureIcebergRestTlsSnafu,
            IcebergRestTlsNoVerificationNotSupportedSnafu,
        },
    },
    config,
    crd::catalog::{
        TrinoCatalogName,
        iceberg::{
            HttpEndpoint, IcebergCatalogConnection, IcebergRestCatalogAuthentication,
            IcebergRestCatalogConnection, IcebergRestCatalogOAuthCredential,
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
        add_rest_catalog_config(self, catalog_config, catalog_name)
    }
}

/// Adds the configuration of the given REST catalog. Split out of
/// [`ExtendCatalogConfig::extend_catalog_config`], as it doesn't need a [`Client`], which makes it
/// testable.
fn add_rest_catalog_config(
    rest_catalog: &IcebergRestCatalogConnection,
    catalog_config: &mut CatalogConfig,
    catalog_name: &TrinoCatalogName,
) -> Result<(), FromTrinoCatalogError> {
    catalog_config.add_property("iceberg.catalog.type", "rest");
    catalog_config.add_property(
        "iceberg.rest-catalog.uri",
        rest_catalog
            .endpoint
            .url()
            .context(BuildIcebergRestUrlSnafu)?,
    );
    add_endpoint_tls(catalog_config, &rest_catalog.endpoint)?;

    // We explicitly use a match here to catch further additions
    match &rest_catalog.authentication {
        IcebergRestCatalogAuthentication::None {} => {
            catalog_config.add_property("iceberg.rest-catalog.security", "NONE");
        }
        IcebergRestCatalogAuthentication::OAuth2 { server, credential } => {
            catalog_config.add_property("iceberg.rest-catalog.security", "OAUTH2");
            catalog_config.add_property(
                "iceberg.rest-catalog.oauth2.server-uri",
                server.url().context(BuildIcebergRestUrlSnafu)?,
            );
            add_endpoint_tls(catalog_config, server)?;
            match credential {
                IcebergRestCatalogOAuthCredential::ClientCredentials {
                    secret_name,
                    scopes,
                } => {
                    // We can't use `add_env_property_from_secret`, as we need to concatenate
                    // clientId and clientSecret in the Trino configuration. So instead we come
                    // up with our own envs and bind them.
                    let property = "iceberg.rest-catalog.oauth2.credential";
                    let base_env_name = calculate_env_name(catalog_name, property);
                    let client_id_env_name = format!("{base_env_name}_CLIENT_ID");
                    let client_secret_env_name = format!("{base_env_name}_CLIENT_SECRET");
                    catalog_config.add_property(
                        property,
                        format!("${{ENV:{client_id_env_name}}}:${{ENV:{client_secret_env_name}}}"),
                    );

                    catalog_config.add_env_from_secret(
                        client_id_env_name,
                        SecretKeySelector {
                            name: secret_name.to_string(),
                            key: CLIENT_ID_SECRET_KEY.to_owned(),
                            ..Default::default()
                        },
                    );
                    catalog_config.add_env_from_secret(
                        client_secret_env_name,
                        SecretKeySelector {
                            name: secret_name.to_string(),
                            key: CLIENT_SECRET_SECRET_KEY.to_owned(),
                            ..Default::default()
                        },
                    );

                    // Trino only accepts a scope in combination with client credentials.
                    // OAuth2 (and the Iceberg client) separate multiple scopes by spaces.
                    if !scopes.is_empty() {
                        catalog_config
                            .add_property("iceberg.rest-catalog.oauth2.scope", scopes.join(" "));
                    }
                }
                IcebergRestCatalogOAuthCredential::Token { secret_name } => catalog_config
                    .add_env_property_from_secret(
                        "iceberg.rest-catalog.oauth2.token",
                        SecretKeySelector {
                            name: secret_name.to_string(),
                            key: "token".to_owned(),
                            ..Default::default()
                        },
                    ),
            }
        }
    }

    Ok(())
}

/// Adds the CA certificate of the given endpoint (if any) to the truststore of Trino.
fn add_endpoint_tls(
    catalog_config: &mut CatalogConfig,
    endpoint: &HttpEndpoint,
) -> Result<(), FromTrinoCatalogError> {
    let (volumes, mounts) = endpoint
        .tls
        .volumes_and_mounts()
        .context(ConfigureIcebergRestTlsSnafu)?;
    catalog_config.volumes.extend(volumes);
    catalog_config.volume_mounts.extend(mounts);

    catalog_config.init_container_extra_start_commands.extend(
        config::tls::tls_truststore_commands(&endpoint.tls)
            .map_err(|_| IcebergRestTlsNoVerificationNotSupportedSnafu.build())?,
    );

    Ok(())
}
