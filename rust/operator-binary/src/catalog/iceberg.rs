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

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, str::FromStr};

    use indoc::formatdoc;
    use rstest::rstest;
    use stackable_operator::k8s_openapi::api::core::v1::{EnvVar, EnvVarSource};

    use super::*;

    const NO_VERIFICATION_TLS: &str = "tls: {verification: {none: {}}}";

    /// Builds the [`CatalogConfig`] of the catalog `my-iceberg` with the given REST catalog.
    /// The `-` in the catalog name checks that it is mapped to a valid env var name.
    fn rest_catalog_config(input: &str) -> Result<CatalogConfig, FromTrinoCatalogError> {
        let rest_catalog: IcebergRestCatalogConnection =
            stackable_operator::utils::yaml_from_str_singleton_map(input)
                .expect("the test input is a valid REST catalog");
        let catalog_name = TrinoCatalogName::from_str("my-iceberg").expect("valid catalog name");
        let mut catalog_config = CatalogConfig::new(&catalog_name, CONNECTOR_NAME);
        add_rest_catalog_config(&rest_catalog, &mut catalog_config, &catalog_name)?;
        Ok(catalog_config)
    }

    /// A REST catalog using a static OAuth2 token, with the given `tls` lines (may be empty) for
    /// the REST catalog and the OAuth2 server.
    fn oauth2_token_input(rest_tls: &str, server_tls: &str) -> String {
        formatdoc! {"
            hostname: rest-catalog
            {rest_tls}
            authentication:
              oAuth2:
                server:
                  hostname: idp.example.com
                  path: /oauth2/token
                  {server_tls}
                token:
                  secretName: iceberg-token
        "}
    }

    fn properties(catalog_config: &CatalogConfig) -> BTreeMap<&str, &str> {
        catalog_config
            .properties
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
            .collect()
    }

    fn env_from_secret(env_name: &str, secret_name: &str, key: &str) -> EnvVar {
        EnvVar {
            name: env_name.to_owned(),
            value_from: Some(EnvVarSource {
                secret_key_ref: Some(SecretKeySelector {
                    name: secret_name.to_owned(),
                    key: key.to_owned(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn no_authentication() {
        let catalog_config = rest_catalog_config("{hostname: rest-catalog, tls: null}")
            .expect("the catalog config builds");

        assert_eq!(
            properties(&catalog_config),
            BTreeMap::from([
                ("connector.name", "iceberg"),
                ("iceberg.catalog.type", "rest"),
                ("iceberg.rest-catalog.uri", "http://rest-catalog/"),
                ("iceberg.rest-catalog.security", "NONE"),
            ])
        );
        assert_eq!(catalog_config.env_bindings, Vec::new());
        assert_eq!(catalog_config.volumes, Vec::new());
        assert_eq!(
            catalog_config.init_container_extra_start_commands,
            Vec::<String>::new()
        );
    }

    #[rstest]
    #[case::default_scope("{secretName: iceberg-client}", None)]
    #[case::single_scope("{secretName: iceberg-client, scopes: [catalog]}", Some("catalog"))]
    #[case::multiple_scopes(
        "{secretName: iceberg-client, scopes: [lakehouse, catalog]}",
        Some("lakehouse catalog")
    )]
    fn client_credentials(#[case] credentials: &str, #[case] expected_scope: Option<&str>) {
        let catalog_config = rest_catalog_config(&formatdoc! {"
            hostname: rest-catalog
            authentication:
              oAuth2:
                server:
                  hostname: idp.example.com
                  path: /oauth2/token
                clientCredentials: {credentials}
        "})
        .expect("the catalog config builds");

        let mut expected_properties = BTreeMap::from([
            ("connector.name", "iceberg"),
            ("iceberg.catalog.type", "rest"),
            ("iceberg.rest-catalog.uri", "http://rest-catalog/"),
            ("iceberg.rest-catalog.security", "OAUTH2"),
            (
                "iceberg.rest-catalog.oauth2.server-uri",
                "http://idp.example.com/oauth2/token",
            ),
            (
                "iceberg.rest-catalog.oauth2.credential",
                "${ENV:CATALOG_MY_ICEBERG_ICEBERG_REST_CATALOG_OAUTH2_CREDENTIAL_CLIENT_ID}:${ENV:CATALOG_MY_ICEBERG_ICEBERG_REST_CATALOG_OAUTH2_CREDENTIAL_CLIENT_SECRET}",
            ),
        ]);
        if let Some(expected_scope) = expected_scope {
            expected_properties.insert("iceberg.rest-catalog.oauth2.scope", expected_scope);
        }
        assert_eq!(properties(&catalog_config), expected_properties);

        assert_eq!(
            catalog_config.env_bindings,
            vec![
                env_from_secret(
                    "CATALOG_MY_ICEBERG_ICEBERG_REST_CATALOG_OAUTH2_CREDENTIAL_CLIENT_ID",
                    "iceberg-client",
                    CLIENT_ID_SECRET_KEY,
                ),
                env_from_secret(
                    "CATALOG_MY_ICEBERG_ICEBERG_REST_CATALOG_OAUTH2_CREDENTIAL_CLIENT_SECRET",
                    "iceberg-client",
                    CLIENT_SECRET_SECRET_KEY,
                ),
            ]
        );
    }

    #[test]
    fn token() {
        let catalog_config =
            rest_catalog_config(&oauth2_token_input("", "")).expect("the catalog config builds");

        assert_eq!(
            properties(&catalog_config),
            BTreeMap::from([
                ("connector.name", "iceberg"),
                ("iceberg.catalog.type", "rest"),
                ("iceberg.rest-catalog.uri", "http://rest-catalog/"),
                ("iceberg.rest-catalog.security", "OAUTH2"),
                (
                    "iceberg.rest-catalog.oauth2.server-uri",
                    "http://idp.example.com/oauth2/token",
                ),
                (
                    "iceberg.rest-catalog.oauth2.token",
                    "${ENV:CATALOG_MY_ICEBERG_ICEBERG_REST_CATALOG_OAUTH2_TOKEN}",
                ),
            ])
        );
        assert_eq!(
            catalog_config.env_bindings,
            vec![env_from_secret(
                "CATALOG_MY_ICEBERG_ICEBERG_REST_CATALOG_OAUTH2_TOKEN",
                "iceberg-token",
                "token",
            )]
        );
    }

    #[rstest]
    #[case::rest_catalog(NO_VERIFICATION_TLS, "")]
    #[case::oauth2_server("", NO_VERIFICATION_TLS)]
    fn disabled_tls_verification_is_rejected(#[case] rest_tls: &str, #[case] server_tls: &str) {
        let result = rest_catalog_config(&oauth2_token_input(rest_tls, server_tls));

        assert!(
            matches!(
                result,
                Err(FromTrinoCatalogError::IcebergRestTlsNoVerificationNotSupported)
            ),
            "expected IcebergRestTlsNoVerificationNotSupported, got: {result:?}"
        );
    }
}
