use serde::{Deserialize, Serialize};
use snafu::{ResultExt, Snafu};
use stackable_operator::{
    commons::{networking::HostName, tls_verification::TlsClientDetailsWithSecureDefaults},
    schemars::{self, JsonSchema},
    v2::types::kubernetes::SecretName,
};
use url::Url;

use super::commons::HiveMetastoreConnection;

#[derive(Debug, Snafu)]
pub enum HttpEndpointError {
    #[snafu(display("failed to parse endpoint URL {endpoint:?}"))]
    ParseEndpointUrl {
        source: url::ParseError,
        endpoint: String,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum IcebergCatalogConnection {
    /// (Recommended) use a REST catalog to store metadata.
    Rest(IcebergRestCatalogConnection),

    /// Use a Hive metastore to store metadata.
    HiveMetastore(HiveMetastoreConnection),

    /// The operator doesn't configure any catalog, the user needs to do that,
    /// e.g. using `configOverrides`.
    UserProvided {},
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IcebergRestCatalogConnection {
    /// The endpoint of the REST catalog server.
    #[serde(flatten)]
    pub endpoint: HttpEndpoint,

    /// How to authenticate against the REST catalog.
    #[serde(default)]
    pub authentication: IcebergRestCatalogAuthentication,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum IcebergRestCatalogAuthentication {
    /// Don't authenticate against the REST catalog (chosen by default).
    None {},

    /// Use OAuth2 to authenticate against the REST catalog.
    ///
    /// Note that we only support configuring a subset of Trino's properties, you might need to use
    /// `configOverrides` to be able to set all [available properties](https://trino.io/docs/current/object-storage/metastores.html#iceberg-specific-metastores).
    #[serde(rename_all = "camelCase")]
    OAuth2 {
        /// The OAuth2 server endpoint, which needs to point to the token endpoint.
        /// It is used to
        ///
        /// * fetch a token using the client credentials (`clientCredentialsSecretName`) and
        /// * refresh the token before it expires. A static token (`tokenSecretName`) is only
        ///   refreshed if it is a JWT with an `exp` claim, otherwise the endpoint is never called.
        ///
        /// It is required nevertheless, as without it the Iceberg client would fall back to the
        /// deprecated `/v1/oauth/tokens` endpoint of the REST catalog, which is planned to be
        /// removed (see <https://github.com/apache/iceberg/issues/10537>).
        server: HttpEndpoint,

        // No docs will show up.
        #[serde(flatten)]
        credential: IcebergRestCatalogOAuthCredential,
    },
}

impl Default for IcebergRestCatalogAuthentication {
    fn default() -> Self {
        Self::None {}
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum IcebergRestCatalogOAuthCredential {
    /// Authenticate using a bearer token.
    /// Mutually exclusive with `clientCredentialsSecretName`.
    ///
    /// The Secret needs to contain the `token` key.
    TokenSecretName(SecretName),

    /// The credentials to exchange for a token in the OAuth2 client credentials flow with the server.
    /// Mutually exclusive with `tokenSecretName`.
    ///
    /// The Secret needs to contain the `clientId` and `clientSecret` keys.
    ClientCredentialsSecretName(SecretName),
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HttpEndpoint {
    /// Hostname of the server without any protocol, port or path.
    /// For example: `iceberg-rest-catalog.example.com`.
    pub hostname: HostName,

    /// Port the server listens on.
    /// Defaults to 443 if TLS is used and to 80 otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,

    /// Path of the endpoint on the server, e.g. `/catalog`. Defaults to `/`.
    #[serde(default = "HttpEndpoint::default_path")]
    pub path: String,

    /// Configure a TLS connection. If not specified, it defaults to webPki verification.
    /// Set it to `null` to not use TLS.
    #[serde(flatten)]
    pub tls: TlsClientDetailsWithSecureDefaults,
}

impl HttpEndpoint {
    /// Builds the endpoint [`Url`], with trailing slashes removed from the configured path.
    pub fn url(&self) -> Result<Url, HttpEndpointError> {
        let endpoint = format!(
            "{scheme}://{host}:{port}",
            scheme = if self.tls.uses_tls() { "https" } else { "http" },
            host = self.hostname.as_url_host(),
            port = self.port()
        );
        let mut url = Url::parse(&endpoint).context(ParseEndpointUrlSnafu { endpoint })?;

        // Same as for OIDC, as some tools can not cope with a trailing slash
        url.set_path(self.path.trim_end_matches('/'));

        Ok(url)
    }

    /// Returns the port to be used, which is either user configured or defaulted based upon TLS usage
    pub fn port(&self) -> u16 {
        self.port
            .unwrap_or_else(|| if self.tls.uses_tls() { 443 } else { 80 })
    }

    fn default_path() -> String {
        "/".to_owned()
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case::defaults("hostname: rest-catalog", "https://rest-catalog/")]
    #[case::without_tls("{hostname: rest-catalog, tls: null}", "http://rest-catalog/")]
    #[case::explicit_web_pki(
        "{hostname: rest-catalog, tls: {verification: {server: {caCert: {webPki: {}}}}}}",
        "https://rest-catalog/"
    )]
    #[case::port_and_path_without_tls(
        "{hostname: rest-catalog, port: 9001, path: /catalog, tls: null}",
        "http://rest-catalog:9001/catalog"
    )]
    #[case::port_and_path_with_tls(
        "{hostname: rest-catalog, port: 8443, path: /catalog, tls: {verification: {server: {caCert: {secretClass: tls}}}}}",
        "https://rest-catalog:8443/catalog"
    )]
    #[case::trailing_slashes(
        "{hostname: idp.example.com, path: /realms/test/protocol/openid-connect/token//}",
        "https://idp.example.com/realms/test/protocol/openid-connect/token"
    )]
    #[case::ipv6("{hostname: '::1', port: 9001}", "https://[::1]:9001/")]
    fn http_endpoint_url(#[case] input: &str, #[case] expected: &str) {
        let endpoint: HttpEndpoint =
            stackable_operator::utils::yaml_from_str_singleton_map(input).unwrap();
        assert_eq!(endpoint.url().unwrap().as_str(), expected);
    }
}
