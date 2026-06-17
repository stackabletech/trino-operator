//! The client-facing port Trino exposes, derived from the validated TLS configuration.
//!
//! Mapping the server-TLS flag onto a concrete port number / name is a resource-shaping decision,
//! so it lives in the build step rather than on [`ValidatedCluster`].

use crate::{
    controller::ValidatedCluster,
    crd::{HTTP_PORT, HTTP_PORT_NAME, HTTPS_PORT, HTTPS_PORT_NAME},
};

/// The client-facing port Trino exposes: HTTPS when server TLS is enabled, otherwise HTTP.
pub(crate) fn exposed_port(cluster: &ValidatedCluster) -> u16 {
    if cluster.server_tls_enabled() {
        HTTPS_PORT
    } else {
        HTTP_PORT
    }
}

/// The name of the client-facing port (see [`exposed_port`]).
pub(crate) fn exposed_protocol(cluster: &ValidatedCluster) -> &'static str {
    if cluster.server_tls_enabled() {
        HTTPS_PORT_NAME
    } else {
        HTTP_PORT_NAME
    }
}
