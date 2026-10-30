use snafu::Snafu;
use stackable_operator::commons::tls_verification::{
    CaCert, TlsClientDetails, TlsServerVerification, TlsVerification,
};

use crate::{controller::build::command, crd::STACKABLE_CLIENT_TLS_DIR};

#[derive(Snafu, Debug)]
pub enum Error {
    /// Returned by [`tls_truststore_commands`] when a connection disables TLS verification, which
    /// Trino does not support for its HTTP and S3 clients.
    #[snafu(display("disabling the TLS verification is not supported"))]
    TlsVerificationDisabled,
}

/// Build the init-container commands that add a server's CA certificate to the client truststore
/// (the JVM default truststore, see `config::jvm`).
///
/// Returns an empty list when no extra trust setup is needed (TLS disabled, or WebPKI
/// verification), and [`Error::TlsVerificationDisabled`] when TLS verification is turned off: the
/// connection would still use `https`, but the client has no way to skip the certificate check,
/// so the handshake would fail at runtime. Shared by the S3 connections (spooling/exchange and
/// catalogs) and the OpenLineage backend connection.
pub fn tls_truststore_commands(tls: &TlsClientDetails) -> Result<Vec<String>, Error> {
    let Some(tls_config) = tls.tls.as_ref() else {
        return Ok(Vec::new());
    };
    match &tls_config.verification {
        TlsVerification::None {} => Err(Error::TlsVerificationDisabled),
        TlsVerification::Server(TlsServerVerification {
            ca_cert: CaCert::WebPki {},
        }) => Ok(Vec::new()),
        TlsVerification::Server(TlsServerVerification {
            ca_cert: CaCert::SecretClass(_),
        }) => Ok(tls
            .tls_ca_cert_mount_path()
            .map(|ca_cert| command::add_cert_to_truststore(&ca_cert, STACKABLE_CLIENT_TLS_DIR))
            .unwrap_or_default()),
    }
}

#[cfg(test)]
mod tests {
    use stackable_operator::commons::tls_verification::Tls;

    use super::*;

    fn tls_details(verification: Option<TlsVerification>) -> TlsClientDetails {
        TlsClientDetails {
            tls: verification.map(|verification| Tls { verification }),
        }
    }

    #[test]
    fn no_tls_yields_no_truststore_commands() {
        assert!(
            tls_truststore_commands(&tls_details(None))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn webpki_verification_yields_no_truststore_commands() {
        let details = tls_details(Some(TlsVerification::Server(TlsServerVerification {
            ca_cert: CaCert::WebPki {},
        })));
        assert!(tls_truststore_commands(&details).unwrap().is_empty());
    }

    #[test]
    fn secret_class_verification_yields_truststore_commands() {
        let details = tls_details(Some(TlsVerification::Server(TlsServerVerification {
            ca_cert: CaCert::SecretClass("tls".to_string()),
        })));
        assert!(!tls_truststore_commands(&details).unwrap().is_empty());
    }

    #[test]
    fn disabled_verification_is_rejected() {
        let details = tls_details(Some(TlsVerification::None {}));
        assert!(tls_truststore_commands(&details).is_err());
    }
}
