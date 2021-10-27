use std::num::ParseIntError;

use stackable_operator::{kube, product_config};

#[allow(clippy::enum_variant_names)]
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(
        "ConfigMap of type [{cm_type}] is for pod with generate_name [{pod_name}] is missing."
    )]
    MissingConfigMapError {
        cm_type: &'static str,
        pod_name: String,
    },

    #[error("ConfigMap of type [{cm_type}] is missing the metadata.name. Maybe the config map was not created yet?")]
    MissingConfigMapNameError { cm_type: &'static str },

    #[error("Kubernetes reported error: {source}")]
    KubeError {
        #[from]
        source: kube::Error,
    },

    #[error("Error from Operator framework: {source}")]
    OperatorError {
        #[from]
        source: stackable_operator::error::Error,
    },

    #[error("Error from serde_json: {source}")]
    SerdeError {
        #[from]
        source: serde_json::Error,
    },

    #[error("H contains invalid id: {source}")]
    InvalidId {
        #[from]
        source: ParseIntError,
    },

    #[error("Error from Hive: {source}")]
    HiveError {
        #[from]
        source: stackable_hive_crd::error::Error,
    },

    #[error("Error creating properties file")]
    PropertiesError(#[from] product_config::writer::PropertiesWriterError),

    #[error("ProductConfig Framework reported error: {source}")]
    ProductConfigError {
        #[from]
        source: product_config::error::Error,
    },

    #[error("Error from OPA: {source}")]
    OpaError {
        #[from]
        source: stackable_opa_crd::error::Error,
    },

    #[error("Operator Framework reported config error: {source}")]
    OperatorConfigError {
        #[from]
        source: stackable_operator::product_config_utils::ConfigError,
    },

    #[error("Crd crate reported error: {source}")]
    TrinoCrdError {
        #[from]
        source: stackable_trino_crd::error::Error,
    },

    #[error("No [{port}] port was found for coordinator when creating config maps. This is required for the [{discovery_property}] property. This is a bug, please open a ticket.")]
    TrinoCoordinatorMissingPortError {
        port: String,
        discovery_property: String,
    },
}
