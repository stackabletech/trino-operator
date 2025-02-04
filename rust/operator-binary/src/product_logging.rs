use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::{
    client::Client,
    k8s_openapi::api::core::v1::ConfigMap,
    kube::ResourceExt,
    product_logging::{
        framework::create_vector_config,
        spec::{
            AutomaticContainerLogConfig, ContainerLogConfig, ContainerLogConfigChoice, LogLevel,
            Logging,
        },
    },
    role_utils::RoleGroupRef,
};
use stackable_trino_crd::{Container, TrinoCluster};
use strum::Display;

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("object has no namespace"))]
    ObjectHasNoNamespace,

    #[snafu(display("failed to retrieve the ConfigMap {cm_name}"))]
    ConfigMapNotFound {
        source: stackable_operator::client::Error,
        cm_name: String,
    },

    #[snafu(display("failed to retrieve the entry {entry} for ConfigMap {cm_name}"))]
    MissingConfigMapEntry {
        entry: &'static str,
        cm_name: String,
    },

    #[snafu(display("vectorAggregatorConfigMapName must be set"))]
    MissingVectorAggregatorAddress,
}

type Result<T, E = Error> = std::result::Result<T, E>;

const VECTOR_AGGREGATOR_CM_ENTRY: &str = "ADDRESS";

#[derive(Display)]
#[strum(serialize_all = "lowercase")]
pub enum TrinoLogLevel {
    Debug,
    Info,
    Warn,
    Error,
    Off,
}

impl From<LogLevel> for TrinoLogLevel {
    fn from(level: LogLevel) -> Self {
        match level {
            LogLevel::TRACE | LogLevel::DEBUG => Self::Debug,
            LogLevel::INFO => Self::Info,
            LogLevel::WARN => Self::Warn,
            LogLevel::ERROR | LogLevel::FATAL => Self::Error,
            LogLevel::NONE => Self::Off,
        }
    }
}

/// Return the address of the Vector aggregator if the corresponding ConfigMap name is given in the
/// cluster spec
pub async fn resolve_vector_aggregator_address(
    trino: &TrinoCluster,
    client: &Client,
) -> Result<Option<String>> {
    let vector_aggregator_address = if let Some(vector_aggregator_config_map_name) = &trino
        .spec
        .cluster_config
        .vector_aggregator_config_map_name
        .as_ref()
    {
        let vector_aggregator_address = client
            .get::<ConfigMap>(
                vector_aggregator_config_map_name,
                trino
                    .namespace()
                    .as_deref()
                    .context(ObjectHasNoNamespaceSnafu)?,
            )
            .await
            .context(ConfigMapNotFoundSnafu {
                cm_name: vector_aggregator_config_map_name.to_string(),
            })?
            .data
            .and_then(|mut data| data.remove(VECTOR_AGGREGATOR_CM_ENTRY))
            .context(MissingConfigMapEntrySnafu {
                entry: VECTOR_AGGREGATOR_CM_ENTRY,
                cm_name: vector_aggregator_config_map_name.to_string(),
            })?;
        Some(vector_aggregator_address)
    } else {
        None
    };

    Ok(vector_aggregator_address)
}

/// Return the `log.properties` configuration
pub fn get_log_properties(logging: &Logging<Container>) -> Option<String> {
    if let Some(ContainerLogConfig {
        choice: Some(ContainerLogConfigChoice::Automatic(log_config)),
    }) = logging.containers.get(&Container::Trino)
    {
        Some(create_trino_log_properties(log_config))
    } else {
        None
    }
}

/// Return the vector toml configuration
pub fn get_vector_toml(
    rolegroup: &RoleGroupRef<TrinoCluster>,
    vector_aggregator_address: Option<&str>,
    logging: &Logging<Container>,
) -> Result<Option<String>> {
    let vector_log_config = if let Some(ContainerLogConfig {
        choice: Some(ContainerLogConfigChoice::Automatic(log_config)),
    }) = logging.containers.get(&Container::Vector)
    {
        Some(log_config)
    } else {
        None
    };

    if logging.enable_vector_agent {
        Ok(Some(create_vector_config(
            rolegroup,
            vector_aggregator_address.context(MissingVectorAggregatorAddressSnafu)?,
            vector_log_config,
        )))
    } else {
        Ok(None)
    }
}

/// Create trino `log.properties` containing loggers and their respective log levels.
/// The operator-rs framework `LogLevel` offers more choices which are parsed to the available
/// `TrinoLogLevel`.
///
/// The `log.properties` will adhere to the example format:
/// ```
/// io.trino=debug
/// io.trino.server=info
/// ```
fn create_trino_log_properties(automatic_container_config: &AutomaticContainerLogConfig) -> String {
    automatic_container_config
        .loggers
        .iter()
        .map(|(logger, config)| {
            let log_level = TrinoLogLevel::from(config.level);
            if logger == AutomaticContainerLogConfig::ROOT_LOGGER {
                format!("={}\n", log_level)
            } else {
                format!("{}={}\n", logger, log_level)
            }
        })
        .collect::<String>()
}
