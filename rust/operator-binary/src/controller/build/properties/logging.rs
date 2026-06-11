use stackable_operator::{
    product_logging::{
        framework::create_vector_config,
        spec::{
            AutomaticContainerLogConfig, ContainerLogConfig, ContainerLogConfigChoice, LogLevel,
            Logging,
        },
    },
    role_utils::RoleGroupRef,
};
use strum::Display;

use crate::crd::{Container, v1alpha1};

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

/// Return the `log.properties` content as a typed `BTreeMap`.
pub fn get_log_property_map(
    logging: &Logging<Container>,
) -> Option<std::collections::BTreeMap<String, String>> {
    if let Some(ContainerLogConfig {
        choice: Some(ContainerLogConfigChoice::Automatic(log_config)),
    }) = logging.containers.get(&Container::Trino)
    {
        let map = log_config
            .loggers
            .iter()
            .map(|(logger, config)| {
                let log_level = TrinoLogLevel::from(config.level);
                let key = if logger == AutomaticContainerLogConfig::ROOT_LOGGER {
                    // ROOT logger maps to an empty key in log.properties (=LEVEL).
                    String::new()
                } else {
                    logger.clone()
                };
                (key, log_level.to_string())
            })
            .collect();
        Some(map)
    } else {
        None
    }
}

/// Return the vector toml configuration
pub fn get_vector_toml(
    rolegroup: &RoleGroupRef<v1alpha1::TrinoCluster>,
    logging: &Logging<Container>,
) -> Option<String> {
    let vector_log_config = if let Some(ContainerLogConfig {
        choice: Some(ContainerLogConfigChoice::Automatic(log_config)),
    }) = logging.containers.get(&Container::Vector)
    {
        Some(log_config)
    } else {
        None
    };

    if logging.enable_vector_agent {
        Some(create_vector_config(rolegroup, vector_log_config))
    } else {
        None
    }
}
