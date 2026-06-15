use std::collections::BTreeMap;

use stackable_operator::{
    product_logging::spec::{AutomaticContainerLogConfig, LogLevel},
    v2::product_logging::framework::ValidatedContainerLogConfigChoice,
};
use strum::Display;

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

/// Return the `log.properties` content as a typed `BTreeMap` for the (validated) Trino container.
///
/// Returns `None` when the Trino container uses a custom log ConfigMap (in which case the operator
/// does not generate `log.properties`).
pub fn get_log_property_map(
    trino_container: &ValidatedContainerLogConfigChoice,
) -> Option<BTreeMap<String, String>> {
    match trino_container {
        ValidatedContainerLogConfigChoice::Automatic(log_config) => {
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
        }
        ValidatedContainerLogConfigChoice::Custom(_) => None,
    }
}
