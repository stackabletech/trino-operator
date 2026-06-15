//! The Vector agent configuration (`vector.yaml`) assembled into the rolegroup `ConfigMap`.

/// The Vector agent configuration (`vector.yaml`).
///
/// It is templated with environment variables (`${LOG_DIR}`, `${NAMESPACE}`, …) that the
/// `v2` Vector container injects at runtime, so the same file content is used for every
/// rolegroup.
const VECTOR_CONFIG: &str = include_str!("vector.yaml");

/// Returns the Vector agent config (`vector.yaml`) content.
pub fn vector_config_file_content() -> String {
    VECTOR_CONFIG.to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vector_config_file_content() {
        let content = vector_config_file_content();
        assert!(!content.is_empty());
        // The airlift source must be present (Trino's main log format) ...
        assert!(content.contains("files_airlift"));
        // ... while the aggregator sink must reference the injected address.
        assert!(content.contains("${VECTOR_AGGREGATOR_ADDRESS}"));
    }
}
