use std::collections::BTreeMap;

use snafu::{ResultExt, Snafu};
use stackable_operator::{
    builder::pod::volume::{VolumeBuilder, VolumeMountBuilder},
    client::Client,
    crd::s3,
    k8s_openapi::{
        api::core::v1::{Volume, VolumeMount},
        apimachinery::pkg::api::resource::Quantity,
    },
};

use crate::{
    config,
    crd::{
        CONFIG_DIR_NAME,
        fault_tolerant_execution::{
            ExchangeManagerBackend, FaultTolerantExecutionConfig, HdfsExchangeConfig,
        },
    },
};

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("Failed to resolve S3 connection"))]
    S3Connection {
        source: s3::v1alpha1::ConnectionError,
    },

    #[snafu(display("Failed to resolve S3 connection"))]
    ResolveS3Connection { source: config::s3::Error },

    #[snafu(display("trino does not support disabling the TLS verification of S3 servers"))]
    S3TlsNoVerificationNotSupported,

    #[snafu(display("failed to convert data size for [{field}] to bytes"))]
    QuantityConversion {
        source: stackable_operator::memory::Error,
        field: &'static str,
    },
}

/// Fault tolerant execution configuration with external resources resolved
pub struct ResolvedFaultTolerantExecutionConfig {
    /// Properties to add to config.properties
    pub config_properties: BTreeMap<String, String>,

    /// Properties to add to exchange-manager.properties (if needed)
    pub exchange_manager_properties: BTreeMap<String, String>,

    /// Volumes required for the configuration (e.g., for S3 credentials)
    pub volumes: Vec<Volume>,

    /// Volume mounts required for the configuration
    pub volume_mounts: Vec<VolumeMount>,

    /// Additional commands that need to be executed before starting Trino
    pub init_container_extra_start_commands: Vec<String>,
}

impl ResolvedFaultTolerantExecutionConfig {
    /// Helper function to insert optional values into properties map
    fn insert_if_present<T: ToString>(
        properties: &mut BTreeMap<String, String>,
        key: &str,
        value: Option<T>,
    ) {
        if let Some(v) = value {
            properties.insert(key.to_string(), v.to_string());
        }
    }

    /// Helper function to insert optional Quantity values after converting to Trino bytes string
    fn insert_quantity_if_present(
        properties: &mut BTreeMap<String, String>,
        key: &'static str,
        quantity: Option<&Quantity>,
    ) -> Result<(), Error> {
        if let Some(q) = quantity {
            use snafu::ResultExt;
            let v = crate::crd::quantity_to_trino_bytes(q)
                .context(QuantityConversionSnafu { field: key })?;
            properties.insert(key.to_string(), v);
        }
        Ok(())
    }

    /// Create a resolved fault tolerant execution configuration from the cluster config
    pub async fn from_config(
        config: &FaultTolerantExecutionConfig,
        client: Option<&Client>,
        namespace: &str,
    ) -> Result<Self, Error> {
        let mut config_properties = BTreeMap::new();

        // Handle different retry policies and their configurations
        let (retry_policy_str, exchange_manager_opt) = match config {
            FaultTolerantExecutionConfig::Query(query_config) => {
                // Set query-specific properties
                Self::insert_if_present(
                    &mut config_properties,
                    "query-retry-attempts",
                    query_config.retry_attempts,
                );
                Self::insert_if_present(
                    &mut config_properties,
                    "retry-initial-delay",
                    query_config
                        .retry_initial_delay
                        .as_ref()
                        .map(|d| format!("{}s", d.as_secs())),
                );
                Self::insert_if_present(
                    &mut config_properties,
                    "retry-max-delay",
                    query_config
                        .retry_max_delay
                        .as_ref()
                        .map(|d| format!("{}s", d.as_secs())),
                );
                Self::insert_if_present(
                    &mut config_properties,
                    "retry-delay-scale-factor",
                    query_config.retry_delay_scale_factor.as_ref(),
                );
                Self::insert_quantity_if_present(
                    &mut config_properties,
                    "exchange.deduplication-buffer-size",
                    query_config.exchange_deduplication_buffer_size.as_ref(),
                )?;

                ("QUERY", query_config.exchange_manager.as_ref())
            }
            FaultTolerantExecutionConfig::Task(task_config) => {
                // Set task-specific properties
                Self::insert_if_present(
                    &mut config_properties,
                    "task-retry-attempts-per-task",
                    task_config.retry_attempts_per_task,
                );
                Self::insert_if_present(
                    &mut config_properties,
                    "retry-initial-delay",
                    task_config
                        .retry_initial_delay
                        .as_ref()
                        .map(|d| format!("{}s", d.as_secs())),
                );
                Self::insert_if_present(
                    &mut config_properties,
                    "retry-max-delay",
                    task_config
                        .retry_max_delay
                        .as_ref()
                        .map(|d| format!("{}s", d.as_secs())),
                );
                Self::insert_if_present(
                    &mut config_properties,
                    "retry-delay-scale-factor",
                    task_config.retry_delay_scale_factor.as_ref(),
                );
                Self::insert_quantity_if_present(
                    &mut config_properties,
                    "exchange.deduplication-buffer-size",
                    task_config.exchange_deduplication_buffer_size.as_ref(),
                )?;

                ("TASK", Some(&task_config.exchange_manager))
            }
        };

        config_properties.insert("retry-policy".to_string(), retry_policy_str.to_string());

        let mut exchange_manager_properties = BTreeMap::new();
        if let Some(exchange_config) = exchange_manager_opt {
            Self::insert_if_present(
                &mut config_properties,
                "fault-tolerant-execution.exchange-encryption-enabled",
                exchange_config.encryption_enabled,
            );
            Self::insert_if_present(
                &mut exchange_manager_properties,
                "exchange.sink-buffer-pool-min-size",
                exchange_config.sink_buffer_pool_min_size,
            );
            Self::insert_if_present(
                &mut exchange_manager_properties,
                "exchange.sink-buffers-per-partition",
                exchange_config.sink_buffers_per_partition,
            );
            Self::insert_quantity_if_present(
                &mut exchange_manager_properties,
                "exchange.sink-max-file-size",
                exchange_config.sink_max_file_size.as_ref(),
            )?;
            Self::insert_if_present(
                &mut exchange_manager_properties,
                "exchange.source-concurrent-readers",
                exchange_config.source_concurrent_readers,
            );

            // Add backend-specific configuration
            match &exchange_config.backend {
                ExchangeManagerBackend::S3(s3_exchange_config) => {
                    exchange_manager_properties.insert(
                        "exchange-manager.name".to_string(),
                        "filesystem".to_string(),
                    );
                    exchange_manager_properties.insert(
                        "exchange.base-directories".to_string(),
                        s3_exchange_config.base_directories.join(","),
                    );

                    Self::insert_if_present(
                        &mut exchange_manager_properties,
                        "exchange.s3.max-error-retries",
                        s3_exchange_config.max_error_retries,
                    );
                    Self::insert_quantity_if_present(
                        &mut exchange_manager_properties,
                        "exchange.s3.upload.part-size",
                        s3_exchange_config.upload_part_size.as_ref(),
                    )?;
                }
                ExchangeManagerBackend::Hdfs(hdfs_config) => {
                    exchange_manager_properties
                        .insert("exchange-manager.name".to_string(), "hdfs".to_string());
                    exchange_manager_properties.insert(
                        "exchange.base-directories".to_string(),
                        hdfs_config.base_directories.join(","),
                    );

                    Self::insert_quantity_if_present(
                        &mut exchange_manager_properties,
                        "exchange.hdfs.block-size",
                        hdfs_config.block_size.as_ref(),
                    )?;
                    Self::insert_if_present(
                        &mut exchange_manager_properties,
                        "exchange.hdfs.skip-directory-scheme-validation",
                        hdfs_config.skip_directory_scheme_validation,
                    );

                    let hdfs_config_dir = format!("{CONFIG_DIR_NAME}/exchange-hdfs-config");
                    exchange_manager_properties.insert(
                        "hdfs.config.resources".to_string(),
                        format!("{hdfs_config_dir}/core-site.xml,{hdfs_config_dir}/hdfs-site.xml"),
                    );
                }
                ExchangeManagerBackend::Local(local_config) => {
                    exchange_manager_properties.insert(
                        "exchange-manager.name".to_string(),
                        "filesystem".to_string(),
                    );
                    exchange_manager_properties.insert(
                        "exchange.base-directories".to_string(),
                        local_config.base_directories.join(","),
                    );
                }
            }
        }

        let mut resolved_config = Self {
            config_properties,
            exchange_manager_properties,
            volumes: Vec::new(),
            volume_mounts: Vec::new(),
            init_container_extra_start_commands: Vec::new(),
        };

        // Resolve external resources if Kubernetes client is available
        // This should always be the case, except for when this function is called during unit tests
        if let (Some(client), Some(exchange_config)) = (client, exchange_manager_opt) {
            match &exchange_config.backend {
                ExchangeManagerBackend::S3(s3_config) => {
                    let resolved_s3_config = config::s3::ResolvedS3Config::from_config(
                        &s3_config.connection,
                        client,
                        namespace,
                    )
                    .await
                    .context(ResolveS3ConnectionSnafu)?;

                    // Copy the S3 configuration over and add "exchange." prefix
                    resolved_config.exchange_manager_properties.extend(
                        resolved_s3_config
                            .properties
                            .into_iter()
                            .map(|(k, v)| (format!("exchange.{k}"), v)),
                    );
                    resolved_config.volumes.extend(resolved_s3_config.volumes);
                    resolved_config
                        .volume_mounts
                        .extend(resolved_s3_config.volume_mounts);
                    resolved_config
                        .init_container_extra_start_commands
                        .extend(resolved_s3_config.init_container_extra_start_commands);
                }
                ExchangeManagerBackend::Hdfs(hdfs_config) => {
                    resolved_config.resolve_hdfs_backend(hdfs_config);
                }
                ExchangeManagerBackend::Local(_) => {
                    // Local backend requires no external resource resolution
                }
            }
        }

        Ok(resolved_config)
    }

    fn resolve_hdfs_backend(&mut self, hdfs_config: &HdfsExchangeConfig) {
        let hdfs_config_dir = format!("{CONFIG_DIR_NAME}/exchange-hdfs-config");
        let volume_name = "exchange-hdfs-config".to_string();

        self.volumes.push(
            VolumeBuilder::new(&volume_name)
                .with_config_map(&hdfs_config.hdfs.config_map)
                .build(),
        );
        self.volume_mounts
            .push(VolumeMountBuilder::new(&volume_name, &hdfs_config_dir).build());
    }
}

#[cfg(test)]
mod tests {

    use indoc::indoc;

    use super::*;

    fn parse_config(config_yaml: &str) -> FaultTolerantExecutionConfig {
        let deserializer = serde_yaml::Deserializer::from_str(config_yaml);
        serde_yaml::with::singleton_map_recursive::deserialize(deserializer)
            .expect("invalid test input")
    }

    #[tokio::test]
    async fn test_query_retry_policy_without_exchange_manager() {
        let config = parse_config(indoc! {r#"
            query:
              retryAttempts: 5
              retryInitialDelay: 15s
              retryMaxDelay: 90s
              retryDelayScaleFactor: 3
              exchangeDeduplicationBufferSize: 64Mi
        "#});

        let fte_config =
            ResolvedFaultTolerantExecutionConfig::from_config(&config, None, "default")
                .await
                .unwrap();

        assert_eq!(
            fte_config.config_properties.get("retry-policy"),
            Some(&"QUERY".to_string())
        );
        assert_eq!(
            fte_config.config_properties.get("query-retry-attempts"),
            Some(&"5".to_string())
        );
        assert_eq!(
            fte_config.config_properties.get("retry-initial-delay"),
            Some(&"15s".to_string())
        );
        assert_eq!(
            fte_config.config_properties.get("retry-max-delay"),
            Some(&"90s".to_string())
        );
        assert_eq!(
            fte_config.config_properties.get("retry-delay-scale-factor"),
            Some(&"3".to_string())
        );
        assert_eq!(
            fte_config
                .config_properties
                .get("exchange.deduplication-buffer-size"),
            Some(&"67108864B".to_string())
        );
    }

    #[tokio::test]
    async fn test_query_retry_policy_with_exchange_manager() {
        let config = parse_config(indoc! {r#"
            query:
              retryAttempts: 3
              retryInitialDelay: 10s
              retryMaxDelay: 1m
              retryDelayScaleFactor: 2
              exchangeDeduplicationBufferSize: 100Mi
              exchangeManager:
                encryptionEnabled: true
                sinkBufferPoolMinSize: 10
                sinkBuffersPerPartition: 2
                sinkMaxFileSize: 1Gi
                sourceConcurrentReaders: 4
                local:
                  baseDirectories: ["/tmp/exchange"]
        "#});

        let fte_config =
            ResolvedFaultTolerantExecutionConfig::from_config(&config, None, "default")
                .await
                .unwrap();

        assert_eq!(
            fte_config.config_properties.get("retry-policy"),
            Some(&"QUERY".to_string())
        );
        assert_eq!(
            fte_config.config_properties.get("query-retry-attempts"),
            Some(&"3".to_string())
        );
        assert_eq!(
            fte_config.config_properties.get("retry-initial-delay"),
            Some(&"10s".to_string())
        );
        assert_eq!(
            fte_config.config_properties.get("retry-max-delay"),
            Some(&"60s".to_string())
        );
        assert_eq!(
            fte_config.config_properties.get("retry-delay-scale-factor"),
            Some(&"2".to_string())
        );

        assert_eq!(
            fte_config
                .exchange_manager_properties
                .get("exchange-manager.name"),
            Some(&"filesystem".to_string())
        );
        assert_eq!(
            fte_config
                .exchange_manager_properties
                .get("exchange.base-directories"),
            Some(&"/tmp/exchange".to_string())
        );
        assert_eq!(
            fte_config
                .config_properties
                .get("exchange.deduplication-buffer-size"),
            Some(&"104857600B".to_string())
        );
        assert_eq!(
            fte_config
                .config_properties
                .get("fault-tolerant-execution.exchange-encryption-enabled"),
            Some(&"true".to_string())
        );
    }

    #[tokio::test]
    async fn test_task_retry_policy_with_s3_exchange_manager() {
        let config = parse_config(indoc! {r#"
            task:
              exchangeManager:
                s3:
                  baseDirectories: ["s3://my-bucket/exchange"]
                  connection:
                    reference: test-s3-connection
                  maxErrorRetries: 5
                  uploadPartSize: 10Mi
                  iamRole: arn:aws:iam::123456789012:role/TrinoRole
                  externalId: external-id-123
        "#});

        let fte_config =
            ResolvedFaultTolerantExecutionConfig::from_config(&config, None, "default")
                .await
                .unwrap();

        assert_eq!(
            fte_config.config_properties.get("retry-policy"),
            Some(&"TASK".to_string())
        );

        assert_eq!(
            fte_config
                .exchange_manager_properties
                .get("exchange-manager.name"),
            Some(&"filesystem".to_string())
        );
        assert_eq!(
            fte_config
                .exchange_manager_properties
                .get("exchange.base-directories"),
            Some(&"s3://my-bucket/exchange".to_string())
        );

        assert_eq!(
            fte_config
                .exchange_manager_properties
                .get("exchange.s3.max-error-retries"),
            Some(&"5".to_string())
        );
        assert_eq!(
            fte_config
                .exchange_manager_properties
                .get("exchange.s3.upload.part-size"),
            Some(&"10485760B".to_string())
        );
    }
}
