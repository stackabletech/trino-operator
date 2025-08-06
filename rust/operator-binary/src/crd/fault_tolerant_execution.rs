//! This module handles fault tolerant execution configuration for Trino.
//!
//! It processes the FaultTolerantExecutionConfig from the cluster configuration and
//! generates the appropriate properties for config.properties and exchange-manager.properties.
//!
//! Based on the Trino documentation: <https://trino.io/docs/current/admin/fault-tolerant-execution.html>

use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};
use snafu::Snafu;
use stackable_operator::{
    builder::pod::volume::{VolumeBuilder, VolumeMountBuilder},
    client::Client,
    commons::tls_verification::{CaCert, TlsServerVerification, TlsVerification},
    crd::s3,
    k8s_openapi::api::core::v1::{Volume, VolumeMount},
    schemars::{self, JsonSchema},
    time::Duration,
};

use super::catalog::commons::HdfsConnection;
use crate::{
    command,
    crd::{CONFIG_DIR_NAME, STACKABLE_CLIENT_TLS_DIR},
};

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FaultTolerantExecutionConfig {
    /// The retry policy for fault tolerant execution.
    /// `Query` retries entire queries, `Task` retries individual tasks.
    /// When set to `Task`, an exchange manager must be configured.
    pub retry_policy: RetryPolicy,

    /// Exchange manager configuration for spooling intermediate data during fault tolerant execution.
    /// Required when using `Task` retry policy, optional for `Query` retry policy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exchange_manager: Option<ExchangeManagerConfig>,

    /// Maximum number of times Trino may attempt to retry a query before declaring it failed.
    /// Only applies to `Query` retry policy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query_retry_attempts: Option<u32>,

    /// Maximum number of times Trino may attempt to retry a single task before declaring the query failed.
    /// Only applies to `Task` retry policy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task_retry_attempts_per_task: Option<u32>,

    /// Minimum time that a failed query or task must wait before it is retried.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_initial_delay: Option<Duration>,

    /// Maximum time that a failed query or task must wait before it is retried.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_max_delay: Option<Duration>,

    /// Factor by which retry delay is increased on each query or task failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_delay_scale_factor: Option<f32>,

    /// Data size of the coordinator's in-memory buffer used to store output of query stages.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exchange_deduplication_buffer_size: Option<String>,

    /// Whether to enable encryption of spooling data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exchange_encryption_enabled: Option<bool>,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum RetryPolicy {
    /// Retry entire queries on failure
    Query,
    /// Retry individual tasks on failure (requires exchange manager)
    Task,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExchangeManagerConfig {
    /// General exchange manager configuration that applies to all backends.
    #[serde(flatten)]
    pub general: ExchangeManagerGeneralConfig,

    /// Backend-specific configuration.
    #[serde(flatten)]
    pub backend: ExchangeManagerBackend,

    /// The `configOverrides` allow overriding arbitrary exchange manager properties.
    #[serde(default)]
    pub config_overrides: HashMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExchangeManagerGeneralConfig {
    /// The minimum buffer pool size for an exchange sink. The larger the buffer pool size,
    /// the larger the write parallelism and memory usage.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sink_buffer_pool_min_size: Option<u32>,

    /// The number of buffers per partition in the buffer pool. The larger the buffer pool size,
    /// the larger the write parallelism and memory usage.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sink_buffers_per_partition: Option<u32>,

    /// Max data size of files written by exchange sinks.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sink_max_file_size: Option<String>,

    /// Number of concurrent readers to read from spooling storage. The larger the number of
    /// concurrent readers, the larger the read parallelism and memory usage.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_concurrent_readers: Option<u32>,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ExchangeManagerBackend {
    /// S3-compatible storage configuration.
    S3(S3ExchangeConfig),
    /// HDFS-based exchange manager.
    Hdfs(HdfsExchangeConfig),
    /// Local filesystem storage (not recommended for production).
    Local(LocalExchangeConfig),
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct S3ExchangeConfig {
    /// S3 bucket URIs for spooling data (e.g., s3://bucket1,s3://bucket2).
    pub base_directories: Vec<String>,
    /// S3 connection configuration.
    /// Learn more about S3 configuration in the [S3 concept docs](DOCS_BASE_URL_PLACEHOLDER/concepts/s3).
    pub connection: stackable_operator::crd::s3::v1alpha1::InlineConnectionOrReference,
    /// IAM role to assume for S3 access.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iam_role: Option<String>,
    /// External ID for the IAM role trust policy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    /// Maximum number of times the S3 client should retry a request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_error_retries: Option<u32>,
    /// Part data size for S3 multi-part upload.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upload_part_size: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HdfsExchangeConfig {
    /// HDFS URIs for spooling data.
    pub base_directories: Vec<String>,
    /// HDFS connection configuration.
    pub hdfs: HdfsConnection,
    /// Block data size for HDFS storage.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_size: Option<String>,
    /// Skip directory scheme validation to support Hadoop-compatible file systems.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_directory_scheme_validation: Option<bool>,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalExchangeConfig {
    /// Local filesystem paths for exchange storage.
    pub base_directories: Vec<String>,
}

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("Exchange manager is required when using Task retry policy"))]
    ExchangeManagerRequiredForTaskPolicy,

    #[snafu(display("Failed to resolve S3 connection"))]
    S3Connection {
        source: s3::v1alpha1::ConnectionError,
    },

    #[snafu(display("trino does not support disabling the TLS verification of S3 servers"))]
    S3TlsNoVerificationNotSupported,
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
    /// Env-Vars that should be exported from files.
    /// You can think of it like `export <key>="$(cat <value>)"`
    pub load_env_from_files: BTreeMap<String, String>,
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

    /// Create a resolved fault tolerant execution configuration from the cluster config
    pub async fn from_config(
        config: &FaultTolerantExecutionConfig,
        client: Option<&Client>,
        namespace: &str,
    ) -> Result<Self, Error> {
        if matches!(config.retry_policy, RetryPolicy::Task) && config.exchange_manager.is_none() {
            return Err(Error::ExchangeManagerRequiredForTaskPolicy);
        }

        let mut config_properties = BTreeMap::new();

        let retry_policy = match config.retry_policy {
            RetryPolicy::Query => "Query",
            RetryPolicy::Task => "Task",
        };
        config_properties.insert("retry-policy".to_string(), retry_policy.to_string());

        Self::insert_if_present(
            &mut config_properties,
            "query-retry-attempts",
            config.query_retry_attempts,
        );
        Self::insert_if_present(
            &mut config_properties,
            "task-retry-attempts-per-task",
            config.task_retry_attempts_per_task,
        );
        Self::insert_if_present(
            &mut config_properties,
            "retry-initial-delay",
            config.retry_initial_delay.as_ref(),
        );
        Self::insert_if_present(
            &mut config_properties,
            "retry-max-delay",
            config.retry_max_delay.as_ref(),
        );
        Self::insert_if_present(
            &mut config_properties,
            "retry-delay-scale-factor",
            config.retry_delay_scale_factor.as_ref(),
        );
        Self::insert_if_present(
            &mut config_properties,
            "exchange.deduplication-buffer-size",
            config.exchange_deduplication_buffer_size.as_ref(),
        );
        Self::insert_if_present(
            &mut config_properties,
            "fault-tolerant-execution.exchange-encryption-enabled",
            config.exchange_encryption_enabled,
        );

        let mut exchange_manager_properties = BTreeMap::new();
        if let Some(exchange_config) = &config.exchange_manager {
            // Add general properties
            Self::insert_if_present(
                &mut exchange_manager_properties,
                "exchange.sink-buffer-pool-min-size",
                exchange_config.general.sink_buffer_pool_min_size,
            );
            Self::insert_if_present(
                &mut exchange_manager_properties,
                "exchange.sink-buffers-per-partition",
                exchange_config.general.sink_buffers_per_partition,
            );
            Self::insert_if_present(
                &mut exchange_manager_properties,
                "exchange.sink-max-file-size",
                exchange_config.general.sink_max_file_size.as_ref(),
            );
            Self::insert_if_present(
                &mut exchange_manager_properties,
                "exchange.source-concurrent-readers",
                exchange_config.general.source_concurrent_readers,
            );

            // Add backend-specific configuration
            match &exchange_config.backend {
                ExchangeManagerBackend::S3(s3_config) => {
                    exchange_manager_properties.insert(
                        "exchange-manager.name".to_string(),
                        "filesystem".to_string(),
                    );
                    exchange_manager_properties.insert(
                        "exchange.base-directories".to_string(),
                        s3_config.base_directories.join(","),
                    );

                    Self::insert_if_present(
                        &mut exchange_manager_properties,
                        "exchange.s3.iam-role",
                        s3_config.iam_role.as_ref(),
                    );
                    Self::insert_if_present(
                        &mut exchange_manager_properties,
                        "exchange.s3.external-id",
                        s3_config.external_id.as_ref(),
                    );
                    Self::insert_if_present(
                        &mut exchange_manager_properties,
                        "exchange.s3.max-error-retries",
                        s3_config.max_error_retries,
                    );
                    Self::insert_if_present(
                        &mut exchange_manager_properties,
                        "exchange.s3.upload.part-size",
                        s3_config.upload_part_size.as_ref(),
                    );
                }
                ExchangeManagerBackend::Hdfs(hdfs_config) => {
                    exchange_manager_properties
                        .insert("exchange-manager.name".to_string(), "hdfs".to_string());
                    exchange_manager_properties.insert(
                        "exchange.base-directories".to_string(),
                        hdfs_config.base_directories.join(","),
                    );

                    Self::insert_if_present(
                        &mut exchange_manager_properties,
                        "exchange.hdfs.block-size",
                        hdfs_config.block_size.as_ref(),
                    );
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

            exchange_manager_properties.extend(exchange_config.config_overrides.clone());
        }

        let mut resolved_config = Self {
            config_properties,
            exchange_manager_properties,
            volumes: Vec::new(),
            volume_mounts: Vec::new(),
            load_env_from_files: BTreeMap::new(),
            init_container_extra_start_commands: Vec::new(),
        };

        // Resolve external resources if Kubernetes client is available
        // This should always be the case, except for when this function is called during unit tests
        if let (Some(client), Some(exchange_config)) = (client, &config.exchange_manager) {
            match &exchange_config.backend {
                ExchangeManagerBackend::S3(s3_config) => {
                    resolved_config
                        .resolve_s3_backend(s3_config, client, namespace)
                        .await?;
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

    async fn resolve_s3_backend(
        &mut self,
        s3_config: &S3ExchangeConfig,
        client: &Client,
        namespace: &str,
    ) -> Result<(), Error> {
        use snafu::ResultExt;

        let s3_connection = s3_config
            .connection
            .clone()
            .resolve(client, namespace)
            .await
            .context(S3ConnectionSnafu)?;

        let (volumes, mounts) = s3_connection
            .volumes_and_mounts()
            .context(S3ConnectionSnafu)?;
        self.volumes.extend(volumes);
        self.volume_mounts.extend(mounts);

        self.exchange_manager_properties.insert(
            "exchange.s3.region".to_string(),
            s3_connection.region.name.clone(),
        );
        self.exchange_manager_properties.insert(
            "exchange.s3.endpoint".to_string(),
            s3_connection
                .endpoint()
                .context(S3ConnectionSnafu)?
                .to_string(),
        );
        self.exchange_manager_properties.insert(
            "exchange.s3.path-style-access".to_string(),
            (s3_connection.access_style == s3::v1alpha1::S3AccessStyle::Path).to_string(),
        );

        if let Some((access_key_path, secret_key_path)) = s3_connection.credentials_mount_paths() {
            let access_key_env = "EXCHANGE_S3_AWS_ACCESS_KEY".to_string();
            let secret_key_env = "EXCHANGE_S3_AWS_SECRET_KEY".to_string();

            self.exchange_manager_properties.insert(
                "exchange.s3.aws-access-key".to_string(),
                format!("${{ENV:{access_key_env}}}"),
            );
            self.exchange_manager_properties.insert(
                "exchange.s3.aws-secret-key".to_string(),
                format!("${{ENV:{secret_key_env}}}"),
            );

            self.load_env_from_files
                .insert(access_key_env, access_key_path);
            self.load_env_from_files
                .insert(secret_key_env, secret_key_path);
        }

        if let Some(tls) = s3_connection.tls.tls.as_ref() {
            match &tls.verification {
                TlsVerification::None {} => return S3TlsNoVerificationNotSupportedSnafu.fail(),
                TlsVerification::Server(TlsServerVerification {
                    ca_cert: CaCert::WebPki {},
                }) => {}
                TlsVerification::Server(TlsServerVerification {
                    ca_cert: CaCert::SecretClass(_),
                }) => {
                    if let Some(ca_cert) = s3_connection.tls.tls_ca_cert_mount_path() {
                        self.init_container_extra_start_commands.extend(
                            command::add_cert_to_truststore(
                                &ca_cert,
                                STACKABLE_CLIENT_TLS_DIR,
                                "exchange-s3-ca-cert",
                            ),
                        );
                    }
                }
            }
        }

        Ok(())
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
    use stackable_operator::time::Duration;

    use super::*;

    #[tokio::test]
    async fn test_query_retry_policy_without_exchange_manager() {
        let config = FaultTolerantExecutionConfig {
            retry_policy: RetryPolicy::Query,
            exchange_manager: None,
            query_retry_attempts: Some(5),
            task_retry_attempts_per_task: None,
            retry_initial_delay: Some(Duration::from_secs(15)),
            retry_max_delay: Some(Duration::from_secs(90)),
            retry_delay_scale_factor: Some(3.0),
            exchange_deduplication_buffer_size: Some("64MB".to_string()),
            exchange_encryption_enabled: Some(false),
        };

        let fte_config =
            ResolvedFaultTolerantExecutionConfig::from_config(&config, None, "default")
                .await
                .unwrap();

        assert_eq!(
            fte_config.config_properties.get("retry-policy"),
            Some(&"Query".to_string())
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
            Some(&"1m30s".to_string())
        );
        assert_eq!(
            fte_config.config_properties.get("retry-delay-scale-factor"),
            Some(&"3".to_string())
        );
        assert_eq!(
            fte_config
                .config_properties
                .get("exchange.deduplication-buffer-size"),
            Some(&"64MB".to_string())
        );
        assert_eq!(
            fte_config
                .config_properties
                .get("fault-tolerant-execution.exchange-encryption-enabled"),
            Some(&"false".to_string())
        );
        assert!(fte_config.exchange_manager_properties.is_empty());
    }

    #[tokio::test]
    async fn test_task_retry_policy_requires_exchange_manager() {
        let config = FaultTolerantExecutionConfig {
            retry_policy: RetryPolicy::Task,
            exchange_manager: None,
            query_retry_attempts: None,
            task_retry_attempts_per_task: Some(3),
            retry_initial_delay: None,
            retry_max_delay: None,
            retry_delay_scale_factor: None,
            exchange_deduplication_buffer_size: None,
            exchange_encryption_enabled: None,
        };

        let result =
            ResolvedFaultTolerantExecutionConfig::from_config(&config, None, "default").await;
        assert!(matches!(
            result,
            Err(Error::ExchangeManagerRequiredForTaskPolicy)
        ));
    }

    #[tokio::test]
    async fn test_task_retry_policy_with_s3_exchange_manager() {
        let config = FaultTolerantExecutionConfig {
            retry_policy: RetryPolicy::Task,
            exchange_manager: Some(ExchangeManagerConfig {
                general: ExchangeManagerGeneralConfig {
                    sink_buffer_pool_min_size: Some(20),
                    sink_buffers_per_partition: Some(4),
                    sink_max_file_size: Some("2GB".to_string()),
                    source_concurrent_readers: Some(8),
                },
                backend: ExchangeManagerBackend::S3(S3ExchangeConfig {
                    base_directories: vec!["s3://my-bucket/exchange".to_string()],
                    connection: stackable_operator::crd::s3::v1alpha1::InlineConnectionOrReference::Reference(
                        "test-s3-connection".to_string()
                    ),
                    iam_role: Some("arn:aws:iam::123456789012:role/TrinoRole".to_string()),
                    external_id: Some("external-id-123".to_string()),
                    max_error_retries: Some(5),
                    upload_part_size: Some("10MB".to_string()),
                }),
                config_overrides: std::collections::HashMap::new(),
            }),
            query_retry_attempts: None,
            task_retry_attempts_per_task: Some(2),
            retry_initial_delay: None,
            retry_max_delay: None,
            retry_delay_scale_factor: None,
            exchange_deduplication_buffer_size: None,
            exchange_encryption_enabled: None,
        };

        let fte_config =
            ResolvedFaultTolerantExecutionConfig::from_config(&config, None, "default")
                .await
                .unwrap();

        assert_eq!(
            fte_config.config_properties.get("retry-policy"),
            Some(&"Task".to_string())
        );
        assert_eq!(
            fte_config
                .config_properties
                .get("task-retry-attempts-per-task"),
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
            Some(&"s3://my-bucket/exchange".to_string())
        );

        assert_eq!(
            fte_config
                .exchange_manager_properties
                .get("exchange.s3.iam-role"),
            Some(&"arn:aws:iam::123456789012:role/TrinoRole".to_string())
        );
        assert_eq!(
            fte_config
                .exchange_manager_properties
                .get("exchange.s3.external-id"),
            Some(&"external-id-123".to_string())
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
            Some(&"10MB".to_string())
        );
        assert_eq!(
            fte_config
                .exchange_manager_properties
                .get("exchange.sink-buffer-pool-min-size"),
            Some(&"20".to_string())
        );
        assert_eq!(
            fte_config
                .exchange_manager_properties
                .get("exchange.sink-buffers-per-partition"),
            Some(&"4".to_string())
        );
        assert_eq!(
            fte_config
                .exchange_manager_properties
                .get("exchange.sink-max-file-size"),
            Some(&"2GB".to_string())
        );
        assert_eq!(
            fte_config
                .exchange_manager_properties
                .get("exchange.source-concurrent-readers"),
            Some(&"8".to_string())
        );
    }

    #[tokio::test]
    async fn test_exchange_manager_config_overrides() {
        let mut config_overrides = HashMap::new();
        config_overrides.insert("custom.property".to_string(), "custom-value".to_string());
        config_overrides.insert("exchange.s3.upload.part-size".to_string(), "overridden-value".to_string());

        let config = FaultTolerantExecutionConfig {
            retry_policy: RetryPolicy::Task,
            exchange_manager: Some(ExchangeManagerConfig {
                general: ExchangeManagerGeneralConfig {
                    sink_buffer_pool_min_size: None,
                    sink_buffers_per_partition: None,
                    sink_max_file_size: None,
                    source_concurrent_readers: None,
                },
                backend: ExchangeManagerBackend::S3(S3ExchangeConfig {
                    base_directories: vec!["s3://my-bucket/exchange".to_string()],
                    connection: stackable_operator::crd::s3::v1alpha1::InlineConnectionOrReference::Reference(
                        "test-s3-connection".to_string()
                    ),
                    iam_role: None,
                    external_id: None,
                    max_error_retries: None,
                    upload_part_size: Some("original-value".to_string()),
                }),
                config_overrides,
            }),
            query_retry_attempts: None,
            task_retry_attempts_per_task: Some(2),
            retry_initial_delay: None,
            retry_max_delay: None,
            retry_delay_scale_factor: None,
            exchange_deduplication_buffer_size: None,
            exchange_encryption_enabled: None,
        };

        let fte_config =
            ResolvedFaultTolerantExecutionConfig::from_config(&config, None, "default")
                .await
                .unwrap();

        assert_eq!(
            fte_config
                .exchange_manager_properties
                .get("custom.property"),
            Some(&"custom-value".to_string())
        );

        assert_eq!(
            fte_config
                .exchange_manager_properties
                .get("exchange.s3.upload.part-size"),
            Some(&"overridden-value".to_string())
        );
    }
}
