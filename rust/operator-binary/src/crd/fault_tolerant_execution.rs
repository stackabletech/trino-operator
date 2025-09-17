//! This module handles fault tolerant execution configuration for Trino.
//!
//! It processes the FaultTolerantExecutionConfig from the cluster configuration and
//! generates the appropriate properties for config.properties and exchange-manager.properties.
//!
//! Based on the Trino documentation: <https://trino.io/docs/current/admin/fault-tolerant-execution.html>

use serde::{Deserialize, Serialize};
use stackable_operator::{
    k8s_openapi::apimachinery::pkg::api::resource::Quantity,
    schemars::{self, JsonSchema},
    shared::time::Duration,
};

use super::catalog::commons::HdfsConnection;

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum FaultTolerantExecutionConfig {
    /// Query-level fault tolerant execution. Retries entire queries on failure.
    Query(QueryRetryConfig),

    /// Task-level fault tolerant execution. Retries individual tasks on failure (requires exchange manager).
    Task(TaskRetryConfig),
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QueryRetryConfig {
    /// Maximum number of times Trino may attempt to retry a query before declaring it failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_attempts: Option<u32>,

    /// Minimum time that a failed query must wait before it is retried.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_initial_delay: Option<Duration>,

    /// Maximum time that a failed query must wait before it is retried.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_max_delay: Option<Duration>,

    /// Factor by which retry delay is increased on each query failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_delay_scale_factor: Option<f32>,

    /// Data size of the coordinator's in-memory buffer used to store output of query stages.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exchange_deduplication_buffer_size: Option<Quantity>,

    /// Exchange manager configuration for spooling intermediate data during fault tolerant execution.
    /// Optional for Query retry policy, recommended for large result sets.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exchange_manager: Option<ExchangeManagerConfig>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskRetryConfig {
    /// Maximum number of times Trino may attempt to retry a single task before declaring the query failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_attempts_per_task: Option<u32>,

    /// Minimum time that a failed task must wait before it is retried.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_initial_delay: Option<Duration>,

    /// Maximum time that a failed task must wait before it is retried.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_max_delay: Option<Duration>,

    /// Factor by which retry delay is increased on each task failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_delay_scale_factor: Option<f32>,

    /// Data size of the coordinator's in-memory buffer used to store output of query stages.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exchange_deduplication_buffer_size: Option<Quantity>,

    /// Exchange manager configuration for spooling intermediate data during fault tolerant execution.
    /// Required for Task retry policy.
    pub exchange_manager: ExchangeManagerConfig,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExchangeManagerConfig {
    /// Whether to enable encryption of spooling data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encryption_enabled: Option<bool>,

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
    pub sink_max_file_size: Option<Quantity>,

    /// Number of concurrent readers to read from spooling storage. The larger the number of
    /// concurrent readers, the larger the read parallelism and memory usage.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_concurrent_readers: Option<u32>,

    /// Backend-specific configuration.
    #[serde(flatten)]
    pub backend: ExchangeManagerBackend,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ExchangeManagerBackend {
    /// S3-compatible storage configuration.
    S3(S3ExchangeConfig),

    /// HDFS-based exchange manager.
    Hdfs(HdfsExchangeConfig),

    /// Local filesystem storage (not recommended for production).
    Local(LocalExchangeConfig),
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct S3ExchangeConfig {
    /// S3 bucket URIs for spooling data (e.g., s3://bucket1,s3://bucket2).
    pub base_directories: Vec<String>,

    /// Maximum number of times the S3 client should retry a request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_error_retries: Option<u32>,

    /// Part data size for S3 multi-part upload.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upload_part_size: Option<Quantity>,

    /// S3 connection configuration.
    /// Learn more about S3 configuration in the [S3 concept docs](DOCS_BASE_URL_PLACEHOLDER/concepts/s3).
    pub connection: stackable_operator::crd::s3::v1alpha1::InlineConnectionOrReference,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HdfsExchangeConfig {
    /// HDFS URIs for spooling data.
    pub base_directories: Vec<String>,

    /// HDFS connection configuration.
    pub hdfs: HdfsConnection,

    /// Block data size for HDFS storage.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_size: Option<Quantity>,

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
