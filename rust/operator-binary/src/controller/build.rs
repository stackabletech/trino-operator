//! Builders that turn a `ValidatedCluster` into Kubernetes resource contents.
//!
//! `properties` renders the Trino `.properties` files; `config_map` assembles
//! the per-rolegroup ConfigMap; `graceful_shutdown` contributes graceful-shutdown
//! `config.properties` entries and Pod lifecycle configuration.

pub mod config_map;
pub mod graceful_shutdown;
pub mod properties;
