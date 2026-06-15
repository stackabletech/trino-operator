//! Builders that turn a `ValidatedCluster` into Kubernetes resource contents.
//!
//! `properties` renders the Trino `.properties` files; `resource` builds the individual
//! Kubernetes resources (ConfigMap, Service, Listener, PDB, …); `graceful_shutdown`
//! contributes graceful-shutdown `config.properties` entries and Pod lifecycle configuration.

pub mod graceful_shutdown;
pub mod properties;
pub mod resource;
