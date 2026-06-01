//! Builders that turn a `ValidatedCluster` into Kubernetes resource contents.
//!
//! `properties` renders the Trino `.properties` files; `config_map` assembles
//! the per-rolegroup ConfigMap.

pub mod config_map;
pub mod properties;
