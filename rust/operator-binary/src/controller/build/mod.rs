//! Builders that turn a `ValidatedCluster` into Kubernetes resource contents.
//!
//! Each submodule owns one output: properties files, ConfigMaps, StatefulSets, etc.

pub mod properties;
