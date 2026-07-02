//! Builders for the individual Kubernetes resources of a TrinoCluster.
//!
//! Each submodule builds one kind of resource (ConfigMap, Service, Listener, PDB, …) and
//! *returns* it, rather than mutating shared state or applying it directly. The reconciler
//! collects the returned objects and applies them.

pub mod config_map;
pub mod listener;
pub mod pdb;
pub mod service;
pub mod statefulset;
