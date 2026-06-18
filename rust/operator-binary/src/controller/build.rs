//! Builders that turn a `ValidatedCluster` into Kubernetes resource contents.

pub mod command;
pub mod graceful_shutdown;
pub mod ports;
pub mod properties;
pub mod resource;

/// Placeholder role-group name used for the recommended labels of a role's group listener.
///
/// The group listener is owned by the role (not a single role-group), so there is no real
/// role-group to attribute it to.
pub(crate) const PLACEHOLDER_LISTENER_ROLE_GROUP: &str = "none";
