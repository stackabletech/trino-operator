//! Builders that turn a `ValidatedCluster` into Kubernetes resource contents.

use std::str::FromStr;

use stackable_operator::v2::types::operator::RoleGroupName;

pub mod command;
pub mod graceful_shutdown;
pub mod ports;
pub mod properties;
pub mod resource;

// Placeholder role-group name used for the recommended labels of a role's group listener.
// The group listener is owned by the role (not a single role-group), so there is no real
// role-group to attribute it to.
stackable_operator::constant!(pub(crate) PLACEHOLDER_LISTENER_ROLE_GROUP: RoleGroupName = "none");
