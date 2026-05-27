//! Per-file builders for Trino `.properties` files.
//!
//! Each `<file>.rs` module produces the rendered key/value pairs for one
//! Trino config file. The shared [`writer`] module serializes the map to the
//! Java-properties on-wire format.

pub mod access_control_properties;
pub mod exchange_manager_properties;
pub mod log_properties;
pub mod node_properties;
pub mod security_properties;
pub mod writer;
