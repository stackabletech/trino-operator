//! Local framework helpers that mirror the work-in-progress upstream
//! `stackable_operator::v2::*` modules.
//!
//! The upstream `v2` module on the `smooth-operator` branch is not yet exported
//! from `lib.rs`, so we vendor the small subset of helpers we need.
//!
//! Follow-up: replace these with `stackable_operator::v2::*` imports once
//! upstream publishes the module.

pub mod role_utils;
