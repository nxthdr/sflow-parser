//! Validation tests against official sFlow specification
//!
//! Automatically downloads and parses sflow.h from GitHub,
//! then validates our Rust implementation against the official C spec.

pub mod parser_spec;

#[allow(clippy::module_inception)]
pub mod validation;
