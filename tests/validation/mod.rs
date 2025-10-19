//! Validation tests against official sFlow specification
//!
//! Validation approaches:
//! 1. sflowtool_validation - Validates against sflowtool's sflow.h C header
//! 2. specs_validation - Validates against official sFlow specification documents (with field validation)

pub mod sflowtool_parser_spec;

#[allow(clippy::module_inception)]
pub mod sflowtool_validation;

pub mod specs_parser_lib_ast;
pub mod specs_validation;
