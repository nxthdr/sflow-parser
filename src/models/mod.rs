//! sFlow v5 data models
//!
//! This module contains all data structures for sFlow v5 datagrams.
//! 
//! ## Module Organization
//! 
//! - `core`: Core datagram and sample structures (fully parsed)
//! - `flow_records`: Flow record types (not yet parsed, models defined)
//! - `counter_records`: Counter record types (not yet parsed, models defined)

pub mod core;
pub mod flow_records;
pub mod counter_records;

// Re-export core types for backward compatibility
pub use core::*;

// Re-export flow record types
pub use flow_records::*;

// Re-export counter record types
pub use counter_records::*;
