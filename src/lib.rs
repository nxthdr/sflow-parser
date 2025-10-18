//! sFlow v5 Parser Library
//!
//! This library provides parsing functionality for sFlow version 5 datagrams
//! as specified in <https://sflow.org/sflow_version_5.txt>
//!
//! # Example
//!
//! ```no_run
//! use sflow_parser::parser::parse_datagram;
//!
//! let data = std::fs::read("sflow.bin").unwrap();
//! let datagram = parse_datagram(&data).unwrap();
//! println!("Parsed {} samples", datagram.samples.len());
//! ```

pub mod models;
pub mod parser;

// Re-export commonly used types
pub use models::{SFlowDatagram, SampleData, SampleRecord};
pub use parser::{parse_datagram, parse_datagrams, ParseError};
