//! Unit tests for sFlow parser
//!
//! Tests are organized into modules matching the source code structure:
//! - core_types: DataFormat, DataSource, Interface, Address, etc.
//! - flow_records: Flow record structures
//! - counter_records: Counter record structures
//! - enums: FlowData, CounterData, SampleData variants
//! - validation: Validation against official sFlow specification

mod unit;
mod validation;
