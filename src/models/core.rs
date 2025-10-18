//! sFlow v5 data models
//!
//! This module contains the data structures representing sFlow v5 datagrams
//! as defined in https://sflow.org/sflow_version_5.txt

use std::net::{Ipv4Addr, Ipv6Addr};

/// sFlow datagram version
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatagramVersion {
    Version5 = 5,
}

/// Address types supported by sFlow
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Address {
    Unknown,
    IPv4(Ipv4Addr),
    IPv6(Ipv6Addr),
}

/// Data format identifier
/// Top 20 bits = enterprise ID, bottom 12 bits = format number
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataFormat(pub u32);

impl DataFormat {
    pub fn new(enterprise: u32, format: u32) -> Self {
        Self((enterprise << 12) | (format & 0xFFF))
    }

    pub fn enterprise(&self) -> u32 {
        self.0 >> 12
    }

    pub fn format(&self) -> u32 {
        self.0 & 0xFFF
    }
}

/// sFlow data source identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataSource(pub u32);

impl DataSource {
    pub fn new(source_type: u8, index: u32) -> Self {
        Self(((source_type as u32) << 24) | (index & 0xFFFFFF))
    }

    pub fn source_type(&self) -> u8 {
        (self.0 >> 24) as u8
    }

    pub fn index(&self) -> u32 {
        self.0 & 0xFFFFFF
    }
}

/// Expanded data source (for ifIndex >= 2^24)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataSourceExpanded {
    pub source_id_type: u32,
    pub source_id_index: u32,
}

/// Interface identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Interface(pub u32);

impl Interface {
    pub fn format(&self) -> u8 {
        (self.0 >> 30) as u8
    }

    pub fn value(&self) -> u32 {
        self.0 & 0x3FFFFFFF
    }

    pub fn is_single(&self) -> bool {
        self.format() == 0
    }

    pub fn is_discarded(&self) -> bool {
        self.format() == 1
    }

    pub fn is_multiple(&self) -> bool {
        self.format() == 2
    }
}

/// Expanded interface (for ifIndex >= 2^24)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterfaceExpanded {
    pub format: u32,
    pub value: u32,
}

/// Flow record containing flow data
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowRecord {
    pub flow_format: DataFormat,
    pub flow_data: Vec<u8>,
}

/// Counter record containing counter data
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CounterRecord {
    pub counter_format: DataFormat,
    pub counter_data: Vec<u8>,
}

/// Compact flow sample (enterprise=0, format=1)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowSample {
    pub sequence_number: u32,
    pub source_id: DataSource,
    pub sampling_rate: u32,
    pub sample_pool: u32,
    pub drops: u32,
    pub input: Interface,
    pub output: Interface,
    pub flow_records: Vec<FlowRecord>,
}

/// Compact counter sample (enterprise=0, format=2)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CountersSample {
    pub sequence_number: u32,
    pub source_id: DataSource,
    pub counters: Vec<CounterRecord>,
}

/// Expanded flow sample (enterprise=0, format=3)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowSampleExpanded {
    pub sequence_number: u32,
    pub source_id: DataSourceExpanded,
    pub sampling_rate: u32,
    pub sample_pool: u32,
    pub drops: u32,
    pub input: InterfaceExpanded,
    pub output: InterfaceExpanded,
    pub flow_records: Vec<FlowRecord>,
}

/// Expanded counter sample (enterprise=0, format=4)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CountersSampleExpanded {
    pub sequence_number: u32,
    pub source_id: DataSourceExpanded,
    pub counters: Vec<CounterRecord>,
}

/// Sample data types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SampleData {
    FlowSample(FlowSample),
    CountersSample(CountersSample),
    FlowSampleExpanded(FlowSampleExpanded),
    CountersSampleExpanded(CountersSampleExpanded),
    Unknown { format: DataFormat, data: Vec<u8> },
}

/// Sample record
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SampleRecord {
    pub sample_type: DataFormat,
    pub sample_data: SampleData,
}

/// sFlow v5 datagram
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SFlowDatagram {
    pub version: DatagramVersion,
    pub agent_address: Address,
    pub sub_agent_id: u32,
    pub sequence_number: u32,
    pub uptime: u32,
    pub samples: Vec<SampleRecord>,
}

impl SFlowDatagram {
    /// Create a new sFlow v5 datagram
    pub fn new(
        agent_address: Address,
        sub_agent_id: u32,
        sequence_number: u32,
        uptime: u32,
    ) -> Self {
        Self {
            version: DatagramVersion::Version5,
            agent_address,
            sub_agent_id,
            sequence_number,
            uptime,
            samples: Vec::new(),
        }
    }
}
