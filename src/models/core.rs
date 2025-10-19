//! sFlow v5 data models
//!
//! This module contains the data structures representing sFlow v5 datagrams
//! as defined in <https://sflow.org/sflow_version_5.txt>

use std::net::{Ipv4Addr, Ipv6Addr};

/// MAC address (6 bytes)
///
/// Represents a 48-bit IEEE 802 MAC address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacAddress(pub [u8; 6]);

impl MacAddress {
    /// Create a new MAC address from 6 bytes
    pub const fn new(bytes: [u8; 6]) -> Self {
        Self(bytes)
    }

    /// Get the MAC address as a byte array
    pub const fn as_bytes(&self) -> &[u8; 6] {
        &self.0
    }

    /// Check if this is a broadcast address (FF:FF:FF:FF:FF:FF)
    pub fn is_broadcast(&self) -> bool {
        self.0 == [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
    }

    /// Check if this is a multicast address (first byte has LSB set)
    pub fn is_multicast(&self) -> bool {
        self.0[0] & 0x01 != 0
    }

    /// Check if this is a unicast address
    pub fn is_unicast(&self) -> bool {
        !self.is_multicast()
    }
}

impl std::fmt::Display for MacAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

impl From<[u8; 6]> for MacAddress {
    fn from(bytes: [u8; 6]) -> Self {
        Self(bytes)
    }
}

impl From<MacAddress> for [u8; 6] {
    fn from(mac: MacAddress) -> Self {
        mac.0
    }
}

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

/// Flow data types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowData {
    /// Sampled Header - Format (0,1)
    SampledHeader(crate::models::record_flows::SampledHeader),
    /// Sampled Ethernet - Format (0,2)
    SampledEthernet(crate::models::record_flows::SampledEthernet),
    /// Sampled IPv4 - Format (0,3)
    SampledIpv4(crate::models::record_flows::SampledIpv4),
    /// Sampled IPv6 - Format (0,4)
    SampledIpv6(crate::models::record_flows::SampledIpv6),
    /// Extended Switch - Format (0,1001)
    ExtendedSwitch(crate::models::record_flows::ExtendedSwitch),
    /// Extended Router - Format (0,1002)
    ExtendedRouter(crate::models::record_flows::ExtendedRouter),
    /// Extended Gateway - Format (0,1003)
    ExtendedGateway(crate::models::record_flows::ExtendedGateway),
    /// Extended User - Format (0,1004)
    ExtendedUser(crate::models::record_flows::ExtendedUser),
    /// Extended URL - Format (0,1005)
    /// Note: This format is deprecated but kept for backward compatibility
    ExtendedUrl(crate::models::record_flows::ExtendedUrl),
    /// Extended MPLS - Format (0,1006)
    ExtendedMpls(crate::models::record_flows::ExtendedMpls),
    /// Extended NAT - Format (0,1007)
    ExtendedNat(crate::models::record_flows::ExtendedNat),
    /// Extended MPLS Tunnel - Format (0,1008)
    ExtendedMplsTunnel(crate::models::record_flows::ExtendedMplsTunnel),
    /// Extended MPLS VC - Format (0,1009)
    ExtendedMplsVc(crate::models::record_flows::ExtendedMplsVc),
    /// Extended MPLS FEC - Format (0,1010)
    ExtendedMplsFec(crate::models::record_flows::ExtendedMplsFec),
    /// Extended MPLS LVP FEC - Format (0,1011)
    ExtendedMplsLvpFec(crate::models::record_flows::ExtendedMplsLvpFec),
    /// Extended VLAN Tunnel - Format (0,1012)
    ExtendedVlanTunnel(crate::models::record_flows::ExtendedVlanTunnel),
    /// Extended 802.11 Payload - Format (0,1013)
    Extended80211Payload(crate::models::record_flows::Extended80211Payload),
    /// Extended 802.11 RX - Format (0,1014)
    Extended80211Rx(crate::models::record_flows::Extended80211Rx),
    /// Extended 802.11 TX - Format (0,1015)
    Extended80211Tx(crate::models::record_flows::Extended80211Tx),
    /// Extended 802.11 Aggregation - Format (0,1016)
    Extended80211Aggregation(crate::models::record_flows::Extended80211Aggregation),
    /// Extended Socket IPv4 - Format (0,2100)
    ExtendedSocketIpv4(crate::models::record_flows::ExtendedSocketIpv4),
    /// Extended Socket IPv6 - Format (0,2101)
    ExtendedSocketIpv6(crate::models::record_flows::ExtendedSocketIpv6),
    /// Application Operation - Format (0,2202)
    AppOperation(crate::models::record_flows::AppOperation),
    /// Application Parent Context - Format (0,2203)
    AppParentContext(crate::models::record_flows::AppParentContext),
    /// Unknown or unparsed format
    Unknown { format: DataFormat, data: Vec<u8> },
}

/// Flow record containing flow data
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowRecord {
    pub flow_format: DataFormat,
    pub flow_data: FlowData,
}

/// Counter data types
#[derive(Debug, Clone, PartialEq)]
pub enum CounterData {
    /// Generic Interface Counters - Format (0,1)
    GenericInterface(crate::models::record_counters::GenericInterfaceCounters),
    /// Ethernet Interface Counters - Format (0,2)
    EthernetInterface(crate::models::record_counters::EthernetInterfaceCounters),
    /// Token Ring Counters - Format (0,3)
    TokenRing(crate::models::record_counters::TokenRingCounters),
    /// 100BaseVG Counters - Format (0,4)
    Vg100Interface(crate::models::record_counters::Vg100InterfaceCounters),
    /// VLAN Counters - Format (0,5)
    Vlan(crate::models::record_counters::VlanCounters),
    /// IEEE 802.11 Counters - Format (0,6)
    Ieee80211(crate::models::record_counters::Ieee80211Counters),
    /// Processor Counters - Format (0,1001)
    Processor(crate::models::record_counters::ProcessorCounters),
    /// Radio Utilization - Format (0,1002)
    RadioUtilization(crate::models::record_counters::RadioUtilization),
    /// Host Description - Format (0,2000)
    HostDescription(crate::models::record_counters::HostDescription),
    /// Host Adapters - Format (0,2001)
    HostAdapters(crate::models::record_counters::HostAdapters),
    /// Host Parent - Format (0,2002)
    HostParent(crate::models::record_counters::HostParent),
    /// Host CPU - Format (0,2003)
    HostCpu(crate::models::record_counters::HostCpu),
    /// Host Memory - Format (0,2004)
    HostMemory(crate::models::record_counters::HostMemory),
    /// Host Disk I/O - Format (0,2005)
    HostDiskIo(crate::models::record_counters::HostDiskIo),
    /// Host Network I/O - Format (0,2006)
    HostNetIo(crate::models::record_counters::HostNetIo),
    /// Virtual Node - Format (0,2100)
    VirtualNode(crate::models::record_counters::VirtualNode),
    /// Virtual CPU - Format (0,2101)
    VirtualCpu(crate::models::record_counters::VirtualCpu),
    /// Virtual Memory - Format (0,2102)
    VirtualMemory(crate::models::record_counters::VirtualMemory),
    /// Virtual Disk I/O - Format (0,2103)
    VirtualDiskIo(crate::models::record_counters::VirtualDiskIo),
    /// Virtual Network I/O - Format (0,2104)
    VirtualNetIo(crate::models::record_counters::VirtualNetIo),
    /// OpenFlow Port - Format (0,1004)
    OpenFlowPort(crate::models::record_counters::OpenFlowPort),
    /// OpenFlow Port Name - Format (0,1005)
    OpenFlowPortName(crate::models::record_counters::OpenFlowPortName),
    /// App Operations - Format (0,2202)
    AppOperations(crate::models::record_counters::AppOperations),
    /// App Resources - Format (0,2203)
    AppResources(crate::models::record_counters::AppResources),
    /// App Workers - Format (0,2206)
    AppWorkers(crate::models::record_counters::AppWorkers),
    /// Unknown or unparsed format
    Unknown { format: DataFormat, data: Vec<u8> },
}

/// Counter record containing counter data
#[derive(Debug, Clone, PartialEq)]
pub struct CounterRecord {
    pub counter_format: DataFormat,
    pub counter_data: CounterData,
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

/// Compact counters sample (enterprise=0, format=2)
#[derive(Debug, Clone, PartialEq)]
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
#[derive(Debug, Clone, PartialEq)]
pub struct CountersSampleExpanded {
    pub sequence_number: u32,
    pub source_id: DataSourceExpanded,
    pub counters: Vec<CounterRecord>,
}

/// Sample data types
#[derive(Debug, Clone, PartialEq)]
pub enum SampleData {
    FlowSample(FlowSample),
    CountersSample(CountersSample),
    FlowSampleExpanded(FlowSampleExpanded),
    CountersSampleExpanded(CountersSampleExpanded),
    Unknown { format: DataFormat, data: Vec<u8> },
}

/// Sample record
#[derive(Debug, Clone, PartialEq)]
pub struct SampleRecord {
    pub sample_type: DataFormat,
    pub sample_data: SampleData,
}

/// sFlow v5 datagram
#[derive(Debug, Clone, PartialEq)]
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
