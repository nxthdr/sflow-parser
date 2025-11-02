//! sFlow v5 data models
//!
//! This module contains the data structures representing sFlow v5 datagrams
//! as defined in <https://sflow.org/sflow_version_5.txt>

use std::net::{Ipv4Addr, Ipv6Addr};

/// MAC address (6 bytes)
///
/// Represents a 48-bit IEEE 802 MAC address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum DatagramVersion {
    Version5 = 5,
}

/// Address types supported by sFlow
///
/// # XDR Definition ([sFlow v5](https://sflow.org/sflow_version_5.txt))
///
/// ```text
/// enum address_type {
///    UNKNOWN = 0,
///    IP_V4   = 1,
///    IP_V6   = 2
/// }
///
/// union address (address_type type) {
///    case UNKNOWN:
///       void;
///    case IP_V4:
///       ip_v4 ip;
///    case IP_V6:
///       ip_v6 ip;
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Address {
    /// Unknown address type
    Unknown,
    /// IPv4 address
    IPv4(Ipv4Addr),
    /// IPv6 address
    IPv6(Ipv6Addr),
}

/// Data format identifier
///
/// Encodes enterprise ID and format number in a single 32-bit value.
/// Top 20 bits = enterprise ID, bottom 12 bits = format number.
///
/// # XDR Definition ([sFlow v5](https://sflow.org/sflow_version_5.txt))
///
/// ```text
/// typedef unsigned int data_format;
/// /* The data_format uniquely identifies the format of an opaque structure in
///    the sFlow specification. For example, the combination of enterprise = 0
///    and format = 1 identifies the "sampled_header" flow_data structure. */
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
///
/// Identifies the source of the data. Top 8 bits = source type, bottom 24 bits = index.
///
/// # XDR Definition ([sFlow v5](https://sflow.org/sflow_version_5.txt))
///
/// ```text
/// typedef unsigned int sflow_data_source;
/// /* The sflow_data_source is encoded as follows:
///    The most significant byte of the sflow_data_source is used to indicate the type of
///    sFlowDataSource (e.g. ifIndex, smonVlanDataSource, entPhysicalEntry) and the lower
///    three bytes contain the relevant index value. */
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
///
/// Used when the index value exceeds 24 bits (16,777,215).
///
/// # XDR Definition ([sFlow v5](https://sflow.org/sflow_version_5.txt))
///
/// ```text
/// struct sflow_data_source_expanded {
///    unsigned int source_id_type;  /* sFlowDataSource type */
///    unsigned int source_id_index; /* sFlowDataSource index */
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DataSourceExpanded {
    /// Source type (e.g., 0 = ifIndex, 1 = smonVlanDataSource, 2 = entPhysicalEntry)
    pub source_id_type: u32,
    /// Source index value
    pub source_id_index: u32,
}

/// Interface identifier
///
/// Compact encoding for interface identification. Top 2 bits indicate format:
/// - 00 = Single interface (value is ifIndex)
/// - 01 = Packet discarded (value is reason code)
/// - 10 = Multiple destination interfaces (value is number of interfaces)
///
/// # XDR Definition ([sFlow v5](https://sflow.org/sflow_version_5.txt))
///
/// ```text
/// typedef unsigned int interface;
/// /* Encoding of the interface value:
///    Bits 31-30: Format
///       00 = ifIndex (0-0x3FFFFFFF)
///       01 = Packet discarded
///       10 = Multiple destinations
///    Bits 29-0: Value */
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
///
/// Used when the interface index exceeds 30 bits (1,073,741,823).
///
/// # XDR Definition ([sFlow v5](https://sflow.org/sflow_version_5.txt))
///
/// ```text
/// struct interface_expanded {
///    unsigned int format;        /* interface format */
///    unsigned int value;         /* interface value,
///                                   Note: 0xFFFFFFFF is the maximum value and must be used
///                                   to indicate traffic originating or terminating in device
///                                   (do not use 0x3FFFFFFF value from compact encoding example) */
/// }
/// ```
///
/// **ERRATUM:** 0xFFFFFFFF is the maximum value and must be used to indicate traffic
/// originating or terminating in device (do not use 0x3FFFFFFF value from compact encoding example).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct InterfaceExpanded {
    /// Interface format (0 = ifIndex, 1 = packet discarded, 2 = multiple destinations)
    pub format: u32,
    /// Interface value
    /// **ERRATUM:** 0xFFFFFFFF indicates traffic originating or terminating in device
    pub value: u32,
}

/// Flow data types
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
    /// Extended URL - Format (0,1005) - DEPRECATED
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
    /// Extended OpenFlow v1 - Format (0,1017) - DEPRECATED
    ExtendedOpenFlowV1(crate::models::record_flows::ExtendedOpenFlowV1),
    /// Extended NAT Port - Format (0,1020)
    ExtendedNatPort(crate::models::record_flows::ExtendedNatPort),
    /// Extended InfiniBand BTH - Format (0,1033)
    ExtendedInfiniBandBth(crate::models::record_flows::ExtendedInfiniBandBth),
    /// Extended L2 Tunnel Egress - Format (0,1021)
    ExtendedL2TunnelEgress(crate::models::record_flows::ExtendedL2TunnelEgress),
    /// Extended L2 Tunnel Ingress - Format (0,1022)
    ExtendedL2TunnelIngress(crate::models::record_flows::ExtendedL2TunnelIngress),
    /// Extended IPv4 Tunnel Egress - Format (0,1023)
    ExtendedIpv4TunnelEgress(crate::models::record_flows::ExtendedIpv4TunnelEgress),
    /// Extended IPv4 Tunnel Ingress - Format (0,1024)
    ExtendedIpv4TunnelIngress(crate::models::record_flows::ExtendedIpv4TunnelIngress),
    /// Extended IPv6 Tunnel Egress - Format (0,1025)
    ExtendedIpv6TunnelEgress(crate::models::record_flows::ExtendedIpv6TunnelEgress),
    /// Extended IPv6 Tunnel Ingress - Format (0,1026)
    ExtendedIpv6TunnelIngress(crate::models::record_flows::ExtendedIpv6TunnelIngress),
    /// Extended Decapsulate Egress - Format (0,1027)
    ExtendedDecapsulateEgress(crate::models::record_flows::ExtendedDecapsulateEgress),
    /// Extended Decapsulate Ingress - Format (0,1028)
    ExtendedDecapsulateIngress(crate::models::record_flows::ExtendedDecapsulateIngress),
    /// Extended VNI Egress - Format (0,1029)
    ExtendedVniEgress(crate::models::record_flows::ExtendedVniEgress),
    /// Extended VNI Ingress - Format (0,1030)
    ExtendedVniIngress(crate::models::record_flows::ExtendedVniIngress),
    /// Extended InfiniBand LRH - Format (0,1031)
    ExtendedInfiniBandLrh(crate::models::record_flows::ExtendedInfiniBandLrh),
    /// Extended InfiniBand GRH - Format (0,1032)
    ExtendedInfiniBandGrh(crate::models::record_flows::ExtendedInfiniBandGrh),
    /// Extended Egress Queue - Format (0,1036)
    ExtendedEgressQueue(crate::models::record_flows::ExtendedEgressQueue),
    /// Extended ACL - Format (0,1037)
    ExtendedAcl(crate::models::record_flows::ExtendedAcl),
    /// Extended Function - Format (0,1038)
    ExtendedFunction(crate::models::record_flows::ExtendedFunction),
    /// Extended Transit - Format (0,1039)
    ExtendedTransit(crate::models::record_flows::ExtendedTransit),
    /// Extended Queue - Format (0,1040)
    ExtendedQueue(crate::models::record_flows::ExtendedQueue),
    /// Extended HW Trap - Format (0,1041)
    ExtendedHwTrap(crate::models::record_flows::ExtendedHwTrap),
    /// Extended Linux Drop Reason - Format (0,1042)
    ExtendedLinuxDropReason(crate::models::record_flows::ExtendedLinuxDropReason),
    /// Extended Socket IPv4 - Format (0,2100)
    ExtendedSocketIpv4(crate::models::record_flows::ExtendedSocketIpv4),
    /// Extended Socket IPv6 - Format (0,2101)
    ExtendedSocketIpv6(crate::models::record_flows::ExtendedSocketIpv6),
    /// Extended Proxy Socket IPv4 - Format (0,2102)
    ExtendedProxySocketIpv4(crate::models::record_flows::ExtendedProxySocketIpv4),
    /// Extended Proxy Socket IPv6 - Format (0,2103)
    ExtendedProxySocketIpv6(crate::models::record_flows::ExtendedProxySocketIpv6),
    /// Memcache Operation - Format (0,2200)
    MemcacheOperation(crate::models::record_flows::MemcacheOperation),
    /// Application Operation - Format (0,2202)
    AppOperation(crate::models::record_flows::AppOperation),
    /// Application Parent Context - Format (0,2203)
    AppParentContext(crate::models::record_flows::AppParentContext),
    /// Application Initiator - Format (0,2204)
    AppInitiator(crate::models::record_flows::AppInitiator),
    /// Application Target - Format (0,2205)
    AppTarget(crate::models::record_flows::AppTarget),
    /// HTTP Request - Format (0,2206)
    HttpRequest(crate::models::record_flows::HttpRequest),
    /// Extended Proxy Request - Format (0,2207)
    ExtendedProxyRequest(crate::models::record_flows::ExtendedProxyRequest),
    /// Extended BST Egress Queue - Format (4413,1)
    ExtendedBstEgressQueue(crate::models::record_flows::ExtendedBstEgressQueue),
    /// Unknown or unparsed format
    Unknown { format: DataFormat, data: Vec<u8> },
}

/// Flow record containing flow data
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FlowRecord {
    pub flow_format: DataFormat,
    pub flow_data: FlowData,
}

/// Counter data types
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
    /// LAG Port Statistics - Format (0,7)
    LagPortStats(crate::models::record_counters::LagPortStats),
    /// InfiniBand Counters - Format (0,9)
    InfiniBandCounters(crate::models::record_counters::InfiniBandCounters),
    /// Optical SFP/QSFP Counters - Format (0,10)
    OpticalSfpQsfp(crate::models::record_counters::OpticalSfpQsfp),
    /// Processor Counters - Format (0,1001)
    Processor(crate::models::record_counters::ProcessorCounters),
    /// Radio Utilization - Format (0,1002)
    RadioUtilization(crate::models::record_counters::RadioUtilization),
    /// OpenFlow Port - Format (0,1004)
    OpenFlowPort(crate::models::record_counters::OpenFlowPort),
    /// OpenFlow Port Name - Format (0,1005)
    OpenFlowPortName(crate::models::record_counters::OpenFlowPortName),
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
    /// MIB-2 IP Group - Format (0,2007)
    Mib2IpGroup(crate::models::record_counters::Mib2IpGroup),
    /// MIB-2 ICMP Group - Format (0,2008)
    Mib2IcmpGroup(crate::models::record_counters::Mib2IcmpGroup),
    /// MIB-2 TCP Group - Format (0,2009)
    Mib2TcpGroup(crate::models::record_counters::Mib2TcpGroup),
    /// MIB-2 UDP Group - Format (0,2010)
    Mib2UdpGroup(crate::models::record_counters::Mib2UdpGroup),
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
    /// JVM Runtime - Format (0,2105)
    JvmRuntime(crate::models::record_counters::JvmRuntime),
    /// JVM Statistics - Format (0,2106)
    JvmStatistics(crate::models::record_counters::JvmStatistics),
    /// Memcache Counters - Format (0,2200) - DEPRECATED
    MemcacheCountersDeprecated(crate::models::record_counters::MemcacheCountersDeprecated),
    /// HTTP Counters - Format (0,2201)
    HttpCounters(crate::models::record_counters::HttpCounters),
    /// App Operations - Format (0,2202)
    AppOperations(crate::models::record_counters::AppOperations),
    /// App Resources - Format (0,2203)
    AppResources(crate::models::record_counters::AppResources),
    /// Memcache Counters - Format (0,2204)
    MemcacheCounters(crate::models::record_counters::MemcacheCounters),
    /// App Workers - Format (0,2206)
    AppWorkers(crate::models::record_counters::AppWorkers),
    /// Broadcom Device Buffer Utilization - Format (4413,1)
    BroadcomDeviceBuffers(crate::models::record_counters::BroadcomDeviceBuffers),
    /// Broadcom Port Buffer Utilization - Format (4413,2)
    BroadcomPortBuffers(crate::models::record_counters::BroadcomPortBuffers),
    /// Broadcom Switch ASIC Table Utilization - Format (4413,3)
    BroadcomTables(crate::models::record_counters::BroadcomTables),
    /// NVIDIA GPU Statistics - Format (5703,1)
    NvidiaGpu(crate::models::record_counters::NvidiaGpu),
    /// Unknown or unparsed format
    Unknown { format: DataFormat, data: Vec<u8> },
}

/// Counter record containing counter data
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CounterRecord {
    pub counter_format: DataFormat,
    pub counter_data: CounterData,
}

/// Compact flow sample - Format (0,1)
///
/// Contains sampled packet information with compact encoding for interfaces.
///
/// # XDR Definition ([sFlow v5](https://sflow.org/sflow_version_5.txt))
///
/// ```text
/// /* Format of a single flow sample */
/// /* opaque = sample_data; enterprise = 0; format = 1 */
///
/// struct flow_sample {
///    unsigned int sequence_number;  /* Incremented with each flow sample
///                                      generated by this sFlow Instance. */
///    sflow_data_source source_id;   /* sFlowDataSource */
///    unsigned int sampling_rate;    /* sFlowPacketSamplingRate */
///    unsigned int sample_pool;      /* Total number of packets that could have been
///                                      sampled (i.e. packets skipped by sampling process
///                                      + total number of samples) */
///    unsigned int drops;            /* Number of times that the sFlow agent detected
///                                      that a packet marked to be sampled was dropped
///                                      due to lack of resources. */
///    interface input;               /* Input interface */
///    interface output;              /* Output interface */
///    flow_record flow_records<>;    /* Information about sampled packet */
/// }
/// ```
///
/// **ERRATUM:** Sequence number clarified as incremented per "sFlow Instance" instead of "source_id".
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FlowSample {
    /// Sequence number incremented with each flow sample generated by this sFlow Instance
    /// **ERRATUM:** Clarified as "sFlow Instance" instead of "source_id"
    pub sequence_number: u32,
    /// sFlow data source identifier
    pub source_id: DataSource,
    /// Sampling rate (1 in N packets)
    pub sampling_rate: u32,
    /// Total packets that could have been sampled
    pub sample_pool: u32,
    /// Number of dropped samples due to lack of resources
    pub drops: u32,
    /// Input interface
    pub input: Interface,
    /// Output interface
    pub output: Interface,
    /// Flow records describing the sampled packet
    pub flow_records: Vec<FlowRecord>,
}

/// Compact counters sample - Format (0,2)
///
/// Contains interface and system counter statistics.
///
/// # XDR Definition ([sFlow v5](https://sflow.org/sflow_version_5.txt))
///
/// ```text
/// /* Format of a single counter sample */
/// /* opaque = sample_data; enterprise = 0; format = 2 */
///
/// struct counters_sample {
///    unsigned int sequence_number;   /* Incremented with each counter sample
///                                       generated by this sFlow Instance. */
///    sflow_data_source source_id;    /* sFlowDataSource */
///    counter_record counters<>;      /* Counters polled for this source */
/// }
/// ```
///
/// **ERRATUM:** Sequence number clarified as incremented per "sFlow Instance" instead of "source_id".
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CountersSample {
    /// Sequence number incremented with each counter sample generated by this sFlow Instance
    /// **ERRATUM:** Clarified as "sFlow Instance" instead of "source_id"
    pub sequence_number: u32,
    /// sFlow data source identifier
    pub source_id: DataSource,
    /// Counter records for this source
    pub counters: Vec<CounterRecord>,
}

/// Expanded flow sample - Format (0,3)
///
/// Flow sample with expanded encoding for large interface indices (>= 2^24).
///
/// # XDR Definition ([sFlow v5](https://sflow.org/sflow_version_5.txt))
///
/// ```text
/// /* Format of a single expanded flow sample */
/// /* opaque = sample_data; enterprise = 0; format = 3 */
///
/// struct flow_sample_expanded {
///    unsigned int sequence_number;  /* Incremented with each flow sample
///                                      generated by this sFlow Instance. */
///    sflow_data_source_expanded source_id; /* sFlowDataSource */
///    unsigned int sampling_rate;    /* sFlowPacketSamplingRate */
///    unsigned int sample_pool;      /* Total number of packets that could have been
///                                      sampled (i.e. packets skipped by sampling process
///                                      + total number of samples) */
///    unsigned int drops;            /* Number of times that the sFlow agent detected
///                                      that a packet marked to be sampled was dropped
///                                      due to lack of resources. */
///    interface_expanded input;      /* Input interface */
///    interface_expanded output;     /* Output interface */
///    flow_record flow_records<>;    /* Information about sampled packet */
/// }
/// ```
///
/// **ERRATUM:** Sequence number clarified as incremented per "sFlow Instance" instead of "source_id".
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FlowSampleExpanded {
    /// Sequence number incremented with each flow sample generated by this sFlow Instance
    /// **ERRATUM:** Clarified as "sFlow Instance" instead of "source_id"
    pub sequence_number: u32,
    /// Expanded sFlow data source identifier
    pub source_id: DataSourceExpanded,
    /// Sampling rate (1 in N packets)
    pub sampling_rate: u32,
    /// Total packets that could have been sampled
    pub sample_pool: u32,
    /// Number of dropped samples due to lack of resources
    pub drops: u32,
    /// Input interface (expanded)
    pub input: InterfaceExpanded,
    /// Output interface (expanded)
    pub output: InterfaceExpanded,
    /// Flow records describing the sampled packet
    pub flow_records: Vec<FlowRecord>,
}

/// Expanded counter sample - Format (0,4)
///
/// Counter sample with expanded encoding for large interface indices (>= 2^24).
///
/// # XDR Definition ([sFlow v5](https://sflow.org/sflow_version_5.txt))
///
/// ```text
/// /* Format of a single expanded counters sample */
/// /* opaque = sample_data; enterprise = 0; format = 4 */
///
/// struct counters_sample_expanded {
///    unsigned int sequence_number;   /* Incremented with each counter sample
///                                       generated by this sFlow Instance. */
///    sflow_data_source_expanded source_id; /* sFlowDataSource */
///    counter_record counters<>;      /* Counters polled for this source */
/// }
/// ```
///
/// **ERRATUM:** Sequence number clarified as incremented per "sFlow Instance" instead of "source_id".
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CountersSampleExpanded {
    /// Sequence number incremented with each counter sample generated by this sFlow Instance
    /// **ERRATUM:** Clarified as "sFlow Instance" instead of "source_id"
    pub sequence_number: u32,
    /// Expanded sFlow data source identifier
    pub source_id: DataSourceExpanded,
    /// Counter records for this source
    pub counters: Vec<CounterRecord>,
}

/// Discarded packet sample - Format (0,5)
///
/// # XDR Definition ([sFlow Drops](https://sflow.org/sflow_drops.txt))
///
/// ```text
/// /* Format of a single discarded packet event */
/// /* opaque = sample_data; enterprise = 0; format = 5 */
/// struct discarded_packet {
///    unsigned int sequence_number;  /* Incremented with each discarded packet
///                                      record generated by this source_id. */
///    sflow_data_source_expanded source_id; /* sFlowDataSource */
///    unsigned int drops;            /* Number of times that the sFlow agent
///                                      detected that a discarded packet record
///                                      was dropped by the rate limit, or because
///                                      of a lack of resources. The drops counter
///                                      reports the total number of drops detected
///                                      since the agent was last reset. Note: An
///                                      agent that cannot detect drops will always
///                                      report zero. */
///    unsigned int inputifindex;     /* If set, ifIndex of interface packet was
///                                      received on. Zero if unknown. Must identify
///                                      physical port consistent with flow_sample
///                                      input interface. */
///    unsigned int outputifindex;    /* If set, ifIndex for egress drops. Zero
///                                      otherwise. Must identify physical port
///                                      consistent with flow_sample output
///                                      interface. */
///    drop_reason reason;            /* Reason for dropping packet. */
///    flow_record discard_records<>; /* Information about the discarded packet. */
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DiscardedPacket {
    /// Sequence number incremented with each discarded packet record
    pub sequence_number: u32,

    /// sFlow data source
    pub source_id: DataSourceExpanded,

    /// Number of discarded packet records dropped by rate limit or lack of resources
    pub drops: u32,

    /// Input interface index (0 if unknown)
    pub input_ifindex: u32,

    /// Output interface index (0 if not egress drop)
    pub output_ifindex: u32,

    /// Reason for dropping the packet
    pub reason: crate::models::record_flows::DropReason,

    /// Flow records describing the discarded packet
    pub flow_records: Vec<FlowRecord>,
}

/// Sample data types
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum SampleData {
    FlowSample(FlowSample),
    CountersSample(CountersSample),
    FlowSampleExpanded(FlowSampleExpanded),
    CountersSampleExpanded(CountersSampleExpanded),
    DiscardedPacket(DiscardedPacket),
    Unknown { format: DataFormat, data: Vec<u8> },
}

/// Sample record
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SampleRecord {
    pub sample_type: DataFormat,
    pub sample_data: SampleData,
}

/// sFlow v5 datagram
///
/// Top-level structure containing one or more samples.
///
/// # XDR Definition ([sFlow v5](https://sflow.org/sflow_version_5.txt))
///
/// ```text
/// /* sFlow version 5 datagram */
///
/// struct sflow_datagram {
///    unsigned int version;        /* sFlow version (5) */
///    address agent_address;       /* IP address of sampling agent */
///    unsigned int sub_agent_id;   /* Used to distinguish multiple sFlow instances
///                                    on the same agent */
///    unsigned int sequence_number;/* Incremented with each sample datagram generated
///                                    by a sub-agent within an agent */
///    unsigned int uptime;         /* Current time (in milliseconds since device
///                                    last booted). Should be set as close to
///                                    datagram transmission time as possible. */
///    sample_record samples<>;     /* An array of sample records */
/// }
/// ```
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SFlowDatagram {
    /// sFlow protocol version (always 5)
    pub version: DatagramVersion,
    /// IP address of the sFlow agent
    pub agent_address: Address,
    /// Sub-agent identifier (distinguishes multiple sFlow instances on same agent)
    pub sub_agent_id: u32,
    /// Datagram sequence number (incremented with each datagram from this sub-agent)
    pub sequence_number: u32,
    /// Device uptime in milliseconds since last boot
    pub uptime: u32,
    /// Array of sample records
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
