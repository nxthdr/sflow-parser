//! Flow record data structures
//!
//! These represent the actual packet data captured in flow samples.
//! Enterprise = 0 (sFlow.org standard formats)

use std::net::{Ipv4Addr, Ipv6Addr};

/// Header protocol types for sampled headers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderProtocol {
    EthernetIso88023 = 1,
    Iso88024TokenBus = 2,
    Iso88025TokenRing = 3,
    Fddi = 4,
    FrameRelay = 5,
    X25 = 6,
    Ppp = 7,
    Smds = 8,
    Aal5 = 9,
    Aal5Ip = 10,
    Ipv4 = 11,
    Ipv6 = 12,
    Mpls = 13,
    Pos = 14,
    Ieee80211Mac = 15,
    Ieee80211Ampdu = 16,
    Ieee80211Amsdu = 17,
}

/// Sampled Header - Format (0,1)
/// Raw packet header captured from the wire
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SampledHeader {
    /// Protocol of the sampled packet
    pub protocol: u32,

    /// Original length of the packet (before sampling)
    pub frame_length: u32,

    /// Number of bytes stripped from the packet before sampling
    pub stripped: u32,

    /// Raw header bytes
    pub header: Vec<u8>,
}

/// Sampled Ethernet Frame - Format (0,2)
/// Ethernet frame header information
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SampledEthernet {
    /// Length of MAC packet in bytes
    pub length: u32,

    /// Source MAC address (6 bytes)
    pub src_mac: [u8; 6],

    /// Destination MAC address (6 bytes)
    pub dst_mac: [u8; 6],

    /// Ethernet type
    pub eth_type: u32,
}

/// Sampled IPv4 - Format (0,3)
/// IPv4 header information
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SampledIpv4 {
    /// Length of IP packet in bytes
    pub length: u32,

    /// IP Protocol (TCP=6, UDP=17, etc.)
    pub protocol: u32,

    /// Source IP address
    pub src_ip: Ipv4Addr,

    /// Destination IP address
    pub dst_ip: Ipv4Addr,

    /// Source port (for TCP/UDP)
    pub src_port: u32,

    /// Destination port (for TCP/UDP)
    pub dst_port: u32,

    /// TCP flags
    pub tcp_flags: u32,

    /// Type of Service
    pub tos: u32,
}

/// Sampled IPv6 - Format (0,4)
/// IPv6 header information
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SampledIpv6 {
    /// Length of IP packet in bytes
    pub length: u32,

    /// IP Protocol (TCP=6, UDP=17, etc.)
    pub protocol: u32,

    /// Source IP address
    pub src_ip: Ipv6Addr,

    /// Destination IP address
    pub dst_ip: Ipv6Addr,

    /// Source port (for TCP/UDP)
    pub src_port: u32,

    /// Destination port (for TCP/UDP)
    pub dst_port: u32,

    /// TCP flags
    pub tcp_flags: u32,

    /// Priority (traffic class)
    pub priority: u32,
}

/// Extended Switch Data - Format (0,1001)
/// Layer 2 switching information
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedSwitch {
    /// Source VLAN ID
    pub src_vlan: u32,

    /// Source priority (802.1p)
    pub src_priority: u32,

    /// Destination VLAN ID
    pub dst_vlan: u32,

    /// Destination priority (802.1p)
    pub dst_priority: u32,
}

/// Extended Router Data - Format (0,1002)
/// Layer 3 routing information
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedRouter {
    /// IP address of next hop router
    pub next_hop: crate::models::core::Address,

    /// Source subnet mask bits
    pub src_mask_len: u32,

    /// Destination subnet mask bits
    pub dst_mask_len: u32,
}

/// AS Path Type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AsPathType {
    AsSet = 1,
    AsSequence = 2,
}

/// AS Path Segment
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsPathSegment {
    pub path_type: u32,
    pub path_length: u32,
    pub path: Vec<u32>,
}

/// Extended Gateway Data - Format (0,1003)
/// BGP routing information
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedGateway {
    /// IP address of the border router
    pub next_hop: crate::models::core::Address,

    /// Autonomous system number
    pub as_number: u32,

    /// Source AS
    pub src_as: u32,

    /// Source peer AS
    pub src_peer_as: u32,

    /// Number of AS path segments
    pub as_path_segments: Vec<AsPathSegment>,

    /// BGP communities
    pub communities: Vec<u32>,

    /// Local preference
    pub local_pref: u32,
}

/// Extended User Data - Format (0,1004)
/// Application-level user information
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedUser {
    /// Source character set (MIBEnum)
    pub src_charset: u32,

    /// Source user ID
    pub src_user: String,

    /// Destination character set (MIBEnum)
    pub dst_charset: u32,

    /// Destination user ID
    pub dst_user: String,
}

/// URL Direction
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UrlDirection {
    Source = 1,
    Destination = 2,
}

/// Extended URL Data - Format (0,1005)
/// HTTP request information
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedUrl {
    /// Direction (source or destination)
    pub direction: u32,

    /// URL string (HTTP request-line)
    pub url: String,

    /// Host header from HTTP request
    pub host: String,
}

/// Extended MPLS Data - Format (0,1006)
/// MPLS label stack information
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedMpls {
    /// Next hop address
    pub next_hop: crate::models::core::Address,

    /// Input label stack
    pub in_label_stack: Vec<u32>,

    /// Output label stack
    pub out_label_stack: Vec<u32>,
}

/// Extended NAT Data - Format (0,1007)
/// Network Address Translation information
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedNat {
    /// Source address type
    pub src_address: crate::models::core::Address,

    /// Destination address type
    pub dst_address: crate::models::core::Address,
}

/// Extended MPLS Tunnel - Format (0,1008)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedMplsTunnel {
    /// Tunnel name
    pub tunnel_name: String,

    /// Tunnel ID
    pub tunnel_id: u32,

    /// Tunnel cost
    pub tunnel_cos: u32,
}

/// Extended MPLS VC - Format (0,1009)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedMplsVc {
    /// VC instance name
    pub vc_instance_name: String,

    /// VC ID
    pub vll_vc_id: u32,

    /// VC label
    pub vc_label: u32,

    /// VC COS
    pub vc_cos: u32,
}

/// Extended MPLS FEC - Format (0,1010)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedMplsFec {
    /// FEC address prefix
    pub fec_addr_prefix: crate::models::core::Address,

    /// FEC prefix length
    pub fec_prefix_len: u32,
}

/// Extended MPLS LVP FEC - Format (0,1011)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedMplsLvpFec {
    /// FEC address prefix length
    pub fec_addr_prefix_len: u32,
}

/// Extended VLAN Tunnel - Format (0,1012)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedVlanTunnel {
    /// Stack of VLAN tags
    pub vlan_stack: Vec<u32>,
}

/// Extended 802.11 Payload - Format (0,1014)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extended80211Payload {
    /// Cipher suite
    pub cipher_suite: u32,

    /// Received signal strength
    pub rssi: u32,

    /// Noise level
    pub noise: u32,

    /// Channel
    pub channel: u32,

    /// Speed (Mbps)
    pub speed: u32,
}

/// Extended 802.11 RX - Format (0,1015)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extended80211Rx {
    /// SSID
    pub ssid: String,

    /// BSSID (MAC address)
    pub bssid: [u8; 6],

    /// Version
    pub version: u32,

    /// Channel
    pub channel: u32,

    /// Speed (Mbps)
    pub speed: u64,

    /// RSSI
    pub rssi: u32,

    /// Noise
    pub noise: u32,
}

/// Extended 802.11 TX - Format (0,1016)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extended80211Tx {
    /// SSID
    pub ssid: String,

    /// BSSID (MAC address)
    pub bssid: [u8; 6],

    /// Version
    pub version: u32,

    /// Transmissions
    pub transmissions: u32,

    /// Packet duration (microseconds)
    pub packet_duration: u32,

    /// Retransmissions
    pub retrans_duration: u32,

    /// Channel
    pub channel: u32,

    /// Speed (Mbps)
    pub speed: u64,

    /// Power (mW)
    pub power: u32,
}
