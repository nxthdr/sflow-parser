//! Flow record data structures
//!
//! These represent the actual packet data captured in flow samples.
//! Enterprise = 0 (sFlow.org standard formats)

use std::net::{Ipv4Addr, Ipv6Addr};

/// Header protocol types for sampled headers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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

impl HeaderProtocol {
    /// Convert from u32 value to HeaderProtocol enum
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            1 => Some(HeaderProtocol::EthernetIso88023),
            2 => Some(HeaderProtocol::Iso88024TokenBus),
            3 => Some(HeaderProtocol::Iso88025TokenRing),
            4 => Some(HeaderProtocol::Fddi),
            5 => Some(HeaderProtocol::FrameRelay),
            6 => Some(HeaderProtocol::X25),
            7 => Some(HeaderProtocol::Ppp),
            8 => Some(HeaderProtocol::Smds),
            9 => Some(HeaderProtocol::Aal5),
            10 => Some(HeaderProtocol::Aal5Ip),
            11 => Some(HeaderProtocol::Ipv4),
            12 => Some(HeaderProtocol::Ipv6),
            13 => Some(HeaderProtocol::Mpls),
            14 => Some(HeaderProtocol::Pos),
            15 => Some(HeaderProtocol::Ieee80211Mac),
            16 => Some(HeaderProtocol::Ieee80211Ampdu),
            17 => Some(HeaderProtocol::Ieee80211Amsdu),
            _ => None,
        }
    }
}

impl std::fmt::Display for HeaderProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HeaderProtocol::EthernetIso88023 => write!(f, "Ethernet (ISO 802.3)"),
            HeaderProtocol::Iso88024TokenBus => write!(f, "ISO 802.4 Token Bus"),
            HeaderProtocol::Iso88025TokenRing => write!(f, "ISO 802.5 Token Ring"),
            HeaderProtocol::Fddi => write!(f, "FDDI"),
            HeaderProtocol::FrameRelay => write!(f, "Frame Relay"),
            HeaderProtocol::X25 => write!(f, "X.25"),
            HeaderProtocol::Ppp => write!(f, "PPP"),
            HeaderProtocol::Smds => write!(f, "SMDS"),
            HeaderProtocol::Aal5 => write!(f, "AAL5"),
            HeaderProtocol::Aal5Ip => write!(f, "AAL5 IP"),
            HeaderProtocol::Ipv4 => write!(f, "IPv4"),
            HeaderProtocol::Ipv6 => write!(f, "IPv6"),
            HeaderProtocol::Mpls => write!(f, "MPLS"),
            HeaderProtocol::Pos => write!(f, "POS"),
            HeaderProtocol::Ieee80211Mac => write!(f, "IEEE 802.11 MAC"),
            HeaderProtocol::Ieee80211Ampdu => write!(f, "IEEE 802.11 A-MPDU"),
            HeaderProtocol::Ieee80211Amsdu => write!(f, "IEEE 802.11 A-MSDU"),
        }
    }
}

/// Sampled Header - Format (0,1)
///
/// Raw packet header captured from the wire
///
/// # XDR Definition (sFlow v5)
///
/// ```text
/// /* Raw Packet Header */
/// /* opaque = flow_data; enterprise = 0; format = 1 */
///
/// struct sampled_header {
///     header_protocol protocol;  /* Format of sampled header */
///     unsigned int frame_length; /* Original length of packet before sampling */
///     unsigned int stripped;     /* Number of octets removed from packet */
///     opaque header<>;           /* Header bytes */
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SampledHeader {
    /// Protocol of the sampled packet
    pub protocol: HeaderProtocol,

    /// Original length of the packet (before sampling)
    pub frame_length: u32,

    /// Number of bytes stripped from the packet before sampling
    pub stripped: u32,

    /// Raw header bytes
    pub header: Vec<u8>,
}

/// Sampled Ethernet Frame - Format (0,2)
///
/// Ethernet frame header information
///
/// # XDR Definition (sFlow v5)
///
/// ```text
/// /* Ethernet Frame Data */
/// /* opaque = flow_data; enterprise = 0; format = 2 */
///
/// struct sampled_ethernet {
///     unsigned int length;   /* The length of the MAC packet received on the
///                               network, excluding lower layer encapsulations
///                               and framing bits but including FCS octets */
///     mac src_mac;           /* Source MAC address */
///     mac dst_mac;           /* Destination MAC address */
///     unsigned int type;     /* Ethernet packet type */
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SampledEthernet {
    /// Length of MAC packet in bytes
    pub length: u32,

    /// Source MAC address
    pub src_mac: crate::models::MacAddress,

    /// Destination MAC address
    pub dst_mac: crate::models::MacAddress,

    /// Ethernet type (spec: type)
    pub eth_type: u32,
}

/// Sampled IPv4 - Format (0,3)
///
/// IPv4 packet header information
///
/// # XDR Definition (sFlow v5)
///
/// ```text
/// /* Packet IP version 4 data */
/// /* opaque = flow_data; enterprise = 0; format = 3 */
///
/// struct sampled_ipv4 {
///     unsigned int length;     /* Length of IP packet excluding lower layer encapsulations */
///     unsigned int protocol;   /* IP Protocol type (e.g., TCP = 6, UDP = 17) */
///     ip_v4 src_ip;            /* Source IP Address */
///     ip_v4 dst_ip;            /* Destination IP Address */
///     unsigned int src_port;   /* TCP/UDP source port number or equivalent */
///     unsigned int dst_port;   /* TCP/UDP destination port number or equivalent */
///     unsigned int tcp_flags;  /* TCP flags */
///     unsigned int tos;        /* IP type of service */
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
///
/// IPv6 packet header information
///
/// # XDR Definition (sFlow v5)
///
/// ```text
/// /* Packet IP Version 6 Data */
/// /* opaque = flow_data; enterprise = 0; format = 4 */
///
/// struct sampled_ipv6 {
///     unsigned int length;     /* Length of IP packet excluding lower layer encapsulations */
///     unsigned int protocol;   /* IP next header (e.g., TCP = 6, UDP = 17) */
///     ip_v6 src_ip;            /* Source IP Address */
///     ip_v6 dst_ip;            /* Destination IP Address */
///     unsigned int src_port;   /* TCP/UDP source port number or equivalent */
///     unsigned int dst_port;   /* TCP/UDP destination port number or equivalent */
///     unsigned int tcp_flags;  /* TCP flags */
///     unsigned int priority;   /* IP priority */
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
///
/// Layer 2 switching information
///
/// # XDR Definition ([sFlow v5](https://sflow.org/sflow_version_5.txt))
///
/// ```text
/// /* Extended Switch Data */
/// /* opaque = flow_data; enterprise = 0; format = 1001 */
///
/// struct extended_switch {
///     unsigned int src_vlan;     /* The 802.1Q VLAN id of incoming frame,
///                                   0xffffffff if unknown */
///     unsigned int src_priority; /* The 802.1p priority of incoming frame,
///                                   0xffffffff if unknown */
///     unsigned int dst_vlan;     /* The 802.1Q VLAN id of outgoing frame,
///                                   0xffffffff if unknown */
///     unsigned int dst_priority; /* The 802.1p priority of outgoing frame,
///                                   0xffffffff if unknown */
/// }
/// ```
///
/// **ERRATUM:** The specification was updated to clarify that 0xffffffff indicates unknown values.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExtendedSwitch {
    /// Source VLAN ID
    /// **ERRATUM:** 0xffffffff if unknown
    pub src_vlan: u32,

    /// Source priority (802.1p)
    /// **ERRATUM:** 0xffffffff if unknown
    pub src_priority: u32,

    /// Destination VLAN ID
    /// **ERRATUM:** 0xffffffff if unknown
    pub dst_vlan: u32,

    /// Destination priority (802.1p)
    /// **ERRATUM:** 0xffffffff if unknown
    pub dst_priority: u32,
}

/// Extended Router Data - Format (0,1002)
///
/// Layer 3 routing information
///
/// # XDR Definition ([sFlow v5](https://sflow.org/sflow_version_5.txt))
///
/// ```text
/// /* Extended Router Data */
/// /* opaque = flow_data; enterprise = 0; format = 1002 */
///
/// struct extended_router {
///     next_hop nexthop;          /* IP address of immediate next hop router */
///     unsigned int src_mask_len; /* Source address prefix mask (number of bits) */
///     unsigned int dst_mask_len; /* Destination address prefix mask (number of bits) */
/// }
/// ```
///
/// **ERRATUM:** The specification was clarified to specify "immediate" next hop router.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExtendedRouter {
    /// IP address of immediate next hop router (spec: nexthop)
    /// **ERRATUM:** Clarified as "immediate" next hop router
    pub next_hop: crate::models::core::Address,

    /// Source subnet mask bits
    pub src_mask_len: u32,

    /// Destination subnet mask bits
    pub dst_mask_len: u32,
}

/// AS Path Type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum AsPathType {
    AsSet = 1,
    AsSequence = 2,
}

/// AS Path Segment
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AsPathSegment {
    pub path_type: u32,
    pub path_length: u32,
    pub path: Vec<u32>,
}

/// Extended Gateway Data - Format (0,1003)
///
/// BGP routing information
///
/// # XDR Definition ([sFlow v5](https://sflow.org/sflow_version_5.txt))
///
/// ```text
/// /* Extended Gateway Data */
/// /* opaque = flow_data; enterprise = 0; format = 1003 */
///
/// struct extended_gateway {
///     next_hop nexthop;           /* Address of the border router */
///     unsigned int as;            /* Autonomous system number of router */
///     unsigned int src_as;        /* Autonomous system number of source */
///     unsigned int src_peer_as;   /* Autonomous system number of source peer */
///     as_path_type dst_as_path<>; /* AS path to the destination */
///     unsigned int communities<>; /* Communities associated with this route */
///     unsigned int localpref;     /* LocalPref associated with this route */
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExtendedGateway {
    /// IP address of the border router (spec: nexthop)
    pub next_hop: crate::models::core::Address,

    /// Autonomous system number (spec: as)
    pub as_number: u32,

    /// Source AS
    pub src_as: u32,

    /// Source peer AS
    pub src_peer_as: u32,

    /// Autonomous system path to the destination
    pub dst_as_path: Vec<AsPathSegment>,

    /// Communities associated with this route
    pub communities: Vec<u32>,

    /// Local preference (spec: localpref)
    pub local_pref: u32,
}

/// Extended User Data - Format (0,1004)
///
/// Application-level user information
///
/// # XDR Definition ([sFlow v5](https://sflow.org/sflow_version_5.txt))
///
/// ```text
/// /* Extended User Data */
/// /* opaque = flow_data; enterprise = 0; format = 1004 */
///
/// struct extended_user {
///     charset src_charset;   /* Character set for src_user */
///     opaque src_user<>;     /* User ID associated with packet source */
///     charset dst_charset;   /* Character set for dst_user */
///     opaque dst_user<>;     /* User ID associated with packet destination */
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum UrlDirection {
    Source = 1,
    Destination = 2,
}

/// Extended URL Data - Format (0,1005)
///
/// HTTP request information
///
/// # XDR Definition ([sFlow v5](https://sflow.org/sflow_version_5.txt))
///
/// ```text
/// /* Extended URL Data */
/// /* opaque = flow_data; enterprise = 0; format = 1005 */
///
/// struct extended_url {
///     url_direction direction; /* Direction of connection */
///     string url<>;            /* The HTTP request-line (see RFC 2616) */
///     string host<>;           /* The host field from the HTTP header */
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExtendedUrl {
    /// Direction (source or destination)
    pub direction: u32,

    /// URL string (HTTP request-line)
    pub url: String,

    /// Host header from HTTP request
    pub host: String,
}

/// Extended MPLS Data - Format (0,1006)
///
/// MPLS label stack information
///
/// # XDR Definition ([sFlow v5](https://sflow.org/sflow_version_5.txt))
///
/// ```text
/// /* Extended MPLS Data */
/// /* opaque = flow_data; enterprise = 0; format = 1006 */
///
/// struct extended_mpls {
///     next_hop nexthop;     /* Address of the next hop */
///     label_stack in_stack; /* Label stack of received packet */
///     label_stack out_stack;/* Label stack for transmitted packet */
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExtendedMpls {
    /// Next hop address (spec: nexthop)
    pub next_hop: crate::models::core::Address,

    /// Input label stack
    pub in_stack: Vec<u32>,

    /// Output label stack
    pub out_stack: Vec<u32>,
}

/// Extended NAT Data - Format (0,1007)
///
/// Network Address Translation information
///
/// # XDR Definition ([sFlow v5](https://sflow.org/sflow_version_5.txt))
///
/// ```text
/// /* Extended NAT Data */
/// /* opaque = flow_data; enterprise = 0; format = 1007 */
///
/// struct extended_nat {
///     address src_address; /* Source address */
///     address dst_address; /* Destination address */
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExtendedNat {
    /// Source address type
    pub src_address: crate::models::core::Address,

    /// Destination address type
    pub dst_address: crate::models::core::Address,
}

/// Extended NAT Port Data - Format (0,1020)
///
/// Layer 4 port translation information for NAT
///
/// # XDR Definition ([sFlow Port NAT](https://sflow.org/sflow_pnat.txt))
///
/// ```text
/// /* Extended NAT L4 Port Data
///    Packet header reports ports as seen at the sFlowDataSource.
///    The extended_nat_port structure reports on translated source and/or
///    destination layer 4 (TCP/UDP) ports for this packet. If port was not
///    translated it should be equal to that reported for the header. */
/// /* opaque = flow_data; enterprise = 0; format = 1020 */
///
/// struct extended_nat_port {
///      unsigned int src_port;            /* Source port */
///      unsigned int dst_port;            /* Destination port */
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExtendedNatPort {
    /// Translated source port
    pub src_port: u32,

    /// Translated destination port
    pub dst_port: u32,
}

/// Extended MPLS Tunnel - Format (0,1008)
///
/// MPLS tunnel information
///
/// # XDR Definition ([sFlow v5](https://sflow.org/sflow_version_5.txt))
///
/// ```text
/// /* Extended MPLS Tunnel */
/// /* opaque = flow_data; enterprise = 0; format = 1008 */
///
/// struct extended_mpls_tunnel {
///     string tunnel_lsp_name<>; /* Tunnel name */
///     unsigned int tunnel_id;   /* Tunnel ID */
///     unsigned int tunnel_cos;  /* Tunnel COS value */
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExtendedMplsTunnel {
    /// Tunnel LSP name
    pub tunnel_lsp_name: String,

    /// Tunnel ID
    pub tunnel_id: u32,

    /// Tunnel COS value
    pub tunnel_cos: u32,
}

/// Extended MPLS VC - Format (0,1009)
///
/// MPLS Virtual Circuit information
///
/// # XDR Definition ([sFlow v5](https://sflow.org/sflow_version_5.txt))
///
/// ```text
/// /* Extended MPLS VC */
/// /* opaque = flow_data; enterprise = 0; format = 1009 */
///
/// struct extended_mpls_vc {
///     string vc_instance_name<>; /* VC instance name */
///     unsigned int vll_vc_id;    /* VLL/VC instance ID */
///     unsigned int vc_label_cos; /* VC Label COS value */
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
///
/// MPLS Forwarding Equivalence Class information
///
/// # XDR Definition ([sFlow v5](https://sflow.org/sflow_version_5.txt))
///
/// ```text
/// /* Extended MPLS FEC */
/// /* opaque = flow_data; enterprise = 0; format = 1010 */
///
/// struct extended_mpls_FTN {
///     string mplsFTNDescr<>;  /* FEC description */
///     unsigned int mplsFTNMask; /* FEC mask */
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExtendedMplsFec {
    /// FEC address prefix
    pub fec_addr_prefix: crate::models::core::Address,

    /// FEC prefix length
    pub fec_prefix_len: u32,
}

/// Extended MPLS LVP FEC - Format (0,1011)
///
/// MPLS LDP FEC information
///
/// # XDR Definition ([sFlow v5](https://sflow.org/sflow_version_5.txt))
///
/// ```text
/// /* Extended MPLS LVP FEC */
/// /* opaque = flow_data; enterprise = 0; format = 1011 */
///
/// struct extended_mpls_LDP_FEC {
///     unsigned int mplsFecAddrPrefixLength; /* FEC address prefix length */
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExtendedMplsLvpFec {
    /// FEC address prefix length
    pub mpls_fec_addr_prefix_length: u32,
}

/// Extended VLAN Tunnel - Format (0,1012)
///
/// VLAN tunnel information for nested VLAN tags
///
/// # XDR Definition ([sFlow v5](https://sflow.org/sflow_version_5.txt))
///
/// ```text
/// /* Extended VLAN tunnel information */
/// /* opaque = flow_data; enterprise = 0; format = 1012 */
///
/// struct extended_vlantunnel {
///     unsigned int stack<>; /* List of stripped 802.1Q TPID/TCI layers */
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExtendedVlanTunnel {
    /// List of stripped 802.1Q TPID/TCI layers
    pub stack: Vec<u32>,
}

/// Extended 802.11 Payload - Format (0,1013)
///
/// Unencrypted 802.11 payload data
///
/// # XDR Definition ([sFlow 802.11](https://sflow.org/sflow_80211.txt))
///
/// ```text
/// /* Extended 80211 Payload */
/// /* opaque = flow_data; enterprise = 0; format = 1013 */
///
/// struct extended_80211_payload {
///     cipher_suite ciphersuite; /* encryption scheme used for this packet */
///     opaque data<>;            /* unencrypted bytes from the payload */
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Extended80211Payload {
    /// Cipher suite (OUI + Suite Type) (spec: ciphersuite)
    pub cipher_suite: u32,

    /// Unencrypted payload data
    pub data: Vec<u8>,
}

/// Extended 802.11 RX - Format (0,1014)
///
/// 802.11 receive information
///
/// # XDR Definition ([sFlow 802.11](https://sflow.org/sflow_80211.txt))
///
/// ```text
/// /* Extended 802.11 RX */
/// /* opaque = flow_data; enterprise = 0; format = 1014 */
///
/// struct extended_80211_rx {
///     string ssid<32>;           /* SSID string */
///     mac bssid;                 /* BSSID */
///     ieee80211_version version; /* version */
///     unsigned int channel;      /* channel number */
///     unsigned hyper speed;      /* speed */
///     unsigned int rsni;         /* received signal to noise ratio */
///     unsigned int rcpi;         /* received channel power */
///     duration_us packet_duration; /* time packet occupied RF medium */
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Extended80211Rx {
    /// SSID string (max 32 bytes)
    pub ssid: String,

    /// BSSID (MAC address)
    pub bssid: crate::models::MacAddress,

    /// IEEE 802.11 version (a=1, b=2, g=3, n=4)
    pub version: u32,

    /// Channel number
    pub channel: u32,

    /// Speed in bits per second
    pub speed: u64,

    /// Received signal to noise ratio (RSNI)
    pub rsni: u32,

    /// Received channel power indicator (RCPI)
    pub rcpi: u32,

    /// Packet duration in microseconds
    pub packet_duration: u32,
}

/// Extended 802.11 TX - Format (0,1015)
///
/// 802.11 transmit information
///
/// # XDR Definition ([sFlow 802.11](https://sflow.org/sflow_80211.txt))
///
/// ```text
/// /* Extended 802.11 TX */
/// /* opaque = flow_data; enterprise = 0; format = 1015 */
///
/// struct extended_80211_tx {
///     string ssid<32>;             /* SSID string */
///     mac bssid;                   /* BSSID */
///     ieee80211_version version;   /* version */
///     unsigned int transmissions;  /* number of transmissions */
///     duration_us packet_duration; /* time packet occupied RF medium */
///     duration_us retrans_duration;/* time failed attempts occupied RF */
///     unsigned int channel;        /* channel number */
///     unsigned hyper speed;        /* speed */
///     unsigned int power;          /* transmit power in mW */
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Extended80211Tx {
    /// SSID string (max 32 bytes)
    pub ssid: String,

    /// BSSID (MAC address)
    pub bssid: crate::models::MacAddress,

    /// IEEE 802.11 version (a=1, b=2, g=3, n=4)
    pub version: u32,

    /// Number of transmissions (0=unknown, 1=success on first attempt, n>1 = n-1 retransmissions)
    pub transmissions: u32,

    /// Packet duration in microseconds (successful transmission)
    pub packet_duration: u32,

    /// Retransmission duration in microseconds (failed attempts)
    pub retrans_duration: u32,

    /// Channel number
    pub channel: u32,

    /// Speed in bits per second
    pub speed: u64,

    /// Transmit power in milliwatts
    pub power: u32,
}

/// PDU (Protocol Data Unit) in 802.11 aggregation
///
/// # XDR Definition ([sFlow 802.11](https://sflow.org/sflow_80211.txt))
///
/// ```text
/// struct pdu {
///     flow_record flow_records<>;
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Pdu {
    /// Flow records for this PDU
    pub flow_records: Vec<crate::models::FlowRecord>,
}

/// Extended 802.11 Aggregation - Format (0,1016)
///
/// 802.11 frame aggregation information
///
/// # XDR Definition ([sFlow 802.11](https://sflow.org/sflow_80211.txt))
///
/// ```text
/// /* Extended 802.11 Aggregation Data */
/// /* opaque = flow_data; enterprise = 0; format = 1016 */
///
/// struct extended_80211_aggregation {
///     pdu pdus<>; /* Array of PDUs in the aggregation */
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Extended80211Aggregation {
    /// Array of PDUs in the aggregation
    pub pdus: Vec<Pdu>,
}

/// Extended OpenFlow v1 - Format (0,1017) - **DEPRECATED**
///
/// OpenFlow 1.0 forwarding information
///
/// **Note:** This format was defined in an early draft of the sFlow OpenFlow specification
/// but was deprecated and removed from the final specification. It is included here for
/// backward compatibility with legacy implementations.
///
/// # XDR Definition ([sFlow OpenFlow Draft](https://sflow.org/draft-sflow-openflow.txt))
///
/// ```text
/// /* Extended OpenFlow 1.0 Data */
/// /* opaque = flow_data; enterprise = 0; format = 1017 */
///
/// struct extended_openflow_v1 {
///     unsigned hyper flow_cookie;  /* Flow cookie set by controller */
///     wildcards flow_match;        /* Bit array of wildcarded fields */
///     actions flow_actions;        /* Bit array of actions applied */
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExtendedOpenFlowV1 {
    /// Flow cookie set by the OpenFlow controller
    pub flow_cookie: u64,

    /// Bit array describing the fields in the packet header that are used to form the flow key
    /// See OpenFlow 1.0 ofp_match for the definition of wildcards
    pub flow_match: u32,

    /// Bit array describing fields that may have been altered by the flow action
    /// The ofp_action_type enum is used to determine the bit positions
    pub flow_actions: u32,
}

/// Extended L2 Tunnel Egress - Format (0,1021)
///
/// Layer 2 tunnel egress information - reports outer Ethernet headers
/// that will be added on egress when encapsulating packets
///
/// # XDR Definition ([sFlow Tunnels](https://sflow.org/sflow_tunnels.txt))
///
/// ```text
/// /* opaque = flow_data; enterprise = 0; format = 1021 */
/// struct extended_L2_tunnel_egress {
///     sampled_ethernet header;
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExtendedL2TunnelEgress {
    /// Outer Ethernet header that will be added on egress
    pub header: SampledEthernet,
}

/// Extended L2 Tunnel Ingress - Format (0,1022)
///
/// Layer 2 tunnel ingress information - reports outer Ethernet headers
/// that were present on ingress and removed during decapsulation
///
/// # XDR Definition ([sFlow Tunnels](https://sflow.org/sflow_tunnels.txt))
///
/// ```text
/// /* opaque = flow_data; enterprise = 0; format = 1022 */
/// struct extended_L2_tunnel_ingress {
///     sampled_ethernet header;
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExtendedL2TunnelIngress {
    /// Outer Ethernet header that was present on ingress
    pub header: SampledEthernet,
}

/// Extended IPv4 Tunnel Egress - Format (0,1023)
///
/// IPv4 tunnel egress information - reports outer IPv4 headers
/// that will be added on egress when encapsulating packets
///
/// # XDR Definition ([sFlow Tunnels](https://sflow.org/sflow_tunnels.txt))
///
/// ```text
/// /* opaque = flow_data; enterprise = 0; format = 1023 */
/// struct extended_ipv4_tunnel_egress {
///     sampled_ipv4 header;
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExtendedIpv4TunnelEgress {
    /// Outer IPv4 header that will be added on egress
    pub header: SampledIpv4,
}

/// Extended IPv4 Tunnel Ingress - Format (0,1024)
///
/// IPv4 tunnel ingress information - reports outer IPv4 headers
/// that were present on ingress and removed during decapsulation
///
/// # XDR Definition ([sFlow Tunnels](https://sflow.org/sflow_tunnels.txt))
///
/// ```text
/// /* opaque = flow_data; enterprise = 0; format = 1024 */
/// struct extended_ipv4_tunnel_ingress {
///     sampled_ipv4 header;
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExtendedIpv4TunnelIngress {
    /// Outer IPv4 header that was present on ingress
    pub header: SampledIpv4,
}

/// Extended IPv6 Tunnel Egress - Format (0,1025)
///
/// IPv6 tunnel egress information - reports outer IPv6 headers
/// that will be added on egress when encapsulating packets
///
/// # XDR Definition ([sFlow Tunnels](https://sflow.org/sflow_tunnels.txt))
///
/// ```text
/// /* opaque = flow_data; enterprise = 0; format = 1025 */
/// struct extended_ipv6_tunnel_egress {
///     sampled_ipv6 header;
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExtendedIpv6TunnelEgress {
    /// Outer IPv6 header that will be added on egress
    pub header: SampledIpv6,
}

/// Extended IPv6 Tunnel Ingress - Format (0,1026)
///
/// IPv6 tunnel ingress information - reports outer IPv6 headers
/// that were present on ingress and removed during decapsulation
///
/// # XDR Definition ([sFlow Tunnels](https://sflow.org/sflow_tunnels.txt))
///
/// ```text
/// /* opaque = flow_data; enterprise = 0; format = 1026 */
/// struct extended_ipv6_tunnel_ingress {
///     sampled_ipv6 header;
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExtendedIpv6TunnelIngress {
    /// Outer IPv6 header that was present on ingress
    pub header: SampledIpv6,
}

/// Extended Decapsulate Egress - Format (0,1027)
///
/// Indicates the end of a tunnel and points to the start of the inner header
/// Used when a packet is sampled before decapsulation on ingress
///
/// # XDR Definition ([sFlow Tunnels](https://sflow.org/sflow_tunnels.txt))
///
/// ```text
/// /* opaque = flow_data; enterprise = 0; format = 1027 */
/// struct extended_decapsulate_egress {
///     unsigned int inner_header_offset;
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExtendedDecapsulateEgress {
    /// Offset in bytes to the inner header within the sampled packet header
    pub inner_header_offset: u32,
}

/// Extended Decapsulate Ingress - Format (0,1028)
///
/// Indicates the start of a tunnel
/// Used when a packet is sampled after encapsulation on egress
///
/// # XDR Definition ([sFlow Tunnels](https://sflow.org/sflow_tunnels.txt))
///
/// ```text
/// /* opaque = flow_data; enterprise = 0; format = 1028 */
/// struct extended_decapsulate_ingress {
///     unsigned int inner_header_offset;
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExtendedDecapsulateIngress {
    /// Offset in bytes to the inner header within the sampled packet header
    pub inner_header_offset: u32,
}

/// Extended VNI Egress - Format (0,1029)
///
/// Virtual Network Identifier for egress traffic
/// The VNI may be explicitly included in the tunneling protocol or implicit
///
/// # XDR Definition ([sFlow Tunnels](https://sflow.org/sflow_tunnels.txt))
///
/// ```text
/// /* opaque_flow_data; enterprise = 0; format = 1029 */
/// struct extended_vni_egress {
///     unsigned int vni;
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExtendedVniEgress {
    /// Virtual Network Identifier
    pub vni: u32,
}

/// Extended VNI Ingress - Format (0,1030)
///
/// Virtual Network Identifier for ingress traffic
/// The VNI may be explicitly included in the tunneling protocol or implicit
/// in the encapsulation (e.g., VXLAN uses UDP port 4789).
///
/// # XDR Definition ([sFlow Tunnel](https://sflow.org/sflow_tunnels.txt))
///
/// ```text
/// /* VNI ingress */
/// /* opaque = flow_data; enterprise = 0; format = 1030 */
///
/// struct extended_vni_ingress {
///     unsigned int vni;  /* VNI associated with ingress packet */
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExtendedVniIngress {
    /// Virtual Network Identifier
    pub vni: u32,
}

/// Drop reason codes for discarded packets
///
/// # XDR Definition ([sFlow Drops](https://sflow.org/sflow_drops.txt))
///
/// ```text
/// /* The drop_reason enumeration may be expanded over time.
///    sFlow collectors must be prepared to receive discard_packet
///    structures with unrecognized drop_reason values.
///
///    This document expands on the discard reason codes 0-262 defined
///    in the sFlow Version 5 [1] interface typedef and this expanded list
///    should be regarded as an expansion of the reason codes in the
///    interface typdef and are valid anywhere the typedef is referenced.
///
///    Codes 263-288 are defined in Devlink Trap [2]. Drop reason / group
///    names from the Devlink Trap document are preserved where they define
///    new reason codes, or referenced as comments where they map to existing
///    codes.
///
///    Codes 289-303 are reasons that have yet to be upstreamed to Devlink Trap,
///    but the intent is that they will eventually be upstreamed and documented as
///    part of the Linux API [2], and so they have been reserved.
///
///    The authoritative list of drop reasons will be maintained
///    at sflow.org */
///
/// enum drop_reason {
///    net_unreachable      = 0,
///    host_unreachable     = 1,
///    protocol_unreachable = 2,
///    port_unreachable     = 3,
///    frag_needed          = 4,
///    src_route_failed     = 5,
///    dst_net_unknown      = 6, /* ipv4_lpm_miss, ipv6_lpm_miss */
///    dst_host_unknown     = 7,
///    src_host_isolated    = 8,
///    dst_net_prohibited   = 9, /* reject_route */
///    dst_host_prohibited  = 10,
///    dst_net_tos_unreachable  = 11,
///    dst_host_tos_unreacheable = 12,
///    comm_admin_prohibited = 13,
///    host_precedence_violation = 14,
///    precedence_cutoff    = 15,
///    unknown              = 256,
///    ttl_exceeded         = 257, /* ttl_value_is_too_small */
///    acl                  = 258, /* ingress_flow_action_drop,
///                                   egress_flow_action_drop
///                                   group acl_drops */
///    no_buffer_space      = 259, /* tail_drop */
///    red                  = 260, /* early_drop */
///    traffic_shaping      = 261,
///    pkt_too_big          = 262, /* mtu_value_is_too_small */
///    src_mac_is_multicast = 263,
///    vlan_tag_mismatch    = 264,
///    ingress_vlan_filter  = 265,
///    ingress_spanning_tree_filter = 266,
///    port_list_is_empty   = 267,
///    port_loopback_filter = 268,
///    blackhole_route      = 269,
///    non_ip               = 270,
///    uc_dip_over_mc_dmac  = 271,
///    dip_is_loopback_address = 272,
///    sip_is_mc            = 273,
///    sip_is_loopback_address = 274,
///    ip_header_corrupted  = 275,
///    ipv4_sip_is_limited_bc = 276,
///    ipv6_mc_dip_reserved_scope = 277,
///    ipv6_mc_dip_interface_local_scope = 278,
///    unresolved_neigh     = 279,
///    mc_reverse_path_forwarding = 280,
///    non_routable_packet  = 281,
///    decap_error          = 282,
///    overlay_smac_is_mc   = 283,
///    unknown_l2           = 284, /* group l2_drops */
///    unknown_l3           = 285, /* group l3_drops */
///    unknown_l3_exception = 286, /* group l3_exceptions */
///    unknown_buffer       = 287, /* group buffer_drops */
///    unknown_tunnel       = 288, /* group tunnel_drops */
///    unknown_l4           = 289,
///    sip_is_unspecified   = 290,
///    mlag_port_isolation  = 291,
///    blackhole_arp_neigh  = 292,
///    src_mac_is_dmac      = 293,
///    dmac_is_reserved     = 294,
///    sip_is_class_e       = 295,
///    mc_dmac_mismatch     = 296,
///    sip_is_dip           = 297,
///    dip_is_local_network = 298,
///    dip_is_link_local    = 299,
///    overlay_smac_is_dmac = 300,
///    egress_vlan_filter   = 301,
///    uc_reverse_path_forwarding = 302,
///    split_horizon        = 303
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u32)]
pub enum DropReason {
    NetUnreachable = 0,
    HostUnreachable = 1,
    ProtocolUnreachable = 2,
    PortUnreachable = 3,
    FragNeeded = 4,
    SrcRouteFailed = 5,
    DstNetUnknown = 6,
    DstHostUnknown = 7,
    SrcHostIsolated = 8,
    DstNetProhibited = 9,
    DstHostProhibited = 10,
    DstNetTosUnreachable = 11,
    DstHostTosUnreachable = 12,
    CommAdminProhibited = 13,
    HostPrecedenceViolation = 14,
    PrecedenceCutoff = 15,
    Unknown = 256,
    TtlExceeded = 257,
    Acl = 258,
    NoBufferSpace = 259,
    Red = 260,
    TrafficShaping = 261,
    PktTooBig = 262,
    SrcMacIsMulticast = 263,
    VlanTagMismatch = 264,
    IngressVlanFilter = 265,
    IngressSpanningTreeFilter = 266,
    PortListIsEmpty = 267,
    PortLoopbackFilter = 268,
    BlackholeRoute = 269,
    NonIp = 270,
    UcDipOverMcDmac = 271,
    DipIsLoopbackAddress = 272,
    SipIsMc = 273,
    SipIsLoopbackAddress = 274,
    IpHeaderCorrupted = 275,
    Ipv4SipIsLimitedBc = 276,
    Ipv6McDipReservedScope = 277,
    Ipv6McDipInterfaceLocalScope = 278,
    UnresolvedNeigh = 279,
    McReversePathForwarding = 280,
    NonRoutablePacket = 281,
    DecapError = 282,
    OverlaySmacIsMc = 283,
    UnknownL2 = 284,
    UnknownL3 = 285,
    UnknownL3Exception = 286,
    UnknownBuffer = 287,
    UnknownTunnel = 288,
    UnknownL4 = 289,
    SipIsUnspecified = 290,
    MlagPortIsolation = 291,
    BlackholeArpNeigh = 292,
    SrcMacIsDmac = 293,
    DmacIsReserved = 294,
    SipIsClassE = 295,
    McDmacMismatch = 296,
    SipIsDip = 297,
    DipIsLocalNetwork = 298,
    DipIsLinkLocal = 299,
    OverlaySmacIsDmac = 300,
    EgressVlanFilter = 301,
    UcReversePathForwarding = 302,
    SplitHorizon = 303,
}

impl DropReason {
    /// Convert from u32 value to DropReason enum
    ///
    /// This is a mechanical mapping of u32 values to enum variants
    /// defined in the sFlow specification. The function is tested
    /// with representative samples rather than exhaustively.
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            0 => Some(DropReason::NetUnreachable),
            1 => Some(DropReason::HostUnreachable),
            2 => Some(DropReason::ProtocolUnreachable),
            3 => Some(DropReason::PortUnreachable),
            4 => Some(DropReason::FragNeeded),
            5 => Some(DropReason::SrcRouteFailed),
            6 => Some(DropReason::DstNetUnknown),
            7 => Some(DropReason::DstHostUnknown),
            8 => Some(DropReason::SrcHostIsolated),
            9 => Some(DropReason::DstNetProhibited),
            10 => Some(DropReason::DstHostProhibited),
            11 => Some(DropReason::DstNetTosUnreachable),
            12 => Some(DropReason::DstHostTosUnreachable),
            13 => Some(DropReason::CommAdminProhibited),
            14 => Some(DropReason::HostPrecedenceViolation),
            15 => Some(DropReason::PrecedenceCutoff),
            256 => Some(DropReason::Unknown),
            257 => Some(DropReason::TtlExceeded),
            258 => Some(DropReason::Acl),
            259 => Some(DropReason::NoBufferSpace),
            260 => Some(DropReason::Red),
            261 => Some(DropReason::TrafficShaping),
            262 => Some(DropReason::PktTooBig),
            263 => Some(DropReason::SrcMacIsMulticast),
            264 => Some(DropReason::VlanTagMismatch),
            265 => Some(DropReason::IngressVlanFilter),
            266 => Some(DropReason::IngressSpanningTreeFilter),
            267 => Some(DropReason::PortListIsEmpty),
            268 => Some(DropReason::PortLoopbackFilter),
            269 => Some(DropReason::BlackholeRoute),
            270 => Some(DropReason::NonIp),
            271 => Some(DropReason::UcDipOverMcDmac),
            272 => Some(DropReason::DipIsLoopbackAddress),
            273 => Some(DropReason::SipIsMc),
            274 => Some(DropReason::SipIsLoopbackAddress),
            275 => Some(DropReason::IpHeaderCorrupted),
            276 => Some(DropReason::Ipv4SipIsLimitedBc),
            277 => Some(DropReason::Ipv6McDipReservedScope),
            278 => Some(DropReason::Ipv6McDipInterfaceLocalScope),
            279 => Some(DropReason::UnresolvedNeigh),
            280 => Some(DropReason::McReversePathForwarding),
            281 => Some(DropReason::NonRoutablePacket),
            282 => Some(DropReason::DecapError),
            283 => Some(DropReason::OverlaySmacIsMc),
            284 => Some(DropReason::UnknownL2),
            285 => Some(DropReason::UnknownL3),
            286 => Some(DropReason::UnknownL3Exception),
            287 => Some(DropReason::UnknownBuffer),
            288 => Some(DropReason::UnknownTunnel),
            289 => Some(DropReason::UnknownL4),
            290 => Some(DropReason::SipIsUnspecified),
            291 => Some(DropReason::MlagPortIsolation),
            292 => Some(DropReason::BlackholeArpNeigh),
            293 => Some(DropReason::SrcMacIsDmac),
            294 => Some(DropReason::DmacIsReserved),
            295 => Some(DropReason::SipIsClassE),
            296 => Some(DropReason::McDmacMismatch),
            297 => Some(DropReason::SipIsDip),
            298 => Some(DropReason::DipIsLocalNetwork),
            299 => Some(DropReason::DipIsLinkLocal),
            300 => Some(DropReason::OverlaySmacIsDmac),
            301 => Some(DropReason::EgressVlanFilter),
            302 => Some(DropReason::UcReversePathForwarding),
            303 => Some(DropReason::SplitHorizon),
            _ => None,
        }
    }
}

/// Extended Egress Queue - Format (0,1036)
///
/// Selected egress queue for the sampled packet
///
/// # XDR Definition ([sFlow Drops](https://sflow.org/sflow_drops.txt))
///
/// ```text
/// /* Selected egress queue */
/// /* Output port number must be provided in enclosing structure */
/// /* opaque = flow_data; enterprise = 0; format = 1036 */
/// struct extended_egress_queue {
///   unsigned int queue;  /* eqress queue number selected for sampled packet */
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExtendedEgressQueue {
    /// Egress queue number selected for sampled packet
    pub queue: u32,
}

/// Extended ACL - Format (0,1037)
///
/// ACL information about the rule that matched this packet
///
/// # XDR Definition ([sFlow Drops](https://sflow.org/sflow_drops.txt))
///
/// ```text
/// /* ACL information */
/// /* Information about ACL rule that matched this packet
/// /* opaque = flow_data; enterprise = 0; format = 1037 */
/// struct extended_acl {
///   unsigned int number; /* access list number */
///   string name<>; /* access list name */
///   unsigned int direction; /* unknown = 0, ingress = 1, egress = 2 */
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExtendedAcl {
    /// Access list number
    pub number: u32,

    /// Access list name
    pub name: String,

    /// Direction: unknown = 0, ingress = 1, egress = 2
    pub direction: u32,
}

/// Extended Function - Format (0,1038)
///
/// Name of the function in software network stack that discarded the packet
///
/// # XDR Definition ([sFlow Drops](https://sflow.org/sflow_drops.txt))
///
/// ```text
/// /* Software function */
/// /* Name of the function in software network stack that discarded the packet */
/// /* opaque = flow_data; enterprise = 0; format = 1038 */
/// struct extended_function {
///   string symbol<>;
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExtendedFunction {
    /// Function symbol name
    pub symbol: String,
}

/// Extended Transit - Format (0,1039)
///
/// Delay for sampled packet traversing switch
///
/// # XDR Definition ([sFlow Transit](https://sflow.org/sflow_transit.txt))
///
/// ```text
/// /* Delay for sampled packet traversing switch */
/// /* opaque = flow_data; enterprise = 0; format = 1039 */
/// struct extended_transit {
///   unsigned int delay; /* transit delay in nanoseconds
///                          0xffffffff indicates value >= 0xffffffff */
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExtendedTransit {
    /// Transit delay in nanoseconds (0xffffffff indicates value >= 0xffffffff)
    pub delay: u32,
}

/// Extended Queue - Format (0,1040)
///
/// Queue depth for sampled packet traversing switch
///
/// # XDR Definition ([sFlow Transit](https://sflow.org/sflow_transit.txt))
///
/// ```text
/// /* Queue depth for sampled packet traversing switch */
/// /* extended_egress_queue structure must be included */
/// /* opaque = flow_data; enterprise = 0; format = 1040 */
/// struct extended_queue {
///   unsigned int depth;   /* queue depth in bytes */
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExtendedQueue {
    /// Queue depth in bytes
    pub depth: u32,
}

/// Extended Socket IPv4 - Format (0,2100)
///
/// IPv4 socket information for application transactions
///
/// # XDR Definition ([sFlow Host](https://sflow.org/sflow_host.txt))
///
/// ```text
/// /* IPv4 Socket */
/// /* opaque = flow_data; enterprise = 0; format = 2100 */
///
/// struct extended_socket_ipv4 {
///     unsigned int protocol;     /* IP Protocol type (e.g., TCP = 6, UDP = 17) */
///     ip_v4 local_ip;            /* local IP address */
///     ip_v4 remote_ip;           /* remote IP address */
///     unsigned int local_port;   /* TCP/UDP local port number or equivalent */
///     unsigned int remote_port;  /* TCP/UDP remote port number or equivalent */
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExtendedSocketIpv4 {
    /// IP Protocol type (e.g., TCP = 6, UDP = 17)
    pub protocol: u32,

    /// Local IP address
    pub local_ip: std::net::Ipv4Addr,

    /// Remote IP address
    pub remote_ip: std::net::Ipv4Addr,

    /// TCP/UDP local port number
    pub local_port: u32,

    /// TCP/UDP remote port number
    pub remote_port: u32,
}

/// Extended Socket IPv6 - Format (0,2101)
///
/// IPv6 socket information for application transactions
///
/// # XDR Definition ([sFlow Host](https://sflow.org/sflow_host.txt))
///
/// ```text
/// /* IPv6 Socket */
/// /* opaque = flow_data; enterprise = 0; format = 2101 */
///
/// struct extended_socket_ipv6 {
///     unsigned int protocol;     /* IP Protocol type (e.g., TCP = 6, UDP = 17) */
///     ip_v6 local_ip;            /* local IP address */
///     ip_v6 remote_ip;           /* remote IP address */
///     unsigned int local_port;   /* TCP/UDP local port number or equivalent */
///     unsigned int remote_port;  /* TCP/UDP remote port number or equivalent */
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExtendedSocketIpv6 {
    /// IP Protocol type (e.g., TCP = 6, UDP = 17)
    pub protocol: u32,

    /// Local IP address
    pub local_ip: std::net::Ipv6Addr,

    /// Remote IP address
    pub remote_ip: std::net::Ipv6Addr,

    /// TCP/UDP local port number
    pub local_port: u32,

    /// TCP/UDP remote port number
    pub remote_port: u32,
}

/// HTTP method enumeration
///
/// # XDR Definition ([sFlow HTTP](https://sflow.org/sflow_http.txt))
///
/// ```text
/// /* The http_method enumeration may be expanded over time.
///    Applications receiving sFlow must be prepared to receive
///    http_request structures with unknown http_method values */
///
/// enum http_method {
///   OTHER    = 0;
///   OPTIONS  = 1;
///   GET      = 2;
///   HEAD     = 3;
///   POST     = 4;
///   PUT      = 5;
///   DELETE   = 6;
///   TRACE    = 7;
///   CONNECT  = 8;
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u32)]
pub enum HttpMethod {
    Other = 0,
    Options = 1,
    Get = 2,
    Head = 3,
    Post = 4,
    Put = 5,
    Delete = 6,
    Trace = 7,
    Connect = 8,
}

impl From<u32> for HttpMethod {
    fn from(value: u32) -> Self {
        match value {
            1 => HttpMethod::Options,
            2 => HttpMethod::Get,
            3 => HttpMethod::Head,
            4 => HttpMethod::Post,
            5 => HttpMethod::Put,
            6 => HttpMethod::Delete,
            7 => HttpMethod::Trace,
            8 => HttpMethod::Connect,
            _ => HttpMethod::Other,
        }
    }
}

impl std::fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpMethod::Other => write!(f, "OTHER"),
            HttpMethod::Options => write!(f, "OPTIONS"),
            HttpMethod::Get => write!(f, "GET"),
            HttpMethod::Head => write!(f, "HEAD"),
            HttpMethod::Post => write!(f, "POST"),
            HttpMethod::Put => write!(f, "PUT"),
            HttpMethod::Delete => write!(f, "DELETE"),
            HttpMethod::Trace => write!(f, "TRACE"),
            HttpMethod::Connect => write!(f, "CONNECT"),
        }
    }
}

/// Extended Proxy Socket IPv4 - Format (0,2102)
///
/// IPv4 socket information for proxy connections
///
/// # XDR Definition ([sFlow HTTP](https://sflow.org/sflow_http.txt))
///
/// ```text
/// /* Proxy socket IPv4 */
/// /* opaque = flow_data; enterprise=0; format=2102 */
/// struct extended_proxy_socket_ipv4 {
///   extended_socket_ipv4 socket;
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExtendedProxySocketIpv4 {
    /// Socket information
    pub socket: ExtendedSocketIpv4,
}

/// Extended Proxy Socket IPv6 - Format (0,2103)
///
/// IPv6 socket information for proxy connections
///
/// # XDR Definition ([sFlow HTTP](https://sflow.org/sflow_http.txt))
///
/// ```text
/// /* Proxy socket IPv6 */
/// /* opaque = flow_data; enterprise=0; format=2103 */
/// struct extended_proxy_socket_ipv6 {
///   extended_socket_ipv6 socket;
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExtendedProxySocketIpv6 {
    /// Socket information
    pub socket: ExtendedSocketIpv6,
}

/// Application operation context
///
/// # XDR Definition ([sFlow Application](https://sflow.org/sflow_application.txt))
///
/// ```text
/// struct context {
///     application application;
///     operation operation;
///     attributes attributes;
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AppContext {
    /// Application name (e.g., "payment", "mail.smtp", "db.oracle")
    pub application: String,

    /// Operation name (e.g., "get.customer.name", "upload.photo")
    pub operation: String,

    /// Operation attributes as name=value pairs (e.g., "cc=visa&loc=mobile")
    pub attributes: String,
}

/// Application operation status
///
/// # XDR Definition ([sFlow Application](https://sflow.org/sflow_application.txt))
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u32)]
pub enum AppStatus {
    Success = 0,
    Other = 1,
    Timeout = 2,
    InternalError = 3,
    BadRequest = 4,
    Forbidden = 5,
    TooLarge = 6,
    NotImplemented = 7,
    NotFound = 8,
    Unavailable = 9,
    Unauthorized = 10,
}

impl From<u32> for AppStatus {
    fn from(value: u32) -> Self {
        match value {
            0 => AppStatus::Success,
            1 => AppStatus::Other,
            2 => AppStatus::Timeout,
            3 => AppStatus::InternalError,
            4 => AppStatus::BadRequest,
            5 => AppStatus::Forbidden,
            6 => AppStatus::TooLarge,
            7 => AppStatus::NotImplemented,
            8 => AppStatus::NotFound,
            9 => AppStatus::Unavailable,
            10 => AppStatus::Unauthorized,
            _ => AppStatus::Other,
        }
    }
}

/// Application Operation - Format (0,2202)
///
/// Sampled application operation information
///
/// # XDR Definition ([sFlow Application](https://sflow.org/sflow_application.txt))
///
/// ```text
/// /* Sampled Application Operation */
/// /* opaque = flow_data; enterprise = 0; format = 2202 */
///
/// struct app_operation {
///     context context;             /* attributes describing the operation */
///     utf8string<64> status_descr; /* additional text describing status */
///     unsigned hyper req_bytes;    /* size of request body (exclude headers) */
///     unsigned hyper resp_bytes;   /* size of response body (exclude headers) */
///     unsigned int uS;             /* duration of the operation (microseconds) */
///     status status;               /* status code */
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AppOperation {
    /// Operation context
    pub context: AppContext,

    /// Additional status description
    pub status_descr: String,

    /// Size of request body in bytes (excluding headers)
    pub req_bytes: u64,

    /// Size of response body in bytes (excluding headers)
    pub resp_bytes: u64,

    /// Duration of the operation in microseconds
    pub duration_us: u32,

    /// Operation status code
    pub status: AppStatus,
}

/// Application Parent Context - Format (0,2203)
///
/// Parent context for sampled client operations
///
/// # XDR Definition ([sFlow Application](https://sflow.org/sflow_application.txt))
///
/// ```text
/// /* Optional parent context information for sampled client operation */
/// /* opaque = flow_data; enterprise = 0; format = 2203 */
///
/// struct app_parent_context {
///     context context;
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AppParentContext {
    /// Parent operation context
    pub context: AppContext,
}

/// Application Initiator - Format (0,2204)
///
/// Actor initiating the request (e.g., customer sending a payment)
///
/// # XDR Definition ([sFlow Application](https://sflow.org/sflow_application.txt))
///
/// ```text
/// /* Actor initiating the request */
/// /* e.g. customer sending a payment */
/// /* opaque = flow_data; enterprise = 0; format = 2204 */
///
/// app_initiator {
///    actor actor;
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AppInitiator {
    /// Business level identifier (e.g., customer id, vendor id)
    pub actor: String,
}

/// Application Target - Format (0,2205)
///
/// Actor targeted by the request (e.g., recipient of payment)
///
/// # XDR Definition ([sFlow Application](https://sflow.org/sflow_application.txt))
///
/// ```text
/// /* Actor targetted by the request */
/// /* e.g. recipient of payment */
/// /* opaque = flow_data; enterprise = 0; format = 2205 */
///
/// app_target {
///    actor actor;
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AppTarget {
    /// Business level identifier (e.g., customer id, vendor id)
    pub actor: String,
}

/// HTTP Request - Format (0,2206)
///
/// HTTP request information
///
/// # XDR Definition ([sFlow HTTP](https://sflow.org/sflow_http.txt))
///
/// ```text
/// /* HTTP protocol version number */
/// /* Encoded as major_number * 1000 + minor_number */
/// /* e.g. HTTP1.1 is encoded as 1001 */
/// typedef unsigned int version;
///
/// /* HTTP request */
/// /* opaque = flow_data; enterprise = 0; format = 2206 */
/// struct http_request {
///   http_method method;        /* method */
///   version protocol;          /* HTTP protocol version */
///   string<255> uri;           /* URI exactly as it came from the client */
///   string<64> host;           /* Host value from request header */
///   string<255> referer;       /* Referer value from request header */
///   string<128> useragent;     /* User-Agent value from request header */
///   string<64> xff;            /* X-Forwarded-For value
///                                 from request header */
///   string<32> authuser;       /* RFC 1413 identity of user*/
///   string<64> mime-type;      /* Mime-Type of response */
///   unsigned hyper req_bytes;  /* Content-Length of request */
///   unsigned hyper resp_bytes; /* Content-Length of response */
///   unsigned int uS;           /* duration of the operation
///                                 (in microseconds) */
///   int status;                /* HTTP status code */
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct HttpRequest {
    /// HTTP method
    pub method: HttpMethod,

    /// HTTP protocol version (major * 1000 + minor, e.g., HTTP/1.1 = 1001)
    pub protocol: u32,

    /// URI exactly as it came from the client
    pub uri: String,

    /// Host value from request header
    pub host: String,

    /// Referer value from request header
    pub referer: String,

    /// User-Agent value from request header
    pub useragent: String,

    /// X-Forwarded-For value from request header
    pub xff: String,

    /// RFC 1413 identity of user
    pub authuser: String,

    /// MIME type of response
    pub mime_type: String,

    /// Content-Length of request
    pub req_bytes: u64,

    /// Content-Length of response
    pub resp_bytes: u64,

    /// Duration of the operation in microseconds
    pub duration_us: u32,

    /// HTTP status code
    pub status: i32,
}

/// Extended Proxy Request - Format (0,2207)
///
/// Rewritten URI for proxy requests
///
/// # XDR Definition ([sFlow HTTP](https://sflow.org/sflow_http.txt))
///
/// ```text
/// /* Rewritten URI */
/// /* Only include if host or uri are modified */
/// /* opaque = flow_data; enterprise = 0; format = 2207 */
/// struct extended_proxy_request {
///   string<255> uri;           /* URI in request to downstream server */
///   string<64>  host;          /* Host in request to downstream server */
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExtendedProxyRequest {
    /// URI in request to downstream server
    pub uri: String,

    /// Host in request to downstream server
    pub host: String,
}
