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
pub struct SampledEthernet {
    /// Length of MAC packet in bytes
    pub length: u32,

    /// Source MAC address (6 bytes)
    pub src_mac: [u8; 6], // TODO: use MacAddress

    /// Destination MAC address (6 bytes)
    pub dst_mac: [u8; 6], // TODO: use MacAddress

    /// Ethernet type
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
///     unsigned int src_vlan;     /* The 802.1Q VLAN id of incoming frame */
///     unsigned int src_priority; /* The 802.1p priority of incoming frame */
///     unsigned int dst_vlan;     /* The 802.1Q VLAN id of outgoing frame */
///     unsigned int dst_priority; /* The 802.1p priority of outgoing frame */
/// }
/// ```
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
///     next_hop nexthop;          /* IP address of next hop router */
///     unsigned int src_mask_len; /* Source address prefix mask (number of bits) */
///     unsigned int dst_mask_len; /* Destination address prefix mask (number of bits) */
/// }
/// ```
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
pub struct ExtendedMpls {
    /// Next hop address
    pub next_hop: crate::models::core::Address,

    /// Input label stack
    pub in_label_stack: Vec<u32>,

    /// Output label stack
    pub out_label_stack: Vec<u32>,
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
pub struct ExtendedNat {
    /// Source address type
    pub src_address: crate::models::core::Address,

    /// Destination address type
    pub dst_address: crate::models::core::Address,
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
pub struct ExtendedMplsTunnel {
    /// Tunnel name
    pub tunnel_name: String,

    /// Tunnel ID
    pub tunnel_id: u32,

    /// Tunnel cost
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
pub struct ExtendedMplsLvpFec {
    /// FEC address prefix length
    pub fec_addr_prefix_len: u32,
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
pub struct ExtendedVlanTunnel {
    /// Stack of VLAN tags
    pub vlan_stack: Vec<u32>,
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
pub struct Extended80211Payload {
    /// Cipher suite (OUI + Suite Type)
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
pub struct Extended80211Rx {
    /// SSID string (max 32 bytes)
    pub ssid: String,

    /// BSSID (MAC address)
    pub bssid: [u8; 6],

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
pub struct Extended80211Tx {
    /// SSID string (max 32 bytes)
    pub ssid: String,

    /// BSSID (MAC address)
    pub bssid: [u8; 6],

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
pub struct Extended80211Aggregation {
    /// Array of PDUs in the aggregation (simplified - just count for now)
    pub pdu_count: u32,
}
