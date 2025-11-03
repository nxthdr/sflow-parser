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
#[repr(u32)]
pub enum AsPathType {
    AsSet = 1,
    AsSequence = 2,
}

impl From<u32> for AsPathType {
    fn from(value: u32) -> Self {
        match value {
            1 => AsPathType::AsSet,
            2 => AsPathType::AsSequence,
            _ => AsPathType::AsSet,
        }
    }
}

/// AS Path Segment
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AsPathSegment {
    pub path_type: AsPathType,
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
#[repr(u32)]
pub enum UrlDirection {
    Source = 1,
    Destination = 2,
}

impl From<u32> for UrlDirection {
    fn from(value: u32) -> Self {
        match value {
            1 => UrlDirection::Source,
            2 => UrlDirection::Destination,
            _ => UrlDirection::Source,
        }
    }
}

/// Extended URL Data - Format (0,1005) - **DEPRECATED**
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
    pub direction: UrlDirection,

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
///     string ssid<32>;             /* SSID string */
///     mac bssid;                   /* BSSID */
///     ieee80211_version version;   /* version */
///     unsigned int channel;        /* channel number */
///     unsigned hyper speed;        /* speed */
///     unsigned int rsni;           /* received signal to noise ratio */
///     unsigned int rcpi;           /* received channel power */
///     duration_us packet_duration; /* time packet occupied RF medium */
/// }
/// ```
///
/// **ERRATUM:** The specification is missing a semicolon after `packet_duration`,
/// violating RFC 4506 XDR syntax requirements. The corrected version is shown above.
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

/// Extended Fiber Channel Routing Entry - Format (0,1018)
///
/// Fiber Channel routing information
///
/// # XDR Definition (RFC 4625)
///
/// ```text
/// /* Extended Fiber Channel Routing Entry */
/// /* opaque = flow_data; enterprise = 0; format = 1018 */
/// /* See RFC 4625 */
/// typedef unsigned int fc_address; /* 24 bit fiber channel address,
///                                     most significant byte = 0 */
/// struct extended_fc {
///  unsigned int src_mask_len; /* Source FC address mask,
///                                 see t11FcRouteSrcMask
///                                (expressed in number of bits) */
///  unsigned int dst_mask_len; /* Destination FC address mask,
///                                 see t11FcRouteDestMask
///                                (expressed in number of bits) */
///   fc_address next_hop; /* Next hop FC switch
///                                 see t11FcRouteDomainId */
///   unsigned int metric; /* most significant byte,
///                                 most significant bit = t11FcRouteType
///                                 least significant 7 bits = t11FcRouteProto,
///                                 least significant 3 bytes = t11FcRouteMetric
///                              */
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExtendedFc {
    /// Source FC address mask (number of bits)
    pub src_mask_len: u32,

    /// Destination FC address mask (number of bits)
    pub dst_mask_len: u32,

    /// Next hop FC switch (24-bit fiber channel address)
    pub next_hop: u32,

    /// Metric containing route type, protocol, and metric value
    /// - Most significant byte, most significant bit: t11FcRouteType
    /// - Most significant byte, least significant 7 bits: t11FcRouteProto
    /// - Least significant 3 bytes: t11FcRouteMetric
    pub metric: u32,
}

/// Extended Queue Length - Format (0,1019)
///
/// Queue length experienced by the sampled packet
///
/// # XDR Definition ([sFlow Discussion](http://groups.google.com/group/sflow/browse_thread/thread/773d27b17a81600c))
///
/// ```text
/// /* Extended queue length data
///    Used to indicate the queue length experienced by the sampled packet.
///    If the extended_queue_length record is exported, queue_length counter
///    records must also be exported with the if_counter record.*/
///
/// /* opaque = flow_data; enterprise = 0; format = 1019 */
///
/// struct extended_queue_length
/// {
///     unsigned int queueIndex; /* persistent index within port of queue
///                                 used to enqueue sampled packet.
///                                 The ifIndex of the port can be inferred
///                                 from the data source. */
///     unsigned int queueLength; /* length of queue, in segments,
///                                  experienced by the packet (ie queue length
///                                  immediately before the sampled packet is
///                                  enqueued). */
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExtendedQueueLength {
    /// Persistent index within port of queue used to enqueue sampled packet
    pub queue_index: u32,

    /// Length of queue, in segments, experienced by the packet
    /// (queue length immediately before the sampled packet is enqueued)
    pub queue_length: u32,
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

/// Extended InfiniBand LRH - Format (0,1031)
///
/// InfiniBand Local Routing Header information
///
/// # XDR Definition ([sFlow InfiniBand](https://sflow.org/draft_sflow_infiniband_2.txt))
///
/// ```text
/// /* Extended IB LRH Data
///    - Local Routing Header definition from InfiniBand Architecture
///      Specification */
///
/// /* opaque = flow_data; enterprise = 0; format = 1031 */
///
/// struct extended_ib_lrh {
///    unsigned int src_vl;       /* source virtual lane               */
///    unsigned int src_sl;       /* source service level              */
///    unsigned int src_dlid;     /* source destination-local-ID       */
///    unsigned int src_slid;     /* source source-local-ID            */
///    unsigned int src_lnh;      /* source link next header           */
///    unsigned int dst_vl;       /* Destination virtual lane          */
///    unsigned int dst_sl;       /* Destination service level         */
///    unsigned int dst_dlid;     /* Destination destination-local-ID  */
///    unsigned int dst_slid;     /* Destination source-local-ID       */
///    unsigned int dst_lnh;      /* Destination link next header      */
/// }
/// ```
///
/// **ERRATUM:** The specification uses non-standard data type `ib_lrh_data` instead of `flow_data`.
/// The corrected version is shown above.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExtendedInfiniBandLrh {
    /// Source virtual lane
    pub src_vl: u32,
    /// Source service level
    pub src_sl: u32,
    /// Source destination-local-ID
    pub src_dlid: u32,
    /// Source source-local-ID
    pub src_slid: u32,
    /// Source link next header
    pub src_lnh: u32,
    /// Destination virtual lane
    pub dst_vl: u32,
    /// Destination service level
    pub dst_sl: u32,
    /// Destination destination-local-ID
    pub dst_dlid: u32,
    /// Destination source-local-ID
    pub dst_slid: u32,
    /// Destination link next header
    pub dst_lnh: u32,
}

/// Extended InfiniBand GRH - Format (0,1032)
///
/// InfiniBand Global Routing Header information
///
/// # XDR Definition ([sFlow InfiniBand](https://sflow.org/draft_sflow_infiniband_2.txt))
///
/// ```text
/// /* GID type  16 bytes long */
/// typedef opaque gid[16];
///
/// /* Extended IB GRH Data
///    - Global Routing Header definition from InfiniBand Architecture
///      Specification */
///
/// /* opaque = flow_data; enterprise = 0; format = 1032 */
///
/// struct extended_ib_grh {
///    unsigned int flow_label; /* flow label          */
///    unsigned int tc;         /* Traffic Class       */
///    gid s_gid;               /* source GID          */
///    gid d_gid;               /* destination GID     */
///    unsigned int next_header; /* next header type    */
///    unsigned int length;      /* payload length      */
/// }
/// ```
///
/// **ERRATUM:** The specification is missing semicolons after `next_header` and `length`,
/// violating RFC 4506 XDR syntax requirements. Additionally, the specification uses
/// non-standard data type `ib_grh_data` instead of `flow_data`. The corrected version is shown above.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExtendedInfiniBandGrh {
    /// Flow label
    pub flow_label: u32,
    /// Traffic class
    pub tc: u32,
    /// Source GID (16 bytes)
    pub s_gid: [u8; 16],
    /// Destination GID (16 bytes)
    pub d_gid: [u8; 16],
    /// Next header type
    pub next_header: u32,
    /// Payload length
    pub length: u32,
}

/// Extended InfiniBand BTH - Format (0,1033)
///
/// InfiniBand Base Transport Header information
///
/// # XDR Definition ([sFlow InfiniBand](https://sflow.org/draft_sflow_infiniband_2.txt))
///
/// ```text
/// /* Extended IB BTH Data
///    - Base Transport Header definition from InfiniBand Architecture
///      Specification */
///
/// /* opaque = flow_data; enterprise = 0; format = 1033 */
///
/// struct extended_ib_bth {
///    unsigned int pkey;   /* Partition key                */
///    unsigned int dst_qp; /* Destination Queue Pair       */
///    unsigned int opcode; /* IBA packet type              */
/// }
/// ```
///
/// **ERRATUM:** The specification uses non-standard data type `ib_bth_data` instead of `flow_data`.
/// The corrected version is shown above.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExtendedInfiniBandBth {
    /// Partition key
    pub pkey: u32,
    /// Destination Queue Pair
    pub dst_qp: u32,
    /// IBA packet type (opcode)
    pub opcode: u32,
}

/// Extended VLAN In - Format (0,1034)
///
/// Ingress 802.1Q VLAN tag information
///
/// # XDR Definition ([sFlow Discussion](https://sflow.org/discussion/sflow-discussion/0199.html))
///
/// ```text
/// /* opaque = flow_data; enterprise = 0; format = 1034 */
/// extended_vlanin {
///   unsigned int stack<>;  /* List of ingress 802.1Q TPID/TCI layers. Each
///                             TPID,TCI pair is represented as a single 32 bit
///                             integer. Layers listed from outermost to
///                             innermost. */
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExtendedVlanIn {
    /// List of ingress 802.1Q TPID/TCI layers
    /// Each TPID,TCI pair is represented as a single 32-bit integer
    /// Layers listed from outermost to innermost
    pub stack: Vec<u32>,
}

/// Extended VLAN Out - Format (0,1035)
///
/// Egress 802.1Q VLAN tag information
///
/// # XDR Definition ([sFlow Discussion](https://sflow.org/discussion/sflow-discussion/0199.html))
///
/// ```text
/// /* opaque = flow_data; enterprise = 0; format = 1035 */
/// extended_vlanout {
///   unsigned int stack<>;  /* List of egress 802.1Q TPID/TCI layers. Each
///                             TPID,TCI pair is represented as a single 32 bit
///                             integer. Layers listed from outermost to
///                             innermost. */
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExtendedVlanOut {
    /// List of egress 802.1Q TPID/TCI layers
    /// Each TPID,TCI pair is represented as a single 32-bit integer
    /// Layers listed from outermost to innermost
    pub stack: Vec<u32>,
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

/// Extended HW Trap - Format (0,1041)
///
/// Devlink Trap Name information from Linux kernel
///
/// # XDR Definition ([host-sflow](https://github.com/sflow/host-sflow/blob/v2.0.50-3/src/sflow/sflow.h))
///
/// ```text
/// /* Devlink Trap Name */
/// /* opaque = flow_data; enterprise = 0; format = 1041 */
/// /* https://www.kernel.org/doc/html/latest/networking/devlink/devlink-trap.html */
/// /* XDR spec: */
/// /*  struct extended_hw_trap { */
/// /*    string group<>; */ /* NET_DM_ATTR_HW_TRAP_GROUP_NAME */
/// /*    string trap<>; */ /* NET_DM_ATTR_HW_TRAP_NAME */
/// /*  } */
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExtendedHwTrap {
    /// Hardware trap group name (NET_DM_ATTR_HW_TRAP_GROUP_NAME)
    pub group: String,

    /// Hardware trap name (NET_DM_ATTR_HW_TRAP_NAME)
    pub trap: String,
}

/// Extended Linux Drop Reason - Format (0,1042)
///
/// Linux drop_monitor reason information
///
/// # XDR Definition ([host-sflow](https://github.com/sflow/host-sflow/blob/v2.0.50-3/src/sflow/sflow.h))
///
/// ```text
/// /* Linux drop_monitor reason */
/// /* opaque = flow_data; enterprise = 0; format = 1042 */
/// /* https://github.com/torvalds/linux/blob/master/include/net/dropreason.h */
/// /* XDR spec: */
/// /*  struct extended_linux_drop_reason { */
/// /*    string reason<>; */ /* NET_DM_ATTR_REASON */
/// /*  } */
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExtendedLinuxDropReason {
    /// Drop reason string (NET_DM_ATTR_REASON)
    pub reason: String,
}

/// Transaction status values
///
/// # XDR Definition ([sFlow Discussion](https://sflow.org/discussion/sflow-discussion/0282.html))
///
/// ```text
/// enum status_value {
///     succeeded = 0,
///     generic_failure = 1,
///     outofmemory = 2,
///     timeout = 3,
///     notpermitted = 4
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u32)]
pub enum TransactionStatus {
    Succeeded = 0,
    GenericFailure = 1,
    OutOfMemory = 2,
    Timeout = 3,
    NotPermitted = 4,
}

impl From<u32> for TransactionStatus {
    fn from(value: u32) -> Self {
        match value {
            0 => TransactionStatus::Succeeded,
            1 => TransactionStatus::GenericFailure,
            2 => TransactionStatus::OutOfMemory,
            3 => TransactionStatus::Timeout,
            4 => TransactionStatus::NotPermitted,
            _ => TransactionStatus::GenericFailure,
        }
    }
}

/// Service direction for transactions
///
/// # XDR Definition ([sFlow Discussion](https://sflow.org/discussion/sflow-discussion/0282.html))
///
/// ```text
/// enum service_direction {
///     client = 1,
///     server = 2
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u32)]
pub enum ServiceDirection {
    Client = 1,
    Server = 2,
}

impl From<u32> for ServiceDirection {
    fn from(value: u32) -> Self {
        match value {
            1 => ServiceDirection::Client,
            2 => ServiceDirection::Server,
            _ => ServiceDirection::Client,
        }
    }
}

/// Transaction - Format (0,2000)
///
/// Generic application transaction record sampled upon completion
///
/// # XDR Definition ([sFlow Discussion](https://sflow.org/discussion/sflow-discussion/0282.html))
///
/// ```text
/// /* Generic Application Transaction record */
/// /* Every Application Transaction sample must start with a generic transaction record */
/// /* opaque = flow_data; enterprise = 0; format = 2000 */
/// struct transaction {
///     service_direction direction; /* was this transaction observed by the server or the client */
///     unsigned int wait;           /* time in microseconds that transaction was queued
///                                     before processing started */
///     unsigned int duration;       /* time in microseconds from start of processing to completion */
///     status_value status;         /* status of transaction */
///     unsigned hyper bytes_received; /* bytes received */
///     unsigned hyper bytes_send;   /* bytes sent */
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Transaction {
    /// Was this transaction observed by the server or the client
    pub direction: ServiceDirection,

    /// Time in microseconds that transaction was queued before processing started
    pub wait: u32,

    /// Time in microseconds from start of processing to completion
    pub duration: u32,

    /// Status of transaction
    pub status: TransactionStatus,

    /// Bytes received
    pub bytes_received: u64,

    /// Bytes sent (spec: bytes_send)
    pub bytes_sent: u64,
}

/// Extended NFS Storage Transaction - Format (0,2001)
///
/// NFS operation transaction details
///
/// # XDR Definition ([sFlow Discussion](https://sflow.org/discussion/sflow-discussion/0282.html))
///
/// ```text
/// /* Extended NFS transaction */
/// /* see RFC 3530 */
/// /* opaque = flow_data; enterprise = 0; format = 2001 */
/// struct extended_nfs_storage_transaction {
///     opaque<> path;        /* canonical path to file or directory
///                              associated with operation file handle
///                              UTF8 encoded string */
///     unsigned int operation; /* NFS operation */
///     unsigned int status;    /* NFS operation status - nfsstat4 */
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExtendedNfsStorageTransaction {
    /// Canonical path to file or directory (UTF8 encoded)
    pub path: Vec<u8>,

    /// NFS operation
    pub operation: u32,

    /// NFS operation status (nfsstat4)
    pub status: u32,
}

/// Extended SCSI Storage Transaction - Format (0,2002)
///
/// SCSI operation transaction details
///
/// # XDR Definition ([sFlow Discussion](https://sflow.org/discussion/sflow-discussion/0282.html))
///
/// ```text
/// /* Extended SCSI transaction */
/// /* opaque = flow_data; enterprise = 0; format = 2002 */
/// struct extended_scsi_storage_transaction {
///     unsigned int lun;       /* LUN */
///     unsigned int operation; /* use maxint to encode unknown operation */
///     unsigned int status;    /* SCSI status code reporting result of operation */
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExtendedScsiStorageTransaction {
    /// Logical Unit Number
    pub lun: u32,

    /// SCSI operation (use maxint to encode unknown operation)
    pub operation: u32,

    /// SCSI status code reporting result of operation
    pub status: u32,
}

/// Extended HTTP Transaction - Format (0,2003)
///
/// HTTP transaction details
///
/// # XDR Definition ([sFlow Discussion](https://sflow.org/discussion/sflow-discussion/0282.html))
///
/// ```text
/// /* Extended Web transaction */
/// /* opaque = flow_data; enterprise = 0; format = 2003 */
/// struct extended_http_transaction {
///     string<> url;       /* The HTTP request-line (see RFC 2616) */
///     string<> host;      /* The host field from the HTTP header */
///     string<> referer;   /* The referer field from the HTTP header */
///     string<> useragent; /* The user agent from the HTTP header */
///     string<> user;      /* The authenticated user */
///     unigned int status; /* Status code returned with response */
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExtendedHttpTransaction {
    /// The HTTP request-line (see RFC 2616)
    pub url: String,

    /// The host field from the HTTP header
    pub host: String,

    /// The referer field from the HTTP header
    pub referer: String,

    /// The user agent from the HTTP header (spec: useragent)
    pub user_agent: String,

    /// The authenticated user
    pub user: String,

    /// Status code returned with response
    pub status: u32,
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

/// Memcache Protocol
///
/// # XDR Definition ([sFlow Memcache](https://sflow.org/sflow_memcache.txt))
///
/// ```text
/// enum memcache_protocol {
///   OTHER  = 0;
///   ASCII  = 1;
///   BINARY = 2;
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u32)]
pub enum MemcacheProtocol {
    Other = 0,
    Ascii = 1,
    Binary = 2,
}

impl MemcacheProtocol {
    /// Convert from u32 value to MemcacheProtocol enum
    pub fn from_u32(value: u32) -> Self {
        match value {
            1 => MemcacheProtocol::Ascii,
            2 => MemcacheProtocol::Binary,
            _ => MemcacheProtocol::Other,
        }
    }
}

/// Memcache Command
///
/// # XDR Definition ([sFlow Memcache](https://sflow.org/sflow_memcache.txt))
///
/// ```text
/// enum memcache_cmd {
///   OTHER    = 0;
///   SET      = 1;
///   ADD      = 2;
///   REPLACE  = 3;
///   APPEND   = 4;
///   PREPEND  = 5;
///   CAS      = 6;
///   GET      = 7;
///   GETS     = 8;
///   INCR     = 9;
///   DECR     = 10;
///   DELETE   = 11;
///   STATS    = 12;
///   FLUSH    = 13;
///   VERSION  = 14;
///   QUIT     = 15;
///   TOUCH    = 16;
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u32)]
pub enum MemcacheCommand {
    Other = 0,
    Set = 1,
    Add = 2,
    Replace = 3,
    Append = 4,
    Prepend = 5,
    Cas = 6,
    Get = 7,
    Gets = 8,
    Incr = 9,
    Decr = 10,
    Delete = 11,
    Stats = 12,
    Flush = 13,
    Version = 14,
    Quit = 15,
    Touch = 16,
}

impl MemcacheCommand {
    /// Convert from u32 value to MemcacheCommand enum
    pub fn from_u32(value: u32) -> Self {
        match value {
            1 => MemcacheCommand::Set,
            2 => MemcacheCommand::Add,
            3 => MemcacheCommand::Replace,
            4 => MemcacheCommand::Append,
            5 => MemcacheCommand::Prepend,
            6 => MemcacheCommand::Cas,
            7 => MemcacheCommand::Get,
            8 => MemcacheCommand::Gets,
            9 => MemcacheCommand::Incr,
            10 => MemcacheCommand::Decr,
            11 => MemcacheCommand::Delete,
            12 => MemcacheCommand::Stats,
            13 => MemcacheCommand::Flush,
            14 => MemcacheCommand::Version,
            15 => MemcacheCommand::Quit,
            16 => MemcacheCommand::Touch,
            _ => MemcacheCommand::Other,
        }
    }
}

/// Memcache Status
///
/// # XDR Definition ([sFlow Memcache](https://sflow.org/sflow_memcache.txt))
///
/// ```text
/// enum memcache_status {
///   UNKNOWN      = 0;
///   OK           = 1;
///   ERROR        = 2;
///   CLIENT_ERROR = 3;
///   SERVER_ERROR = 4;
///   STORED       = 5;
///   NOT_STORED   = 6;
///   EXISTS       = 7;
///   NOT_FOUND    = 8;
///   DELETED      = 9;
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u32)]
pub enum MemcacheStatus {
    Unknown = 0,
    Ok = 1,
    Error = 2,
    ClientError = 3,
    ServerError = 4,
    Stored = 5,
    NotStored = 6,
    Exists = 7,
    NotFound = 8,
    Deleted = 9,
}

impl MemcacheStatus {
    /// Convert from u32 value to MemcacheStatus enum
    pub fn from_u32(value: u32) -> Self {
        match value {
            1 => MemcacheStatus::Ok,
            2 => MemcacheStatus::Error,
            3 => MemcacheStatus::ClientError,
            4 => MemcacheStatus::ServerError,
            5 => MemcacheStatus::Stored,
            6 => MemcacheStatus::NotStored,
            7 => MemcacheStatus::Exists,
            8 => MemcacheStatus::NotFound,
            9 => MemcacheStatus::Deleted,
            _ => MemcacheStatus::Unknown,
        }
    }
}

/// Memcache Operation - Format (0,2200)
///
/// Sampled memcache operation
///
/// # XDR Definition ([sFlow Memcache](https://sflow.org/sflow_memcache.txt))
///
/// ```text
/// /* Memcache operation */
/// /* opaque = flow_data; enterprise = 0; format = 2200 */
///
/// struct memcache_operation {
///   memcache_protocol protocol;  /* protocol */
///   memcache_cmd cmd;            /* command */
///   string<255> key;             /* key used to store/retrieve data */
///   unsigned int nkeys;          /* number of keys
///                                   (including sampled key) */
///   unsigned int value_bytes;    /* size of the value (in bytes) */
///   unsigned int uS;             /* duration of the operation
///                                   (in microseconds) */
///   memcache_status status;      /* status of command */
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MemcacheOperation {
    /// Protocol (ASCII or Binary)
    pub protocol: MemcacheProtocol,

    /// Command type
    pub cmd: MemcacheCommand,

    /// Key used to store/retrieve data
    pub key: String,

    /// Number of keys (including sampled key)
    pub nkeys: u32,

    /// Size of the value in bytes
    pub value_bytes: u32,

    /// Duration of the operation in microseconds
    pub duration_us: u32,

    /// Status of the command
    pub status: MemcacheStatus,
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

/// HTTP Request - Format (0,2201) - **DEPRECATED**
///
/// Legacy HTTP request information
///
/// **Note:** This format was defined in an early sFlow HTTP discussion
/// but was deprecated and replaced by format 2206. It is included here for
/// backward compatibility with legacy implementations.
///
/// # XDR Definition ([sFlow Discussion](https://groups.google.com/g/sflow/c/iKzLK61ZTR0))
///
/// ```text
/// /* HTTP request */
/// /* opaque = flow_data; enterprise = 0; format = 2201 */
/// struct http_request {
///   http_method method;        /* method */
///   string<255> uri;           /* URI exactly as it came from the client */
///   string<32> host;           /* Host value from request header */
///   string<255> referer;       /* Referer value from request header */
///   string<64> useragent;      /* User-Agent value from request header */
///   string<64> xff;            /* X-Forwarded-For value from request header */
///   string<32> authuser;       /* RFC 1413 identity of user*/
///   string<32> mime_type;      /* Mime-Type */
///   unsigned hyper req_bytes;  /* Content-Length of request */
///   unsigned hyper resp_bytes; /* Content-Length of response */
///   unsigned int uS;           /* duration of the operation (microseconds) */
///   int status;                /* HTTP status code */
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct HttpRequestDeprecated {
    /// HTTP method
    pub method: HttpMethod,

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

    /// Mime-Type
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
/// struct app_initiator {
///    actor actor;
/// }
/// ```
///
/// **ERRATUM:** The specification is missing the `struct` keyword before the structure name,
/// which is inconsistent with XDR syntax conventions. The corrected version is shown above.
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
/// struct app_target {
///    actor actor;
/// }
/// ```
///
/// **ERRATUM:** The specification is missing the `struct` keyword before the structure name,
/// which is inconsistent with XDR syntax conventions. The corrected version is shown above.
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

/// Extended Nav Timing - Format (0,2208)
///
/// Navigation timing information from web browsers
///
/// # XDR Definition ([sFlow Discussion](https://groups.google.com/g/sflow/c/FKzkvig32Tk))
///
/// ```text
/// /* Navigation Timing */
/// /* reference http://www.w3.org/TR/navigation-timing/ */
/// /* To allow times to fit into 32 bits, normalize so that smallest time
/// value is 1, times are expressed in milliseconds and 0 is used to indicate
/// that event is not fired, or not complete */
/// /* opaque = flow_data; enterprise = 0; format = 2208 */
///
/// struct extended_nav_timing {
///     unsigned int type; /* PerformanceNavigation */
///     unsigned int redirectCount;
///     unsigned int navigationStart; /* PerformanceTiming */
///     unsigned int unloadEventStart;
///     unsigned int unloadEventEnd;
///     unsigned int redirectStart;
///     unsigned int redirectEnd;
///     unsigned int fetchStart;
///     unsigned int domainLookupStart;
///     unsigned int domainLookupEnd;
///     unsigned int connectStart;
///     unsigned int connectEnd;
///     unsigned int secureConnectionStart;
///     unsigned int requestStart;
///     unsigned int responseStart;
///     unsigned int responseEnd;
///     unsigned int domLoading;
///     unsigned int domInteractive;
///     unsigned int domContentLoadedEventStart;
///     unsigned int domContentLoadedEventEnd;
///     unsigned int domComplete;
///     unsigned int loadEventStart;
///     unsigned int loadEventEnd;
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExtendedNavTiming {
    /// Navigation type (PerformanceNavigation)
    pub nav_type: u32,
    /// Redirect count
    pub redirect_count: u32,
    /// Navigation start time (PerformanceTiming)
    pub navigation_start: u32,
    /// Unload event start time
    pub unload_event_start: u32,
    /// Unload event end time
    pub unload_event_end: u32,
    /// Redirect start time
    pub redirect_start: u32,
    /// Redirect end time
    pub redirect_end: u32,
    /// Fetch start time
    pub fetch_start: u32,
    /// Domain lookup start time
    pub domain_lookup_start: u32,
    /// Domain lookup end time
    pub domain_lookup_end: u32,
    /// Connect start time
    pub connect_start: u32,
    /// Connect end time
    pub connect_end: u32,
    /// Secure connection start time
    pub secure_connection_start: u32,
    /// Request start time
    pub request_start: u32,
    /// Response start time
    pub response_start: u32,
    /// Response end time
    pub response_end: u32,
    /// DOM loading time
    pub dom_loading: u32,
    /// DOM interactive time
    pub dom_interactive: u32,
    /// DOM content loaded event start time
    pub dom_content_loaded_event_start: u32,
    /// DOM content loaded event end time
    pub dom_content_loaded_event_end: u32,
    /// DOM complete time
    pub dom_complete: u32,
    /// Load event start time
    pub load_event_start: u32,
    /// Load event end time
    pub load_event_end: u32,
}

/// Packet direction for TCP info
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum PacketDirection {
    Unknown = 0,
    Received = 1,
    Sent = 2,
}

impl PacketDirection {
    /// Convert from u32 value to PacketDirection enum
    pub fn from_u32(value: u32) -> Self {
        match value {
            1 => PacketDirection::Received,
            2 => PacketDirection::Sent,
            _ => PacketDirection::Unknown,
        }
    }
}

/// Extended TCP Info - Format (0,2209)
///
/// TCP connection state information based on Linux struct tcp_info
///
/// # XDR Definition ([sFlow Discussion](https://groups.google.com/g/sflow/c/JCG9iwacLZA))
///
/// ```text
/// /* TCP connection state */
/// /* Based on Linux struct tcp_info */
/// /* opaque = flow_data; enterprise=0; format=2209 */
/// struct extended_tcp_info {
///   packet_direction dir;     /* Sampled packet direction */
///   unsigned int snd_mss;     /* Cached effective mss, not including SACKS */
///   unsigned int rcv_mss;     /* Max. recv. segment size */
///   unsigned int unacked;     /* Packets which are "in flight" */
///   unsigned int lost;        /* Lost packets */
///   unsigned int retrans;     /* Retransmitted packets */
///   unsigned int pmtu;        /* Last pmtu seen by socket */
///   unsigned int rtt;         /* smoothed RTT (microseconds) */
///   unsigned int rttvar;      /* RTT variance (microseconds) */
///   unsigned int snd_cwnd;    /* Sending congestion window */
///   unsigned int reordering;  /* Reordering */
///   unsigned int min_rtt;     /* Minimum RTT (microseconds) */
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExtendedTcpInfo {
    /// Sampled packet direction
    pub dir: PacketDirection,
    /// Cached effective MSS, not including SACKS
    pub snd_mss: u32,
    /// Maximum receive segment size
    pub rcv_mss: u32,
    /// Packets which are "in flight"
    pub unacked: u32,
    /// Lost packets
    pub lost: u32,
    /// Retransmitted packets
    pub retrans: u32,
    /// Last PMTU seen by socket
    pub pmtu: u32,
    /// Smoothed RTT (microseconds)
    pub rtt: u32,
    /// RTT variance (microseconds)
    pub rttvar: u32,
    /// Sending congestion window
    pub snd_cwnd: u32,
    /// Reordering
    pub reordering: u32,
    /// Minimum RTT (microseconds)
    pub min_rtt: u32,
}

/// Extended Entities - Format (0,2210)
///
/// Traffic source/sink entity reference
///
/// # XDR Definition ([sFlow Discussion](https://blog.sflow.com/2018/10/systemd-traffic-marking.html))
///
/// ```text
/// /* Traffic source/sink entity reference */
/// /* opaque = flow_data; enterprise = 0; format = 2210 */
/// /* Set Data source to all zeroes if unknown */
/// struct extended_entities {
///  sflow_data_source_expanded src_ds;    /* Data Source associated with
///                                           packet source */
///  sflow_data_source_expanded dst_ds;    /* Data Source associated with
///                                           packet destination */
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExtendedEntities {
    /// Data source associated with packet source
    pub src_ds: crate::models::core::DataSourceExpanded,
    /// Data source associated with packet destination
    pub dst_ds: crate::models::core::DataSourceExpanded,
}

/// Extended BST Egress Queue - Format (4413,1)
///
/// Selected egress queue for sampled packet from Broadcom switch ASIC
///
/// # XDR Definition ([sFlow Broadcom Buffers](https://sflow.org/bv-sflow.txt))
///
/// ```text
/// /* Selected egress queue */
/// /* opaque = flow_data; enterprise = 4413; format = 1 */
/// struct extended_bst_egress_queue {
///   unsigned int queue;  /* eqress queue number selected for sampled packet */
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExtendedBstEgressQueue {
    /// Egress queue number selected for sampled packet
    pub queue: u32,
}
