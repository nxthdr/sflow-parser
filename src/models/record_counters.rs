//! Counter record data structures
//!
//! These represent interface and system statistics collected periodically.
//! Enterprise = 0 (sFlow.org standard formats)

/// Generic Interface Counters - Format (0,1)
///
/// Standard interface statistics (RFC 2233)
///
/// # XDR Definition ([sFlow v5](https://sflow.org/sflow_version_5.txt))
///
/// ```text
/// /* Generic Interface Counters - see RFC 2233 */
/// /* opaque = counter_data; enterprise = 0; format = 1 */
///
/// struct if_counters {
///     unsigned int ifIndex;
///     unsigned int ifType;
///     unsigned hyper ifSpeed;
///     unsigned int ifDirection;
///     unsigned int ifStatus;
///     unsigned hyper ifInOctets;
///     unsigned int ifInUcastPkts;
///     unsigned int ifInMulticastPkts;
///     unsigned int ifInBroadcastPkts;
///     unsigned int ifInDiscards;
///     unsigned int ifInErrors;
///     unsigned int ifInUnknownProtos;
///     unsigned hyper ifOutOctets;
///     unsigned int ifOutUcastPkts;
///     unsigned int ifOutMulticastPkts;
///     unsigned int ifOutBroadcastPkts;
///     unsigned int ifOutDiscards;
///     unsigned int ifOutErrors;
///     unsigned int ifPromiscuousMode;
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GenericInterfaceCounters {
    /// Interface index
    pub if_index: u32,

    /// Interface type (from IANAifType)
    pub if_type: u32,

    /// Interface speed in bits per second
    pub if_speed: u64,

    /// Interface direction (1=full-duplex, 2=half-duplex, 3=in, 4=out)
    pub if_direction: u32,

    /// Interface status (bit 0=admin, bit 1=oper)
    pub if_status: u32,

    /// Total octets received
    pub if_in_octets: u64,

    /// Total unicast packets received
    pub if_in_ucast_pkts: u32,

    /// Total multicast packets received
    pub if_in_multicast_pkts: u32,

    /// Total broadcast packets received
    pub if_in_broadcast_pkts: u32,

    /// Total discarded inbound packets
    pub if_in_discards: u32,

    /// Total inbound errors
    pub if_in_errors: u32,

    /// Total inbound packets with unknown protocol
    pub if_in_unknown_protos: u32,

    /// Total octets transmitted
    pub if_out_octets: u64,

    /// Total unicast packets transmitted
    pub if_out_ucast_pkts: u32,

    /// Total multicast packets transmitted
    pub if_out_multicast_pkts: u32,

    /// Total broadcast packets transmitted
    pub if_out_broadcast_pkts: u32,

    /// Total discarded outbound packets
    pub if_out_discards: u32,

    /// Total outbound errors
    pub if_out_errors: u32,

    /// Promiscuous mode (1=true, 2=false)
    pub if_promiscuous_mode: u32,
}

/// Ethernet Interface Counters - Format (0,2)
///
/// Ethernet-specific statistics (RFC 2358)
///
/// # XDR Definition ([sFlow v5](https://sflow.org/sflow_version_5.txt))
///
/// ```text
/// /* Ethernet Interface Counters - see RFC 2358 */
/// /* opaque = counter_data; enterprise = 0; format = 2 */
///
/// struct ethernet_counters {
///     unsigned int dot3StatsAlignmentErrors;
///     unsigned int dot3StatsFCSErrors;
///     unsigned int dot3StatsSingleCollisionFrames;
///     unsigned int dot3StatsMultipleCollisionFrames;
///     unsigned int dot3StatsSQETestErrors;
///     unsigned int dot3StatsDeferredTransmissions;
///     unsigned int dot3StatsLateCollisions;
///     unsigned int dot3StatsExcessiveCollisions;
///     unsigned int dot3StatsInternalMacTransmitErrors;
///     unsigned int dot3StatsCarrierSenseErrors;
///     unsigned int dot3StatsFrameTooLongs;
///     unsigned int dot3StatsInternalMacReceiveErrors;
///     unsigned int dot3StatsSymbolErrors;
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EthernetInterfaceCounters {
    /// Alignment errors
    pub dot3_stats_alignment_errors: u32,

    /// FCS errors
    pub dot3_stats_fcs_errors: u32,

    /// Single collision frames
    pub dot3_stats_single_collision_frames: u32,

    /// Multiple collision frames
    pub dot3_stats_multiple_collision_frames: u32,

    /// SQE test errors
    pub dot3_stats_sqe_test_errors: u32,

    /// Deferred transmissions
    pub dot3_stats_deferred_transmissions: u32,

    /// Late collisions
    pub dot3_stats_late_collisions: u32,

    /// Excessive collisions
    pub dot3_stats_excessive_collisions: u32,

    /// Internal MAC transmit errors
    pub dot3_stats_internal_mac_transmit_errors: u32,

    /// Carrier sense errors
    pub dot3_stats_carrier_sense_errors: u32,

    /// Frame too long errors
    pub dot3_stats_frame_too_longs: u32,

    /// Internal MAC receive errors
    pub dot3_stats_internal_mac_receive_errors: u32,

    /// Symbol errors
    pub dot3_stats_symbol_errors: u32,
}

/// Token Ring Counters - Format (0,3)
///
/// Token Ring statistics (RFC 1748)
///
/// # XDR Definition ([sFlow v5](https://sflow.org/sflow_version_5.txt))
///
/// ```text
/// /* Token Ring Counters - see RFC 1748 */
/// /* opaque = counter_data; enterprise = 0; format = 3 */
///
/// struct tokenring_counters {
///     unsigned int dot5StatsLineErrors;
///     unsigned int dot5StatsBurstErrors;
///     unsigned int dot5StatsACErrors;
///     unsigned int dot5StatsAbortTransErrors;
///     unsigned int dot5StatsInternalErrors;
///     unsigned int dot5StatsLostFrameErrors;
///     unsigned int dot5StatsReceiveCongestions;
///     unsigned int dot5StatsFrameCopiedErrors;
///     unsigned int dot5StatsTokenErrors;
///     unsigned int dot5StatsSoftErrors;
///     unsigned int dot5StatsHardErrors;
///     unsigned int dot5StatsSignalLoss;
///     unsigned int dot5StatsTransmitBeacons;
///     unsigned int dot5StatsRecoverys;
///     unsigned int dot5StatsLobeWires;
///     unsigned int dot5StatsRemoves;
///     unsigned int dot5StatsSingles;
///     unsigned int dot5StatsFreqErrors;
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TokenRingCounters {
    pub dot5_stats_line_errors: u32,
    pub dot5_stats_burst_errors: u32,
    pub dot5_stats_ac_errors: u32,
    pub dot5_stats_abort_trans_errors: u32,
    pub dot5_stats_internal_errors: u32,
    pub dot5_stats_lost_frame_errors: u32,
    pub dot5_stats_receive_congestions: u32,
    pub dot5_stats_frame_copied_errors: u32,
    pub dot5_stats_token_errors: u32,
    pub dot5_stats_soft_errors: u32,
    pub dot5_stats_hard_errors: u32,
    pub dot5_stats_signal_loss: u32,
    pub dot5_stats_transmit_beacons: u32,
    pub dot5_stats_recoverys: u32,
    pub dot5_stats_lobe_wires: u32,
    pub dot5_stats_removes: u32,
    pub dot5_stats_singles: u32,
    pub dot5_stats_freq_errors: u32,
}

/// 100BaseVG Interface Counters - Format (0,4)
///
/// 100BaseVG statistics (RFC 2020)
///
/// # XDR Definition ([sFlow v5](https://sflow.org/sflow_version_5.txt))
///
/// ```text
/// /* 100 BaseVG interface counters - see RFC 2020 */
/// /* opaque = counter_data; enterprise = 0; format = 4 */
///
/// struct vg_counters {
///     unsigned int dot12InHighPriorityFrames;
///     unsigned hyper dot12InHighPriorityOctets;
///     unsigned int dot12InNormPriorityFrames;
///     unsigned hyper dot12InNormPriorityOctets;
///     unsigned int dot12InIPMErrors;
///     unsigned int dot12InOversizeFrameErrors;
///     unsigned int dot12InDataErrors;
///     unsigned int dot12InNullAddressedFrames;
///     unsigned int dot12OutHighPriorityFrames;
///     unsigned hyper dot12OutHighPriorityOctets;
///     unsigned int dot12TransitionIntoTrainings;
///     unsigned hyper dot12HCInHighPriorityOctets;
///     unsigned hyper dot12HCInNormPriorityOctets;
///     unsigned hyper dot12HCOutHighPriorityOctets;
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Vg100InterfaceCounters {
    pub dot12_in_high_priority_frames: u32,
    pub dot12_in_high_priority_octets: u64,
    pub dot12_in_norm_priority_frames: u32,
    pub dot12_in_norm_priority_octets: u64,
    pub dot12_in_ipm_errors: u32,
    pub dot12_in_oversize_frame_errors: u32,
    pub dot12_in_data_errors: u32,
    pub dot12_in_null_addressed_frames: u32,
    pub dot12_out_high_priority_frames: u32,
    pub dot12_out_high_priority_octets: u64,
    pub dot12_transition_into_trainings: u32,
    pub dot12_hc_in_high_priority_octets: u64,
    pub dot12_hc_in_norm_priority_octets: u64,
    pub dot12_hc_out_high_priority_octets: u64,
}

/// VLAN Counters - Format (0,5)
///
/// VLAN statistics
///
/// # XDR Definition ([sFlow v5](https://sflow.org/sflow_version_5.txt))
///
/// ```text
/// /* VLAN Counters */
/// /* opaque = counter_data; enterprise = 0; format = 5 */
///
/// struct vlan_counters {
///     unsigned int vlan_id;
///     unsigned hyper octets;
///     unsigned int ucastPkts;
///     unsigned int multicastPkts;
///     unsigned int broadcastPkts;
///     unsigned int discards;
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct VlanCounters {
    /// VLAN ID
    pub vlan_id: u32,

    /// Total octets
    pub octets: u64,

    /// Unicast packets
    pub ucast_pkts: u32,

    /// Multicast packets
    pub multicast_pkts: u32,

    /// Broadcast packets
    pub broadcast_pkts: u32,

    /// Discarded packets
    pub discards: u32,
}

/// IEEE 802.11 Counters - Format (0,6)
///
/// Wireless interface statistics
///
/// # XDR Definition ([sFlow 802.11](https://sflow.org/sflow_80211.txt))
///
/// ```text
/// /* IEEE802.11 interface counters - see IEEE802dot11-MIB */
/// /* opaque = counter_data; enterprise = 0; format = 6 */
///
/// struct ieee80211_counters {
///     unsigned int dot11TransmittedFragmentCount;
///     unsigned int dot11MulticastTransmittedFrameCount;
///     unsigned int dot11FailedCount;
///     unsigned int dot11RetryCount;
///     unsigned int dot11MultipleRetryCount;
///     unsigned int dot11FrameDuplicateCount;
///     unsigned int dot11RTSSuccessCount;
///     unsigned int dot11RTSFailureCount;
///     unsigned int dot11ACKFailureCount;
///     unsigned int dot11ReceivedFragmentCount;
///     unsigned int dot11MulticastReceivedFrameCount;
///     unsigned int dot11FCSErrorCount;
///     unsigned int dot11TransmittedFrameCount;
///     unsigned int dot11WEPUndecryptableCount;
///     unsigned int dot11QoSDiscardedFragmentCount;
///     unsigned int dot11AssociatedStationCount;
///     unsigned int dot11QoSCFPollsReceivedCount;
///     unsigned int dot11QoSCFPollsUnusedCount;
///     unsigned int dot11QoSCFPollsUnusableCount;
///     unsigned int dot11QoSCFPollsLostCount;
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Ieee80211Counters {
    pub dot11_transmitted_fragment_count: u32,
    pub dot11_multicast_transmitted_frame_count: u32,
    pub dot11_failed_count: u32,
    pub dot11_retry_count: u32,
    pub dot11_multiple_retry_count: u32,
    pub dot11_frame_duplicate_count: u32,
    pub dot11_rts_success_count: u32,
    pub dot11_rts_failure_count: u32,
    pub dot11_ack_failure_count: u32,
    pub dot11_received_fragment_count: u32,
    pub dot11_multicast_received_frame_count: u32,
    pub dot11_fcs_error_count: u32,
    pub dot11_transmitted_frame_count: u32,
    pub dot11_wep_undecryptable_count: u32,
    pub dot11_qos_discarded_fragment_count: u32,
    pub dot11_associated_station_count: u32,
    pub dot11_qos_cf_polls_received_count: u32,
    pub dot11_qos_cf_polls_unused_count: u32,
    pub dot11_qos_cf_polls_unusable_count: u32,
    pub dot11_qos_cf_polls_lost_count: u32,
}

/// Processor Counters - Format (0,1001)
///
/// CPU and memory utilization
///
/// # XDR Definition ([sFlow v5](https://sflow.org/sflow_version_5.txt))
///
/// ```text
/// /* Processor Information */
/// /* opaque = counter_data; enterprise = 0; format = 1001 */
///
/// struct processor {
///     percentage 5s_cpu;          /* 5 second average CPU utilization */
///     percentage 1m_cpu;          /* 1 minute average CPU utilization */
///     percentage 5m_cpu;          /* 5 minute average CPU utilization */
///     unsigned hyper total_memory /* total memory (in bytes) */
///     unsigned hyper free_memory  /* free memory (in bytes) */
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ProcessorCounters {
    /// 5 second average CPU utilization (0-100%) (spec: 5s_cpu)
    pub cpu_5s: u32,

    /// 1 minute average CPU utilization (0-100%) (spec: 1m_cpu)
    pub cpu_1m: u32,

    /// 5 minute average CPU utilization (0-100%) (spec: 5m_cpu)
    pub cpu_5m: u32,

    /// Total memory in bytes
    pub total_memory: u64,

    /// Free memory in bytes
    pub free_memory: u64,
}

/// Radio Utilization - Format (0,1002)
///
/// 802.11 radio channel utilization
///
/// # XDR Definition ([sFlow 802.11](https://sflow.org/sflow_80211.txt))
///
/// ```text
/// /* 802.11 radio utilization */
/// /* opaque = counter_data; enterprise = 0; format = 1002 */
///
/// struct radio_utilization {
///     unsigned int elapsed_time;        /* Elapsed time in ms */
///     unsigned int on_channel_time;     /* Time on assigned channel */
///     unsigned int on_channel_busy_time;/* Time busy on channel */
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RadioUtilization {
    /// Elapsed time in milliseconds
    pub elapsed_time: u32,

    /// On channel time
    pub on_channel_time: u32,

    /// On channel busy time
    pub on_channel_busy_time: u32,
}

/// OpenFlow Port - Format (0,1004)
///
/// OpenFlow port statistics
///
/// # XDR Definition ([sFlow OpenFlow](https://sflow.org/sflow_openflow.txt))
///
/// ```text
/// /* OpenFlow port */
/// /* opaque = counter_data; enterprise = 0; format = 1004 */
///
/// struct of_port {
///     unsigned hyper datapath_id;
///     unsigned int port_no;
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct OpenFlowPort {
    /// Datapath ID
    pub datapath_id: u64,

    /// Port number
    pub port_no: u32,
}

/// OpenFlow Port Name - Format (0,1005)
///
/// OpenFlow port name string
///
/// # XDR Definition ([sFlow OpenFlow](https://sflow.org/sflow_openflow.txt))
///
/// ```text
/// /* Port name */
/// /* opaque = counter_data; enterprise = 0; format = 1005 */
///
/// struct port_name {
///     string name<>;
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct OpenFlowPortName {
    /// Port name
    pub port_name: String,
}

/// Machine Type enumeration
///
/// Processor family types as defined in sFlow v5 specification
///
/// # XDR Definition ([sFlow Host](https://sflow.org/sflow_host.txt))
///
/// ```text
/// enum machine_type {
///    unknown = 0,
///    other   = 1,
///    x86     = 2,
///    x86_64  = 3,
///    ia64    = 4,
///    sparc   = 5,
///    alpha   = 6,
///    powerpc = 7,
///    m68k    = 8,
///    mips    = 9,
///    arm     = 10,
///    hppa    = 11,
///    s390    = 12
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u32)]
pub enum MachineType {
    Unknown = 0,
    Other = 1,
    X86 = 2,
    X86_64 = 3,
    Ia64 = 4,
    Sparc = 5,
    Alpha = 6,
    Powerpc = 7,
    M68k = 8,
    Mips = 9,
    Arm = 10,
    Hppa = 11,
    S390 = 12,
}

impl From<u32> for MachineType {
    fn from(value: u32) -> Self {
        match value {
            0 => MachineType::Unknown,
            1 => MachineType::Other,
            2 => MachineType::X86,
            3 => MachineType::X86_64,
            4 => MachineType::Ia64,
            5 => MachineType::Sparc,
            6 => MachineType::Alpha,
            7 => MachineType::Powerpc,
            8 => MachineType::M68k,
            9 => MachineType::Mips,
            10 => MachineType::Arm,
            11 => MachineType::Hppa,
            12 => MachineType::S390,
            _ => MachineType::Unknown,
        }
    }
}

/// Operating System Name enumeration
///
/// OS types as defined in sFlow v5 specification
///
/// # XDR Definition ([sFlow Host](https://sflow.org/sflow_host.txt))
///
/// ```text
/// enum os_name {
///    unknown   = 0,
///    other     = 1,
///    linux     = 2,
///    windows   = 3,
///    darwin    = 4,
///    hpux      = 5,
///    aix       = 6,
///    dragonfly = 7,
///    freebsd   = 8,
///    netbsd    = 9,
///    openbsd   = 10,
///    osf       = 11,
///    solaris   = 12
/// }
/// ```
///
/// **Note:** The enumeration may be expanded over time. Applications receiving
/// sFlow must be prepared to receive host_descr structures with unknown os_name values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u32)]
pub enum OsName {
    Unknown = 0,
    Other = 1,
    Linux = 2,
    Windows = 3,
    Darwin = 4,
    Hpux = 5,
    Aix = 6,
    Dragonfly = 7,
    Freebsd = 8,
    Netbsd = 9,
    Openbsd = 10,
    Osf = 11,
    Solaris = 12,
}

impl From<u32> for OsName {
    fn from(value: u32) -> Self {
        match value {
            0 => OsName::Unknown,
            1 => OsName::Other,
            2 => OsName::Linux,
            3 => OsName::Windows,
            4 => OsName::Darwin,
            5 => OsName::Hpux,
            6 => OsName::Aix,
            7 => OsName::Dragonfly,
            8 => OsName::Freebsd,
            9 => OsName::Netbsd,
            10 => OsName::Openbsd,
            11 => OsName::Osf,
            12 => OsName::Solaris,
            _ => OsName::Unknown,
        }
    }
}

/// Host Description - Format (0,2000)
///
/// Physical or virtual host description
///
/// # XDR Definition ([sFlow Host](https://sflow.org/sflow_host.txt))
///
/// ```text
/// /* Physical or virtual host description */
/// /* opaque = counter_data; enterprise = 0; format = 2000 */
///
/// struct host_descr {
///    string hostname<64>;       /* hostname, empty if unknown */
///    opaque uuid<16>;           /* 16 bytes binary UUID, empty if unknown */
///    machine_type machine_type; /* the processor family */
///    os_name os_name;           /* Operating system */
///    string os_release<32>;     /* e.g. 2.6.9-42.ELsmp,xp-sp3, empty if unknown */
/// }
/// ```
///
/// **ERRATUM:** UUID field changed from `opaque uuid<16>` to `opaque uuid[16]` (fixed array).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct HostDescription {
    /// Hostname
    pub hostname: String,

    /// UUID (16 bytes)
    /// **ERRATUM:** All zeros if unknown (changed from variable-length to fixed-length array)
    pub uuid: [u8; 16],

    /// Machine type (processor family)
    pub machine_type: MachineType,

    /// Operating system name
    pub os_name: OsName,

    /// OS release (e.g., "5.10.0")
    pub os_release: String,
}

/// Host Adapters - Format (0,2001)
///
/// Set of network adapters associated with entity
///
/// # XDR Definition ([sFlow Host](https://sflow.org/sflow_host.txt))
///
/// ```text
/// /* Set of adapters associated with entity */
/// /* opaque = counter_data; enterprise = 0; format = 2001 */
///
/// struct host_adapters {
///     adapter adapters<>; /* adapter(s) associated with entity */
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct HostAdapters {
    /// Adapters
    pub adapters: Vec<HostAdapter>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct HostAdapter {
    /// Interface index
    pub if_index: u32,

    /// MAC addresses
    pub mac_addresses: Vec<crate::models::MacAddress>,
}

/// Host Parent - Format (0,2002)
///
/// Containment hierarchy between logical and physical entities
///
/// # XDR Definition ([sFlow Host](https://sflow.org/sflow_host.txt))
///
/// ```text
/// /* Define containment hierarchy */
/// /* opaque = counter_data; enterprise = 0; format = 2002 */
///
/// struct host_parent {
///     unsigned int container_type;  /* sFlowDataSource type */
///     unsigned int container_index; /* sFlowDataSource index */
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct HostParent {
    /// Container type (e.g., "docker", "lxc")
    pub container_type: u32,

    /// Container index
    pub container_index: u32,
}

/// Host CPU - Format (0,2003)
///
/// Physical server CPU statistics
///
/// # XDR Definition ([sFlow Host](https://sflow.org/sflow_host.txt))
///
/// ```text
/// /* Physical Server CPU */
/// /* opaque = counter_data; enterprise = 0; format = 2003 */
///
/// struct host_cpu {
///     float load_one;          /* 1 minute load avg */
///     float load_five;         /* 5 minute load avg */
///     float load_fifteen;      /* 15 minute load avg */
///     unsigned int proc_run;   /* running processes */
///     unsigned int proc_total; /* total processes */
///     unsigned int cpu_num;    /* number of CPUs */
///     unsigned int cpu_speed;  /* CPU speed in MHz */
///     unsigned int uptime;     /* seconds since last reboot */
///     unsigned int cpu_user;   /* user time (ms) */
///     unsigned int cpu_nice;   /* nice time (ms) */
///     unsigned int cpu_system; /* system time (ms) */
///     unsigned int cpu_idle;   /* idle time (ms) */
///     unsigned int cpu_wio;    /* I/O wait time (ms) */
///     unsigned int cpu_intr;   /* interrupt time (ms) */
///     unsigned int cpu_sintr;  /* soft interrupt time (ms) */
///     unsigned int interrupts; /* interrupt count */
///     unsigned int contexts;   /* context switch count */
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct HostCpu {
    /// Load average (1 minute) - stored as hundredths (multiply by 100)
    pub load_one: u32,

    /// Load average (5 minutes) - stored as hundredths (multiply by 100)
    pub load_five: u32,

    /// Load average (15 minutes) - stored as hundredths (multiply by 100)
    pub load_fifteen: u32,

    /// Number of running processes
    pub proc_run: u32,

    /// Total number of processes
    pub proc_total: u32,

    /// Number of CPUs
    pub cpu_num: u32,

    /// CPU speed in MHz
    pub cpu_speed: u32,

    /// CPU uptime in seconds
    pub uptime: u32,

    /// CPU time in user mode (ms)
    pub cpu_user: u32,

    /// CPU time in nice mode (ms)
    pub cpu_nice: u32,

    /// CPU time in system mode (ms)
    pub cpu_system: u32,

    /// CPU idle time (ms)
    pub cpu_idle: u32,

    /// CPU time waiting for I/O (ms)
    pub cpu_wio: u32,

    /// CPU time servicing interrupts (ms)
    pub cpu_intr: u32,

    /// CPU time servicing soft interrupts (ms)
    pub cpu_sintr: u32,

    /// Number of interrupts
    pub interrupts: u32,

    /// Number of context switches
    pub contexts: u32,
}

/// Host Memory - Format (0,2004)
///
/// Physical server memory statistics
///
/// # XDR Definition ([sFlow Host](https://sflow.org/sflow_host.txt))
///
/// ```text
/// /* Physical Server Memory */
/// /* opaque = counter_data; enterprise = 0; format = 2004 */
///
/// struct host_memory {
///     unsigned hyper mem_total;   /* total bytes */
///     unsigned hyper mem_free;    /* free bytes */
///     unsigned hyper mem_shared;  /* shared bytes */
///     unsigned hyper mem_buffers; /* buffers bytes */
///     unsigned hyper mem_cached;  /* cached bytes */
///     unsigned hyper swap_total;  /* swap total bytes */
///     unsigned hyper swap_free;   /* swap free bytes */
///     unsigned int page_in;       /* page in count */
///     unsigned int page_out;      /* page out count */
///     unsigned int swap_in;       /* swap in count */
///     unsigned int swap_out;      /* swap out count */
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct HostMemory {
    /// Total memory in bytes
    pub mem_total: u64,

    /// Free memory in bytes
    pub mem_free: u64,

    /// Shared memory in bytes
    pub mem_shared: u64,

    /// Memory used for buffers in bytes
    pub mem_buffers: u64,

    /// Memory used for cache in bytes
    pub mem_cached: u64,

    /// Total swap space in bytes
    pub swap_total: u64,

    /// Free swap space in bytes
    pub swap_free: u64,

    /// Page in count
    pub page_in: u32,

    /// Page out count
    pub page_out: u32,

    /// Swap in count
    pub swap_in: u32,

    /// Swap out count
    pub swap_out: u32,
}

/// Host Disk I/O - Format (0,2005)
///
/// Physical server disk I/O statistics
///
/// # XDR Definition ([sFlow Host](https://sflow.org/sflow_host.txt))
///
/// ```text
/// /* Physical Server Disk I/O */
/// /* opaque = counter_data; enterprise = 0; format = 2005 */
///
/// struct host_disk_io {
///     unsigned hyper disk_total;    /* total disk size in bytes */
///     unsigned hyper disk_free;     /* total disk free in bytes */
///     percentage part_max_used;     /* utilization of most utilized partition */
///     unsigned int reads;           /* reads issued */
///     unsigned hyper bytes_read;    /* bytes read */
///     unsigned int read_time;       /* read time (ms) */
///     unsigned int writes;          /* writes completed */
///     unsigned hyper bytes_written; /* bytes written */
///     unsigned int write_time;      /* write time (ms) */
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct HostDiskIo {
    /// Total disk capacity in bytes
    pub disk_total: u64,

    /// Free disk space in bytes
    pub disk_free: u64,

    /// Percentage of disk used (0-100)
    pub part_max_used: u32,

    /// Number of disk reads
    pub reads: u32,

    /// Bytes read from disk
    pub bytes_read: u64,

    /// Read time in milliseconds
    pub read_time: u32,

    /// Number of disk writes
    pub writes: u32,

    /// Bytes written to disk
    pub bytes_written: u64,

    /// Write time in milliseconds
    pub write_time: u32,
}

/// Host Network I/O - Format (0,2006)
///
/// Physical server network I/O statistics
///
/// # XDR Definition ([sFlow Host](https://sflow.org/sflow_host.txt))
///
/// ```text
/// /* Physical Server Network I/O */
/// /* opaque = counter_data; enterprise = 0; format = 2006 */
///
/// struct host_net_io {
///     unsigned hyper bytes_in;  /* total bytes in */
///     unsigned int pkts_in;     /* total packets in */
///     unsigned int errs_in;     /* total errors in */
///     unsigned int drops_in;    /* total drops in */
///     unsigned hyper bytes_out; /* total bytes out */
///     unsigned int packets_out; /* total packets out */
///     unsigned int errs_out;    /* total errors out */
///     unsigned int drops_out;   /* total drops out */
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct HostNetIo {
    /// Bytes received
    pub bytes_in: u64,

    /// Packets received
    pub pkts_in: u32,

    /// Receive errors
    pub errs_in: u32,

    /// Receive drops
    pub drops_in: u32,

    /// Bytes transmitted
    pub bytes_out: u64,

    /// Packets transmitted
    pub packets_out: u32,

    /// Transmit errors
    pub errs_out: u32,

    /// Transmit drops
    pub drops_out: u32,
}

/// Virtual Node - Format (0,2100)
///
/// Hypervisor statistics
///
/// # XDR Definition ([sFlow Host](https://sflow.org/sflow_host.txt))
///
/// ```text
/// /* Virtual Node Statistics */
/// /* opaque = counter_data; enterprise = 0; format = 2100 */
///
/// struct virt_node {
///     unsigned int mhz;           /* expected CPU frequency */
///     unsigned int cpus;          /* number of active CPUs */
///     unsigned hyper memory;      /* memory size in bytes */
///     unsigned hyper memory_free; /* unassigned memory in bytes */
///     unsigned int num_domains;   /* number of active domains */
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct VirtualNode {
    /// Expected CPU frequency in MHz
    pub mhz: u32,

    /// Number of active CPUs
    pub cpus: u32,

    /// Memory size in bytes
    pub memory: u64,

    /// Unassigned memory in bytes
    pub memory_free: u64,

    /// Number of active domains
    pub num_domains: u32,
}

/// Virtual CPU - Format (0,2101)
///
/// Virtual domain CPU statistics
///
/// # XDR Definition ([sFlow Host](https://sflow.org/sflow_host.txt))
///
/// ```text
/// /* Virtual Domain CPU statistics */
/// /* See libvirt, struct virDomainInfo */
/// /* opaque = counter_data; enterprise = 0; format = 2101 */
///
/// struct virt_cpu {
///     unsigned int state;    /* virtDomainState */
///     unsigned int cpuTime;  /* CPU time used (ms) */
///     unsigned int nrVirtCpu;/* number of virtual CPUs */
/// }
/// ```
///
/// **ERRATUM:** Comment reference corrected from `virtDomainInfo` to `virDomainInfo`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct VirtualCpu {
    /// CPU state (0=running, 1=idle, 2=blocked)
    pub state: u32,

    /// CPU time in milliseconds
    pub cpu_time: u32,

    /// Number of virtual CPUs
    pub nr_virt_cpu: u32,
}

/// Virtual Memory - Format (0,2102)
///
/// Virtual domain memory statistics
///
/// # XDR Definition ([sFlow Host](https://sflow.org/sflow_host.txt))
///
/// ```text
/// /* Virtual Domain Memory statistics */
/// /* See libvirt, struct virDomainInfo */
/// /* opaque = counter_data; enterprise = 0; format = 2102 */
///
/// struct virt_memory {
///     unsigned hyper memory;    /* memory in bytes used by domain */
///     unsigned hyper maxMemory; /* memory in bytes allowed */
/// }
/// ```
///
/// **ERRATUM:** Comment reference corrected from `virtDomainInfo` to `virDomainInfo`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct VirtualMemory {
    /// Memory in bytes
    pub memory: u64,

    /// Maximum memory in bytes
    pub max_memory: u64,
}

/// Virtual Disk I/O - Format (0,2103)
///
/// Virtual domain disk statistics
///
/// # XDR Definition ([sFlow Host](https://sflow.org/sflow_host.txt))
///
/// ```text
/// /* Virtual Domain Disk statistics */
/// /* See libvirt, struct virDomainBlockInfo */
/// /* See libvirt, struct virDomainBlockStatsStruct */
/// /* opaque = counter_data; enterprise = 0; format = 2103 */
///
/// struct virt_disk_io {
///     unsigned hyper capacity;   /* logical size in bytes */
///     unsigned hyper allocation; /* current allocation in bytes */
///     unsigned hyper physical;   /* physical size in bytes of the container of the backing image */
///     unsigned int rd_req;       /* number of read requests */
///     unsigned hyper rd_bytes;   /* number of read bytes */
///     unsigned int wr_req;       /* number of write requests */
///     unsigned hyper wr_bytes;   /* number of written bytes */
///     unsigned int errs;         /* read/write errors */
/// }
/// ```
///
/// **ERRATUM:** Field name changed from `available` to `physical`, and comment references corrected
/// from `virtDomainBlockInfo`/`virtDomainBlockStatsStruct` to `virDomainBlockInfo`/`virDomainBlockStatsStruct`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct VirtualDiskIo {
    /// Capacity in bytes
    pub capacity: u64,

    /// Allocation in bytes
    pub allocation: u64,

    /// Physical size in bytes of the container of the backing image (spec: physical)
    /// **ERRATUM:** Field renamed from `available` (remaining free bytes) to `physical`
    pub available: u64,

    /// Read requests
    pub rd_req: u32,

    /// Bytes read
    pub rd_bytes: u64,

    /// Write requests
    pub wr_req: u32,

    /// Bytes written
    pub wr_bytes: u64,

    /// Errors
    pub errs: u32,
}

/// Virtual Network I/O - Format (0,2104)
///
/// Virtual domain network statistics
///
/// # XDR Definition ([sFlow Host](https://sflow.org/sflow_host.txt))
///
/// ```text
/// /* Virtual Domain Network statistics */
/// /* See libvirt, struct virDomainInterfaceStatsStruct */
/// /* opaque = counter_data; enterprise = 0; format = 2104 */
///
/// struct virt_net_io {
///     unsigned hyper rx_bytes;  /* total bytes received */
///     unsigned int rx_packets;  /* total packets received */
///     unsigned int rx_errs;     /* total receive errors */
///     unsigned int rx_drop;     /* total receive drops */
///     unsigned hyper tx_bytes;  /* total bytes transmitted */
///     unsigned int tx_packets;  /* total packets transmitted */
///     unsigned int tx_errs;     /* total transmit errors */
///     unsigned int tx_drop;     /* total transmit drops */
/// }
/// ```
///
/// **ERRATUM:** Comment reference corrected from `virtDomainInterfaceStatsStruct` to `virDomainInterfaceStatsStruct`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct VirtualNetIo {
    /// Bytes received
    pub rx_bytes: u64,

    /// Packets received
    pub rx_packets: u32,

    /// Receive errors
    pub rx_errs: u32,

    /// Receive drops
    pub rx_drop: u32,

    /// Bytes transmitted
    pub tx_bytes: u64,

    /// Packets transmitted
    pub tx_packets: u32,

    /// Transmit errors
    pub tx_errs: u32,

    /// Transmit drops
    pub tx_drop: u32,
}

/// HTTP Counters - Format (0,2201)
///
/// HTTP performance counters
///
/// # XDR Definition ([sFlow HTTP](https://sflow.org/sflow_http.txt))
///
/// ```text
/// /* HTTP counters */
/// /* opaque = counter_data; enterprise = 0; format = 2201 */
/// struct http_counters {
///   unsigned int method_option_count;
///   unsigned int method_get_count;
///   unsigned int method_head_count;
///   unsigned int method_post_count;
///   unsigned int method_put_count;
///   unsigned int method_delete_count;
///   unsigned int method_trace_count;
///   unsigned int method_connect_count;
///   unsigned int method_other_count;
///   unsigned int status_1XX_count;
///   unsigned int status_2XX_count;
///   unsigned int status_3XX_count;
///   unsigned int status_4XX_count;
///   unsigned int status_5XX_count;
///   unsigned int status_other_count;
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct HttpCounters {
    /// OPTIONS method count
    pub method_option_count: u32,

    /// GET method count
    pub method_get_count: u32,

    /// HEAD method count
    pub method_head_count: u32,

    /// POST method count
    pub method_post_count: u32,

    /// PUT method count
    pub method_put_count: u32,

    /// DELETE method count
    pub method_delete_count: u32,

    /// TRACE method count
    pub method_trace_count: u32,

    /// CONNECT method count
    pub method_connect_count: u32,

    /// Other method count
    pub method_other_count: u32,

    /// 1XX status code count (spec: status_1XX_count)
    pub status_1xx_count: u32,

    /// 2XX status code count (spec: status_2XX_count)
    pub status_2xx_count: u32,

    /// 3XX status code count (spec: status_3XX_count)
    pub status_3xx_count: u32,

    /// 4XX status code count (spec: status_4XX_count)
    pub status_4xx_count: u32,

    /// 5XX status code count (spec: status_5XX_count)
    pub status_5xx_count: u32,

    /// Other status code count
    pub status_other_count: u32,
}

/// App Operations - Format (0,2202)
///
/// Count of operations by status code
///
/// # XDR Definition ([sFlow Application](https://sflow.org/sflow_application.txt))
///
/// ```text
/// /* Application counters */
/// /* opaque = counter_data; enterprise = 0; format = 2202 */
///
/// struct app_operations {
///     application application;
///     unsigned int success;
///     unsigned int other;
///     unsigned int timeout;
///     unsigned int internal_error;
///     unsigned int bad_request;
///     unsigned int forbidden;
///     unsigned int too_large;
///     unsigned int not_implemented;
///     unsigned int not_found;
///     unsigned int unavailable;
///     unsigned int unauthorized;
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AppOperations {
    /// Application identifier
    pub application: String,

    /// Successful operations
    pub success: u32,

    /// Other status
    pub other: u32,

    /// Timeout
    pub timeout: u32,

    /// Internal error
    pub internal_error: u32,

    /// Bad request
    pub bad_request: u32,

    /// Forbidden
    pub forbidden: u32,

    /// Too large
    pub too_large: u32,

    /// Not implemented
    pub not_implemented: u32,

    /// Not found
    pub not_found: u32,

    /// Unavailable
    pub unavailable: u32,

    /// Unauthorized
    pub unauthorized: u32,
}

/// App Resources - Format (0,2203)
///
/// Application resource usage
///
/// # XDR Definition ([sFlow Application](https://sflow.org/sflow_application.txt))
///
/// ```text
/// /* Application resources */
/// /* opaque = counter_data; enterprise = 0; format = 2203 */
///
/// struct app_resources {
///     unsigned int user_time;   /* user time (ms) */
///     unsigned int system_time; /* system time (ms) */
///     unsigned hyper mem_used;  /* memory used in bytes */
///     unsigned hyper mem_max;   /* max memory in bytes */
///     unsigned int fd_open;     /* open file descriptors */
///     unsigned int fd_max;      /* max file descriptors */
///     unsigned int conn_open;   /* open network connections */
///     unsigned int conn_max;    /* max network connections */
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AppResources {
    /// User time in milliseconds
    pub user_time: u32,

    /// System time in milliseconds
    pub system_time: u32,

    /// Memory used in bytes
    pub mem_used: u64,

    /// Maximum memory in bytes
    pub mem_max: u64,

    /// Number of open file descriptors
    pub fd_open: u32,

    /// Maximum number of file descriptors
    pub fd_max: u32,

    /// Number of open connections
    pub conn_open: u32,

    /// Maximum number of connections
    pub conn_max: u32,
}

/// App Workers - Format (0,2206)
///
/// Application worker thread/process statistics
///
/// # XDR Definition ([sFlow Application](https://sflow.org/sflow_application.txt))
///
/// ```text
/// /* Application workers */
/// /* opaque = counter_data; enterprise = 0; format = 2206 */
///
/// struct app_workers {
///     unsigned int workers_active; /* number of active workers */
///     unsigned int workers_idle;   /* number of idle workers */
///     unsigned int workers_max;    /* max number of workers */
///     unsigned int req_delayed;    /* requests delayed */
///     unsigned int req_dropped;    /* requests dropped */
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AppWorkers {
    /// Number of active workers
    pub workers_active: u32,

    /// Number of idle workers
    pub workers_idle: u32,

    /// Maximum number of workers
    pub workers_max: u32,

    /// Number of delayed requests
    pub req_delayed: u32,

    /// Number of dropped requests
    pub req_dropped: u32,
}
