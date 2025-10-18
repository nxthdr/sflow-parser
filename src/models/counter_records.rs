//! Counter record data structures
//!
//! These represent interface and system statistics collected periodically.
//! Enterprise = 0 (sFlow.org standard formats)

/// Generic Interface Counters - Format (0,1)
/// Standard interface statistics (RFC 2233)
#[derive(Debug, Clone, PartialEq, Eq)]
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
/// Ethernet-specific statistics (RFC 2358)
#[derive(Debug, Clone, PartialEq, Eq)]
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
#[derive(Debug, Clone, PartialEq, Eq)]
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vg100InterfaceCounters {
    pub dot12_in_high_priority_frames: u32,
    pub dot12_in_high_priority_octets: u64,
    pub dot12_in_norm_priority_frames: u32,
    pub dot12_in_norm_priority_octets: u64,
    pub dot12_in_ipm_errors: u32,
    pub dot12_in_oversized_frame_errors: u32,
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
#[derive(Debug, Clone, PartialEq, Eq)]
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

/// Processor Counters - Format (0,1001)
/// CPU and memory utilization
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessorCounters {
    /// 5 second average CPU utilization (0-100%)
    pub cpu_5s: u32,

    /// 1 minute average CPU utilization (0-100%)
    pub cpu_1m: u32,

    /// 5 minute average CPU utilization (0-100%)
    pub cpu_5m: u32,

    /// Total memory in bytes
    pub total_memory: u64,

    /// Free memory in bytes
    pub free_memory: u64,
}

/// Radio Utilization - Format (0,1002)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RadioUtilization {
    /// Elapsed time in milliseconds
    pub elapsed_time: u32,

    /// On channel time
    pub on_channel_time: u32,

    /// On channel busy time
    pub on_channel_busy_time: u32,
}

/// Host Description - Format (0,2000)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostDescription {
    /// Hostname
    pub hostname: String,

    /// UUID (16 bytes)
    pub uuid: [u8; 16],

    /// Machine type (e.g., "x86_64")
    pub machine_type: String,

    /// OS name (e.g., "Linux")
    pub os_name: String,

    /// OS release (e.g., "5.10.0")
    pub os_release: String,
}

/// Host Adapters - Format (0,2001)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostAdapter {
    /// Interface index
    pub if_index: u32,

    /// MAC addresses
    pub mac_addresses: Vec<[u8; 6]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostAdapters {
    pub adapters: Vec<HostAdapter>,
}

/// Host Parent - Format (0,2002)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostParent {
    /// Container type (e.g., "docker", "lxc")
    pub container_type: u32,

    /// Container index
    pub container_index: u32,
}

/// Host CPU - Format (0,2003)
#[derive(Debug, Clone, PartialEq, Eq)]
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
#[derive(Debug, Clone, PartialEq, Eq)]
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
#[derive(Debug, Clone, PartialEq, Eq)]
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
#[derive(Debug, Clone, PartialEq, Eq)]
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
    pub pkts_out: u32,

    /// Transmit errors
    pub errs_out: u32,

    /// Transmit drops
    pub drops_out: u32,
}

/// Virtual Node - Format (0,2100)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VirtualNode {
    /// Memory in bytes
    pub memory: u64,

    /// Number of virtual CPUs
    pub num_cpus: u32,

    /// CPU time in milliseconds
    pub cpu_time: u32,
}

/// Virtual CPU - Format (0,2101)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VirtualCpu {
    /// CPU state (0=running, 1=idle, 2=blocked)
    pub state: u32,

    /// CPU time in milliseconds
    pub cpu_time: u32,
}

/// Virtual Memory - Format (0,2102)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VirtualMemory {
    /// Memory in bytes
    pub memory: u64,

    /// Maximum memory in bytes
    pub max_memory: u64,
}

/// Virtual Disk I/O - Format (0,2103)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VirtualDiskIo {
    /// Capacity in bytes
    pub capacity: u64,

    /// Allocation in bytes
    pub allocation: u64,

    /// Available in bytes
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VirtualNetIo {
    /// Bytes received
    pub rx_bytes: u64,

    /// Packets received
    pub rx_pkts: u32,

    /// Receive errors
    pub rx_errs: u32,

    /// Receive drops
    pub rx_drop: u32,

    /// Bytes transmitted
    pub tx_bytes: u64,

    /// Packets transmitted
    pub tx_pkts: u32,

    /// Transmit errors
    pub tx_errs: u32,

    /// Transmit drops
    pub tx_drop: u32,
}

/// OpenFlow Port - Format (0,1004)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenFlowPort {
    /// Datapath ID
    pub datapath_id: u64,

    /// Port number
    pub port_no: u32,
}

/// OpenFlow Port Name - Format (0,1005)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenFlowPortName {
    /// Port name
    pub port_name: String,
}

/// App Resources - Format (0,2206)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppResources {
    /// User time in milliseconds
    pub user_time: u32,

    /// System time in milliseconds
    pub system_time: u32,

    /// Memory used in bytes
    pub mem_used: u64,

    /// Maximum memory in bytes
    pub mem_max: u64,

    /// File descriptors
    pub fd_open: u32,

    /// Maximum file descriptors
    pub fd_max: u32,

    /// Connection count
    pub conn_open: u32,

    /// Maximum connections
    pub conn_max: u32,
}
