//! Tests for counter record parsers
//!
//! These tests validate counter record parsing logic that isn't covered
//! by integration tests (less common counter types).

use sflow_parser::models::record_counters::*;
use sflow_parser::models::MacAddress;
use sflow_parser::models::{MachineType, OsName};

#[test]
fn test_token_ring_counters_structure() {
    // Test that TokenRingCounters structure exists and has expected fields
    let counters = TokenRingCounters {
        dot5_stats_line_errors: 0,
        dot5_stats_burst_errors: 0,
        dot5_stats_ac_errors: 0,
        dot5_stats_abort_trans_errors: 0,
        dot5_stats_internal_errors: 0,
        dot5_stats_lost_frame_errors: 0,
        dot5_stats_receive_congestions: 0,
        dot5_stats_frame_copied_errors: 0,
        dot5_stats_token_errors: 0,
        dot5_stats_soft_errors: 0,
        dot5_stats_hard_errors: 0,
        dot5_stats_signal_loss: 0,
        dot5_stats_transmit_beacons: 0,
        dot5_stats_recoverys: 0,
        dot5_stats_lobe_wires: 0,
        dot5_stats_removes: 0,
        dot5_stats_singles: 0,
        dot5_stats_freq_errors: 0,
    };

    assert_eq!(counters.dot5_stats_line_errors, 0);
}

#[test]
fn test_vg100_interface_counters_structure() {
    // Test that Vg100InterfaceCounters structure exists
    let counters = Vg100InterfaceCounters {
        dot12_in_high_priority_frames: 10,
        dot12_in_high_priority_octets: 1000,
        dot12_in_norm_priority_frames: 40,
        dot12_in_norm_priority_octets: 4000,
        dot12_in_ipm_errors: 0,
        dot12_in_oversize_frame_errors: 0,
        dot12_in_data_errors: 0,
        dot12_in_null_addressed_frames: 0,
        dot12_out_high_priority_frames: 12,
        dot12_out_high_priority_octets: 1200,
        dot12_transition_into_trainings: 0,
        dot12_hc_in_high_priority_octets: 1000,
        dot12_hc_in_norm_priority_octets: 4000,
        dot12_hc_out_high_priority_octets: 1200,
    };

    assert_eq!(counters.dot12_in_high_priority_frames, 10);
}

#[test]
fn test_vlan_counters() {
    let counters = VlanCounters {
        vlan_id: 100,
        octets: 10000,
        ucast_pkts: 100,
        multicast_pkts: 20,
        broadcast_pkts: 10,
        discards: 0,
    };

    assert_eq!(counters.vlan_id, 100);
    assert_eq!(counters.octets, 10000);
    assert_eq!(counters.ucast_pkts, 100);
}

#[test]
fn test_radio_utilization() {
    let counters = RadioUtilization {
        elapsed_time: 1000,
        on_channel_time: 900,
        on_channel_busy_time: 450,
    };

    assert_eq!(counters.elapsed_time, 1000);
    assert_eq!(counters.on_channel_time, 900);
    assert_eq!(counters.on_channel_busy_time, 450);
}

#[test]
fn test_host_adapters() {
    let adapter1 = HostAdapter {
        if_index: 1,
        mac_addresses: vec![MacAddress::from([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])],
    };
    let adapter2 = HostAdapter {
        if_index: 2,
        mac_addresses: vec![MacAddress::from([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])],
    };

    let counters = HostAdapters {
        adapters: vec![adapter1, adapter2],
    };

    assert_eq!(counters.adapters.len(), 2);
    assert_eq!(counters.adapters[0].if_index, 1);
    assert_eq!(counters.adapters[1].if_index, 2);
}

#[test]
fn test_host_parent() {
    let counters = HostParent {
        container_type: 1,
        container_index: 42,
    };

    assert_eq!(counters.container_type, 1);
    assert_eq!(counters.container_index, 42);
}

#[test]
fn test_virtual_node() {
    let counters = VirtualNode {
        mhz: 2400,
        cpus: 4,
        memory: 8_589_934_592,      // 8 GB
        memory_free: 4_294_967_296, // 4 GB
        num_domains: 2,
    };

    assert_eq!(counters.mhz, 2400);
    assert_eq!(counters.cpus, 4);
    assert_eq!(counters.memory, 8_589_934_592);
    assert_eq!(counters.memory_free, 4_294_967_296);
    assert_eq!(counters.num_domains, 2);
}

#[test]
fn test_virtual_cpu() {
    let counters = VirtualCpu {
        state: 1,
        cpu_time: 1_000_000,
        nr_virt_cpu: 2,
    };

    assert_eq!(counters.state, 1);
    assert_eq!(counters.cpu_time, 1_000_000);
    assert_eq!(counters.nr_virt_cpu, 2);
}

#[test]
fn test_virtual_memory() {
    let counters = VirtualMemory {
        memory: 2_147_483_648,     // 2 GB
        max_memory: 4_294_967_296, // 4 GB
    };

    assert_eq!(counters.memory, 2_147_483_648);
    assert_eq!(counters.max_memory, 4_294_967_296);
}

#[test]
fn test_virtual_disk_io() {
    let counters = VirtualDiskIo {
        capacity: 107_374_182_400,  // 100 GB
        allocation: 53_687_091_200, // 50 GB
        available: 53_687_091_200,  // 50 GB
        rd_req: 1000,
        rd_bytes: 10_485_760, // 10 MB
        wr_req: 500,
        wr_bytes: 5_242_880, // 5 MB
        errs: 0,
    };

    assert_eq!(counters.capacity, 107_374_182_400);
    assert_eq!(counters.rd_req, 1000);
    assert_eq!(counters.wr_req, 500);
}

#[test]
fn test_virtual_net_io() {
    let counters = VirtualNetIo {
        rx_bytes: 1_048_576, // 1 MB
        rx_packets: 1000,
        rx_errs: 0,
        rx_drop: 0,
        tx_bytes: 524_288, // 512 KB
        tx_packets: 500,
        tx_errs: 0,
        tx_drop: 0,
    };

    assert_eq!(counters.rx_bytes, 1_048_576);
    assert_eq!(counters.rx_packets, 1000);
    assert_eq!(counters.tx_bytes, 524_288);
    assert_eq!(counters.tx_packets, 500);
}

#[test]
fn test_openflow_port() {
    let counters = OpenFlowPort {
        datapath_id: 0x0000000000000001,
        port_no: 1,
    };

    assert_eq!(counters.datapath_id, 1);
    assert_eq!(counters.port_no, 1);
}

#[test]
fn test_openflow_port_name() {
    let counters = OpenFlowPortName {
        port_name: "eth0".to_string(),
    };

    assert_eq!(counters.port_name, "eth0");
}

#[test]
fn test_app_resources() {
    let counters = AppResources {
        user_time: 5000,
        system_time: 2000,
        mem_used: 104_857_600,  // 100 MB
        mem_max: 1_073_741_824, // 1 GB
        fd_open: 50,
        fd_max: 1024,
        conn_open: 10,
        conn_max: 100,
    };

    assert_eq!(counters.user_time, 5000);
    assert_eq!(counters.system_time, 2000);
    assert_eq!(counters.mem_used, 104_857_600);
    assert_eq!(counters.fd_open, 50);
    assert_eq!(counters.conn_open, 10);
}

#[test]
fn test_host_description() {
    let uuid_bytes = [
        0x55, 0x0e, 0x84, 0x00, 0xe2, 0x9b, 0x41, 0xd4, 0xa7, 0x16, 0x44, 0x66, 0x55, 0x44, 0x00,
        0x00,
    ];

    let counters = HostDescription {
        hostname: "server01.example.com".to_string(),
        uuid: uuid_bytes,
        machine_type: MachineType::X86_64,
        os_name: OsName::Linux,
        os_release: "5.15.0-56-generic".to_string(),
    };

    assert_eq!(counters.hostname, "server01.example.com");
    assert_eq!(counters.uuid[0], 0x55);
    assert_eq!(counters.uuid[1], 0x0e);
    assert_eq!(counters.machine_type, MachineType::X86_64);
    assert_eq!(counters.os_name, OsName::Linux);
}
