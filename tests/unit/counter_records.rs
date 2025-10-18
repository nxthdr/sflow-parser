//! Tests for counter record structures

use sflow_parser::models::counter_records::*;
use sflow_parser::models::*;

#[test]
fn test_generic_interface_counters() {
    let counters = GenericInterfaceCounters {
        if_index: 1,
        if_type: 6,              // Ethernet
        if_speed: 1_000_000_000, // 1 Gbps
        if_direction: 1,
        if_status: 3,
        if_in_octets: 1000000,
        if_in_ucast_pkts: 5000,
        if_in_multicast_pkts: 100,
        if_in_broadcast_pkts: 50,
        if_in_discards: 0,
        if_in_errors: 0,
        if_in_unknown_protos: 0,
        if_out_octets: 2000000,
        if_out_ucast_pkts: 10000,
        if_out_multicast_pkts: 200,
        if_out_broadcast_pkts: 100,
        if_out_discards: 0,
        if_out_errors: 0,
        if_promiscuous_mode: 2,
    };
    assert_eq!(counters.if_index, 1);
    assert_eq!(counters.if_type, 6);
    assert_eq!(counters.if_speed, 1_000_000_000);
    assert_eq!(counters.if_in_octets, 1000000);
    assert_eq!(counters.if_out_octets, 2000000);
}

#[test]
fn test_ethernet_interface_counters() {
    let counters = EthernetInterfaceCounters {
        dot3_stats_alignment_errors: 0,
        dot3_stats_fcs_errors: 5,
        dot3_stats_single_collision_frames: 10,
        dot3_stats_multiple_collision_frames: 2,
        dot3_stats_sqe_test_errors: 0,
        dot3_stats_deferred_transmissions: 1,
        dot3_stats_late_collisions: 0,
        dot3_stats_excessive_collisions: 0,
        dot3_stats_internal_mac_transmit_errors: 0,
        dot3_stats_carrier_sense_errors: 0,
        dot3_stats_frame_too_longs: 0,
        dot3_stats_internal_mac_receive_errors: 0,
        dot3_stats_symbol_errors: 0,
    };
    assert_eq!(counters.dot3_stats_fcs_errors, 5);
    assert_eq!(counters.dot3_stats_single_collision_frames, 10);
}

#[test]
fn test_processor_counters() {
    let counters = ProcessorCounters {
        cpu_5s: 50,
        cpu_1m: 45,
        cpu_5m: 40,
        total_memory: 16_000_000_000,
        free_memory: 8_000_000_000,
    };
    assert_eq!(counters.cpu_5s, 50);
    assert_eq!(counters.total_memory, 16_000_000_000);
    assert_eq!(counters.free_memory, 8_000_000_000);
}

#[test]
fn test_host_cpu() {
    let cpu = HostCpu {
        load_one: 150,    // 1.50
        load_five: 120,   // 1.20
        load_fifteen: 90, // 0.90
        proc_run: 2,
        proc_total: 150,
        cpu_num: 8,
        cpu_speed: 3000,
        uptime: 86400,
        cpu_user: 10000,
        cpu_nice: 100,
        cpu_system: 5000,
        cpu_idle: 70000,
        cpu_wio: 1000,
        cpu_intr: 50,
        cpu_sintr: 25,
        interrupts: 100000,
        contexts: 500000,
    };
    assert_eq!(cpu.load_one, 150);
    assert_eq!(cpu.cpu_num, 8);
    assert_eq!(cpu.cpu_speed, 3000);
    assert_eq!(cpu.uptime, 86400);
}

#[test]
fn test_host_memory() {
    let memory = HostMemory {
        mem_total: 16_000_000_000,
        mem_free: 8_000_000_000,
        mem_shared: 1_000_000_000,
        mem_buffers: 500_000_000,
        mem_cached: 2_000_000_000,
        swap_total: 4_000_000_000,
        swap_free: 3_000_000_000,
        page_in: 1000,
        page_out: 500,
        swap_in: 10,
        swap_out: 5,
    };
    assert_eq!(memory.mem_total, 16_000_000_000);
    assert_eq!(memory.mem_free, 8_000_000_000);
    assert_eq!(memory.swap_total, 4_000_000_000);
}

#[test]
fn test_host_disk_io() {
    let disk = HostDiskIo {
        disk_total: 1_000_000_000_000,
        disk_free: 500_000_000_000,
        part_max_used: 75,
        reads: 10000,
        bytes_read: 100_000_000,
        read_time: 5000,
        writes: 5000,
        bytes_written: 50_000_000,
        write_time: 3000,
    };
    assert_eq!(disk.disk_total, 1_000_000_000_000);
    assert_eq!(disk.part_max_used, 75);
    assert_eq!(disk.reads, 10000);
}

#[test]
fn test_host_net_io() {
    let net = HostNetIo {
        bytes_in: 10_000_000_000,
        pkts_in: 1_000_000,
        errs_in: 10,
        drops_in: 5,
        bytes_out: 5_000_000_000,
        pkts_out: 500_000,
        errs_out: 2,
        drops_out: 1,
    };
    assert_eq!(net.bytes_in, 10_000_000_000);
    assert_eq!(net.pkts_in, 1_000_000);
    assert_eq!(net.bytes_out, 5_000_000_000);
}

#[test]
fn test_counter_record_structure() {
    let record = CounterRecord {
        counter_format: DataFormat::new(0, 1),
        counter_data: CounterData::Unknown {
            format: DataFormat::new(0, 1),
            data: vec![5, 6, 7, 8],
        },
    };

    assert_eq!(record.counter_format.enterprise(), 0);
    assert_eq!(record.counter_format.format(), 1);

    match &record.counter_data {
        CounterData::Unknown { format, data } => {
            assert_eq!(format.enterprise(), 0);
            assert_eq!(format.format(), 1);
            assert_eq!(data.len(), 4);
        }
        _ => panic!("Expected Unknown counter data"),
    }
}
