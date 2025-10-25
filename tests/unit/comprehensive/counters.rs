//! Counter record parsing tests
//!
//! Tests for parsing all counter record types: interface, host, virtual, and app counters.

use super::helpers::*;
use sflow_parser::parsers::parse_datagram;

#[test]
fn test_parse_ethernet_interface_counters() {
    // Ethernet interface counters: 13 u32 = 52 bytes
    let record_data = [
        0x00, 0x00, 0x00, 0x00, // dot3_stats_alignment_errors = 0
        0x00, 0x00, 0x00, 0x05, // dot3_stats_fcs_errors = 5
        0x00, 0x00, 0x00, 0x0A, // dot3_stats_single_collision_frames = 10
        0x00, 0x00, 0x00, 0x02, // dot3_stats_multiple_collision_frames = 2
        0x00, 0x00, 0x00, 0x00, // dot3_stats_sqe_test_errors = 0
        0x00, 0x00, 0x00, 0x01, // dot3_stats_deferred_transmissions = 1
        0x00, 0x00, 0x00, 0x00, // dot3_stats_late_collisions = 0
        0x00, 0x00, 0x00, 0x00, // dot3_stats_excessive_collisions = 0
        0x00, 0x00, 0x00, 0x00, // dot3_stats_internal_mac_transmit_errors = 0
        0x00, 0x00, 0x00, 0x00, // dot3_stats_carrier_sense_errors = 0
        0x00, 0x00, 0x00, 0x00, // dot3_stats_frame_too_longs = 0
        0x00, 0x00, 0x00, 0x00, // dot3_stats_internal_mac_receive_errors = 0
        0x00, 0x00, 0x00, 0x00, // dot3_stats_symbol_errors = 0
    ];

    let data = build_counter_sample_test(0x0002, &record_data); // record type = 2

    let result = parse_datagram(&data);
    assert!(result.is_ok());

    let datagram = result.unwrap();
    match &datagram.samples[0].sample_data {
        SampleData::CountersSample(counters) => {
            assert_eq!(counters.counters.len(), 1);
            match &counters.counters[0].counter_data {
                CounterData::EthernetInterface(eth) => {
                    assert_eq!(eth.dot3_stats_fcs_errors, 5);
                    assert_eq!(eth.dot3_stats_single_collision_frames, 10);
                    assert_eq!(eth.dot3_stats_multiple_collision_frames, 2);
                }
                _ => panic!("Expected EthernetInterface"),
            }
        }
        _ => panic!("Expected CountersSample"),
    }
}

#[test]
fn test_parse_token_ring_counters() {
    // Token Ring counters: 18 u32 = 72 bytes
    let record_data = [
        0x00, 0x00, 0x00, 0x05, // dot5_stats_line_errors = 5
        0x00, 0x00, 0x00, 0x02, // dot5_stats_burst_errors = 2
        0x00, 0x00, 0x00, 0x01, // dot5_stats_ac_errors = 1
        0x00, 0x00, 0x00, 0x00, // dot5_stats_abort_trans_errors = 0
        0x00, 0x00, 0x00, 0x03, // dot5_stats_internal_errors = 3
        0x00, 0x00, 0x00, 0x01, // dot5_stats_lost_frame_errors = 1
        0x00, 0x00, 0x00, 0x00, // dot5_stats_receive_congestions = 0
        0x00, 0x00, 0x00, 0x00, // dot5_stats_frame_copied_errors = 0
        0x00, 0x00, 0x00, 0x02, // dot5_stats_token_errors = 2
        0x00, 0x00, 0x00, 0x0A, // dot5_stats_soft_errors = 10
        0x00, 0x00, 0x00, 0x01, // dot5_stats_hard_errors = 1
        0x00, 0x00, 0x00, 0x00, // dot5_stats_signal_loss = 0
        0x00, 0x00, 0x00, 0x00, // dot5_stats_transmit_beacons = 0
        0x00, 0x00, 0x00, 0x05, // dot5_stats_recoverys = 5
        0x00, 0x00, 0x00, 0x00, // dot5_stats_lobe_wires = 0
        0x00, 0x00, 0x00, 0x01, // dot5_stats_removes = 1
        0x00, 0x00, 0x00, 0x00, // dot5_stats_singles = 0
        0x00, 0x00, 0x00, 0x02, // dot5_stats_freq_errors = 2
    ];

    let data = build_counter_sample_test(0x0003, &record_data); // record type = 3

    let result = parse_datagram(&data);
    assert!(result.is_ok());

    let datagram = result.unwrap();
    match &datagram.samples[0].sample_data {
        SampleData::CountersSample(counters) => {
            assert_eq!(counters.counters.len(), 1);
            match &counters.counters[0].counter_data {
                CounterData::TokenRing(tr) => {
                    assert_eq!(tr.dot5_stats_line_errors, 5);
                    assert_eq!(tr.dot5_stats_burst_errors, 2);
                    assert_eq!(tr.dot5_stats_soft_errors, 10);
                    assert_eq!(tr.dot5_stats_hard_errors, 1);
                }
                _ => panic!("Expected TokenRing"),
            }
        }
        _ => panic!("Expected CountersSample"),
    }
}

#[test]
fn test_parse_vg100_interface_counters() {
    // 100BaseVG counters: 8 u32 + 6 u64 = 80 bytes
    let record_data = [
        0x00, 0x00, 0x03, 0xE8, // dot12_in_high_priority_frames = 1000
        0x00, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x42,
        0x40, // dot12_in_high_priority_octets = 1000000
        0x00, 0x00, 0x07, 0xD0, // dot12_in_norm_priority_frames = 2000
        0x00, 0x00, 0x00, 0x00, 0x00, 0x1E, 0x84,
        0x80, // dot12_in_norm_priority_octets = 2000000
        0x00, 0x00, 0x00, 0x05, // dot12_in_ipm_errors = 5
        0x00, 0x00, 0x00, 0x02, // dot12_in_oversized_frame_errors = 2
        0x00, 0x00, 0x00, 0x01, // dot12_in_data_errors = 1
        0x00, 0x00, 0x00, 0x00, // dot12_in_null_addressed_frames = 0
        0x00, 0x00, 0x01, 0xF4, // dot12_out_high_priority_frames = 500
        0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0xA1,
        0x20, // dot12_out_high_priority_octets = 500000
        0x00, 0x00, 0x00, 0x0A, // dot12_transition_into_trainings = 10
        0x00, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x42,
        0x40, // dot12_hc_in_high_priority_octets = 1000000
        0x00, 0x00, 0x00, 0x00, 0x00, 0x1E, 0x84,
        0x80, // dot12_hc_in_norm_priority_octets = 2000000
        0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0xA1,
        0x20, // dot12_hc_out_high_priority_octets = 500000
    ];

    let data = build_counter_sample_test(0x0004, &record_data); // record type = 4

    let result = parse_datagram(&data);
    if let Err(e) = &result {
        eprintln!("Parse error: {}", e);
    }
    assert!(result.is_ok());

    let datagram = result.unwrap();
    match &datagram.samples[0].sample_data {
        SampleData::CountersSample(counters) => {
            assert_eq!(counters.counters.len(), 1);
            match &counters.counters[0].counter_data {
                CounterData::Vg100Interface(vg) => {
                    assert_eq!(vg.dot12_in_high_priority_frames, 1000);
                    assert_eq!(vg.dot12_in_high_priority_octets, 1000000);
                    assert_eq!(vg.dot12_in_norm_priority_frames, 2000);
                    assert_eq!(vg.dot12_in_ipm_errors, 5);
                }
                _ => panic!("Expected Vg100Interface"),
            }
        }
        _ => panic!("Expected CountersSample"),
    }
}

#[test]
fn test_parse_vlan_counters() {
    // VLAN counters: 1 u32 + 1 u64 + 4 u32 = 28 bytes
    let record_data = [
        0x00, 0x00, 0x00, 0x64, // vlan_id = 100
        0x00, 0x00, 0x00, 0x00, 0x00, 0x98, 0x96, 0x80, // octets = 10000000
        0x00, 0x00, 0x27, 0x10, // ucast_pkts = 10000
        0x00, 0x00, 0x03, 0xE8, // multicast_pkts = 1000
        0x00, 0x00, 0x00, 0x64, // broadcast_pkts = 100
        0x00, 0x00, 0x00, 0x05, // discards = 5
    ];

    let data = build_counter_sample_test(0x0005, &record_data); // record type = 5

    let result = parse_datagram(&data);
    if let Err(e) = &result {
        eprintln!("Parse error: {}", e);
    }
    assert!(result.is_ok());

    let datagram = result.unwrap();
    match &datagram.samples[0].sample_data {
        SampleData::CountersSample(counters) => {
            assert_eq!(counters.counters.len(), 1);
            match &counters.counters[0].counter_data {
                CounterData::Vlan(vlan) => {
                    assert_eq!(vlan.vlan_id, 100);
                    assert_eq!(vlan.octets, 10000000);
                    assert_eq!(vlan.ucast_pkts, 10000);
                    assert_eq!(vlan.multicast_pkts, 1000);
                    assert_eq!(vlan.broadcast_pkts, 100);
                    assert_eq!(vlan.discards, 5);
                }
                _ => panic!("Expected Vlan"),
            }
        }
        _ => panic!("Expected CountersSample"),
    }
}

#[test]
fn test_parse_ieee80211_counters() {
    // IEEE 802.11 Counters: 20 u32 = 80 bytes
    let record_data = [
        0x00, 0x00, 0x27, 0x10, // dot11_transmitted_fragment_count = 10000
        0x00, 0x00, 0x00, 0x0A, // dot11_multicast_transmitted_frame_count = 10
        0x00, 0x00, 0x00, 0x05, // dot11_failed_count = 5
        0x00, 0x00, 0x00, 0x03, // dot11_retry_count = 3
        0x00, 0x00, 0x00, 0x02, // dot11_multiple_retry_count = 2
        0x00, 0x00, 0x00, 0x01, // dot11_frame_duplicate_count = 1
        0x00, 0x00, 0x00, 0x00, // dot11_rts_success_count = 0
        0x00, 0x00, 0x00, 0x00, // dot11_rts_failure_count = 0
        0x00, 0x00, 0x00, 0x00, // dot11_ack_failure_count = 0
        0x00, 0x00, 0x1F, 0x40, // dot11_received_fragment_count = 8000
        0x00, 0x00, 0x00, 0x14, // dot11_multicast_received_frame_count = 20
        0x00, 0x00, 0x00, 0x00, // dot11_fcs_error_count = 0
        0x00, 0x00, 0x13, 0x88, // dot11_transmitted_frame_count = 5000
        0x00, 0x00, 0x00, 0x00, // dot11_wep_undecryptable_count = 0
        0x00, 0x00, 0x00, 0x00, // dot11_qos_discarded_fragment_count = 0
        0x00, 0x00, 0x00, 0x0F, // dot11_associated_station_count = 15
        0x00, 0x00, 0x00, 0x00, // dot11_qos_cf_polls_received_count = 0
        0x00, 0x00, 0x00, 0x00, // dot11_qos_cf_polls_unused_count = 0
        0x00, 0x00, 0x00, 0x00, // dot11_qos_cf_polls_unusable_count = 0
        0x00, 0x00, 0x00, 0x00, // dot11_qos_cf_polls_lost_count = 0
    ];

    let data = build_counter_sample_test(0x0006, &record_data); // record type = 6

    let result = parse_datagram(&data);
    if let Err(e) = &result {
        eprintln!("Parse error: {}", e);
    }
    assert!(result.is_ok());

    let datagram = result.unwrap();
    match &datagram.samples[0].sample_data {
        SampleData::CountersSample(counters) => {
            assert_eq!(counters.counters.len(), 1);
            match &counters.counters[0].counter_data {
                CounterData::Ieee80211(wifi) => {
                    assert_eq!(wifi.dot11_transmitted_fragment_count, 10000);
                    assert_eq!(wifi.dot11_multicast_transmitted_frame_count, 10);
                    assert_eq!(wifi.dot11_failed_count, 5);
                    assert_eq!(wifi.dot11_retry_count, 3);
                    assert_eq!(wifi.dot11_transmitted_frame_count, 5000);
                }
                _ => panic!("Expected Ieee80211"),
            }
        }
        _ => panic!("Expected CountersSample"),
    }
}

#[test]
fn test_parse_processor_counters() {
    // Processor counters: 3 u32 + 2 u64 = 28 bytes
    let record_data = [
        0x00, 0x00, 0x00, 0x32, // cpu_5s = 50%
        0x00, 0x00, 0x00, 0x2D, // cpu_1m = 45%
        0x00, 0x00, 0x00, 0x28, // cpu_5m = 40%
        0x00, 0x00, 0x00, 0x03, 0xB9, 0xAC, 0xA0, 0x00, // total_memory = 16GB
        0x00, 0x00, 0x00, 0x01, 0xDC, 0xD6, 0x50, 0x00, // free_memory = 8GB
    ];

    let data = build_counter_sample_test(0x03E9, &record_data); // record type = 1001

    let result = parse_datagram(&data);
    if let Err(e) = &result {
        eprintln!("Parse error: {}", e);
    }
    assert!(result.is_ok());

    let datagram = result.unwrap();
    match &datagram.samples[0].sample_data {
        SampleData::CountersSample(counters) => {
            assert_eq!(counters.counters.len(), 1);
            match &counters.counters[0].counter_data {
                CounterData::Processor(proc) => {
                    assert_eq!(proc.cpu_5s, 50);
                    assert_eq!(proc.cpu_1m, 45);
                    assert_eq!(proc.cpu_5m, 40);
                    assert_eq!(proc.total_memory, 16_000_000_000);
                    assert_eq!(proc.free_memory, 8_000_000_000);
                }
                _ => panic!("Expected Processor"),
            }
        }
        _ => panic!("Expected CountersSample"),
    }
}

#[test]
fn test_parse_radio_utilization() {
    // Radio Utilization: elapsed_time(4) + on_channel_time(4) + on_channel_busy_time(4) = 12 bytes
    let record_data = [
        0x00, 0x00, 0x03, 0xE8, // elapsed_time = 1000 ms
        0x00, 0x00, 0x02, 0xBC, // on_channel_time = 700 ms
        0x00, 0x00, 0x01, 0xF4, // on_channel_busy_time = 500 ms
    ];

    let data = build_counter_sample_test(0x03EA, &record_data); // record type = 1002

    let result = parse_datagram(&data);
    assert!(result.is_ok());

    let datagram = result.unwrap();
    match &datagram.samples[0].sample_data {
        SampleData::CountersSample(counters) => {
            assert_eq!(counters.counters.len(), 1);
            match &counters.counters[0].counter_data {
                CounterData::RadioUtilization(radio) => {
                    assert_eq!(radio.elapsed_time, 1000);
                    assert_eq!(radio.on_channel_time, 700);
                    assert_eq!(radio.on_channel_busy_time, 500);
                }
                _ => panic!("Expected RadioUtilization"),
            }
        }
        _ => panic!("Expected CountersSample"),
    }
}

#[test]
fn test_parse_openflow_port() {
    // OpenFlow Port: datapath_id(8) + port_no(4) = 12 bytes
    let record_data = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // datapath_id = 1
        0x00, 0x00, 0x00, 0x05, // port_no = 5
    ];

    let data = build_counter_sample_test(0x03EC, &record_data); // record type = 1004

    let result = parse_datagram(&data);
    assert!(result.is_ok());

    let datagram = result.unwrap();
    match &datagram.samples[0].sample_data {
        SampleData::CountersSample(counters) => {
            assert_eq!(counters.counters.len(), 1);
            match &counters.counters[0].counter_data {
                CounterData::OpenFlowPort(port) => {
                    assert_eq!(port.datapath_id, 1);
                    assert_eq!(port.port_no, 5);
                }
                _ => panic!("Expected OpenFlowPort"),
            }
        }
        _ => panic!("Expected CountersSample"),
    }
}

#[test]
fn test_parse_host_description() {
    // Host Description: hostname + uuid(16) + machine_type + os_name + os_release
    let record_data = [
        0x00, 0x00, 0x00, 0x09, // hostname length = 9
        b's', b'e', b'r', b'v', b'e', b'r', b'-', b'0', b'1', 0x00, 0x00,
        0x00, // "server-01" + padding
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, // uuid (16 bytes)
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x00, 0x00, 0x00,
        0x06, // machine_type length = 6
        b'x', b'8', b'6', b'_', b'6', b'4', 0x00, 0x00, // "x86_64" + padding
        0x00, 0x00, 0x00, 0x05, // os_name length = 5
        b'L', b'i', b'n', b'u', b'x', 0x00, 0x00, 0x00, // "Linux" + padding
        0x00, 0x00, 0x00, 0x06, // os_release length = 6
        b'6', b'.', b'5', b'.', b'1', b'0', 0x00, 0x00, // "6.5.10" + padding
    ];

    let data = build_counter_sample_test(0x07D0, &record_data); // record type = 2000

    let result = parse_datagram(&data);
    if let Err(e) = &result {
        eprintln!("Parse error: {}", e);
    }
    assert!(result.is_ok());

    let datagram = result.unwrap();
    match &datagram.samples[0].sample_data {
        SampleData::CountersSample(counters) => {
            assert_eq!(counters.counters.len(), 1);
            match &counters.counters[0].counter_data {
                CounterData::HostDescription(host) => {
                    assert_eq!(host.hostname, "server-01");
                    assert_eq!(host.machine_type, "x86_64");
                    assert_eq!(host.os_name, "Linux");
                    assert_eq!(host.os_release, "6.5.10");
                }
                _ => panic!("Expected HostDescription"),
            }
        }
        _ => panic!("Expected CountersSample"),
    }
}

#[test]
fn test_parse_openflow_port_name() {
    // OpenFlow Port Name: port_name_len(4) + "eth0"(4) = 8 bytes
    let record_data = [
        0x00, 0x00, 0x00, 0x04, // port_name length = 4
        b'e', b't', b'h', b'0', // "eth0"
    ];

    let data = build_counter_sample_test(0x03ED, &record_data); // record type = 1005

    let result = parse_datagram(&data);
    assert!(result.is_ok());

    let datagram = result.unwrap();
    match &datagram.samples[0].sample_data {
        SampleData::CountersSample(counters) => {
            assert_eq!(counters.counters.len(), 1);
            match &counters.counters[0].counter_data {
                CounterData::OpenFlowPortName(port_name) => {
                    assert_eq!(port_name.port_name, "eth0");
                }
                _ => panic!("Expected OpenFlowPortName"),
            }
        }
        _ => panic!("Expected CountersSample"),
    }
}

#[test]
fn test_parse_host_adapters() {
    // Host Adapters: num_adapters(4) + 2 adapters * (if_index(4) + num_macs(4) + mac(6)) = 32 bytes
    let record_data = [
        0x00, 0x00, 0x00, 0x02, // num_adapters = 2
        // Adapter 1
        0x00, 0x00, 0x00, 0x01, // if_index = 1
        0x00, 0x00, 0x00, 0x01, // num_macs = 1
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // MAC address
        // Adapter 2
        0x00, 0x00, 0x00, 0x02, // if_index = 2
        0x00, 0x00, 0x00, 0x01, // num_macs = 1
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, // MAC address
    ];

    let data = build_counter_sample_test(0x07D1, &record_data); // record type = 2001

    let result = parse_datagram(&data);
    assert!(result.is_ok());

    let datagram = result.unwrap();
    match &datagram.samples[0].sample_data {
        SampleData::CountersSample(counters) => {
            assert_eq!(counters.counters.len(), 1);
            match &counters.counters[0].counter_data {
                CounterData::HostAdapters(adapters) => {
                    assert_eq!(adapters.adapters.len(), 2);
                    assert_eq!(adapters.adapters[0].if_index, 1);
                    assert_eq!(adapters.adapters[0].mac_addresses.len(), 1);
                    assert_eq!(
                        adapters.adapters[0].mac_addresses[0],
                        MacAddress::from([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
                    );
                    assert_eq!(adapters.adapters[1].if_index, 2);
                    assert_eq!(
                        adapters.adapters[1].mac_addresses[0],
                        MacAddress::from([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
                    );
                }
                _ => panic!("Expected HostAdapters"),
            }
        }
        _ => panic!("Expected CountersSample"),
    }
}

#[test]
fn test_parse_host_parent() {
    // Host Parent: container_type(4) + container_index(4) = 8 bytes
    let record_data = [
        0x00, 0x00, 0x00, 0x01, // container_type = 1 (docker)
        0x00, 0x00, 0x00, 0x0A, // container_index = 10
    ];

    let data = build_counter_sample_test(0x07D2, &record_data); // record type = 2002

    let result = parse_datagram(&data);
    assert!(result.is_ok());

    let datagram = result.unwrap();
    match &datagram.samples[0].sample_data {
        SampleData::CountersSample(counters) => {
            assert_eq!(counters.counters.len(), 1);
            match &counters.counters[0].counter_data {
                CounterData::HostParent(parent) => {
                    assert_eq!(parent.container_type, 1);
                    assert_eq!(parent.container_index, 10);
                }
                _ => panic!("Expected HostParent"),
            }
        }
        _ => panic!("Expected CountersSample"),
    }
}

#[test]
fn test_parse_host_cpu_counters() {
    // Host CPU counters: 8 u32 + 7 u64 = 68 bytes
    let record_data = [
        0x00, 0x00, 0x00, 0x96, // load_one = 150 (1.50)
        0x00, 0x00, 0x00, 0x78, // load_five = 120 (1.20)
        0x00, 0x00, 0x00, 0x5A, // load_fifteen = 90 (0.90)
        0x00, 0x00, 0x00, 0x02, // proc_run = 2
        0x00, 0x00, 0x00, 0x96, // proc_total = 150
        0x00, 0x00, 0x00, 0x08, // cpu_num = 8
        0x00, 0x00, 0x0B, 0xB8, // cpu_speed = 3000 MHz
        0x00, 0x01, 0x51, 0x80, // uptime = 86400 seconds
        0x00, 0x00, 0x27, 0x10, // cpu_user = 10000
        0x00, 0x00, 0x00, 0x64, // cpu_nice = 100
        0x00, 0x00, 0x13, 0x88, // cpu_system = 5000
        0x00, 0x01, 0x11, 0x70, // cpu_idle = 70000
        0x00, 0x00, 0x03, 0xE8, // cpu_wio = 1000
        0x00, 0x00, 0x00, 0x32, // cpu_intr = 50
        0x00, 0x00, 0x00, 0x19, // cpu_sintr = 25
        0x00, 0x01, 0x86, 0xA0, // interrupts = 100000
        0x00, 0x07, 0xA1, 0x20, // contexts = 500000
    ];

    let data = build_counter_sample_test(0x07D3, &record_data); // record type = 2003

    let result = parse_datagram(&data);
    assert!(result.is_ok());

    let datagram = result.unwrap();
    match &datagram.samples[0].sample_data {
        SampleData::CountersSample(counters) => {
            assert_eq!(counters.counters.len(), 1);
            match &counters.counters[0].counter_data {
                CounterData::HostCpu(cpu) => {
                    assert_eq!(cpu.load_one, 150);
                    assert_eq!(cpu.cpu_num, 8);
                    assert_eq!(cpu.cpu_speed, 3000);
                    assert_eq!(cpu.uptime, 86400);
                }
                _ => panic!("Expected HostCpu"),
            }
        }
        _ => panic!("Expected CountersSample"),
    }
}

#[test]
fn test_parse_host_memory_counters() {
    // Host Memory counters: 4 u64 + 1 u32 = 36 bytes
    let record_data = [
        0x00, 0x00, 0x00, 0x03, 0xB9, 0xAC, 0xA0, 0x00, // mem_total = 16GB
        0x00, 0x00, 0x00, 0x01, 0xDC, 0xD6, 0x50, 0x00, // mem_free = 8GB
        0x00, 0x00, 0x00, 0x00, 0x3B, 0x9A, 0xCA, 0x00, // mem_shared = 1GB
        0x00, 0x00, 0x00, 0x00, 0x1D, 0xCD, 0x65, 0x00, // mem_buffers = 500MB
        0x00, 0x00, 0x00, 0x00, 0x77, 0x35, 0x94, 0x00, // mem_cached = 2GB
        0x00, 0x00, 0x00, 0x00, 0xEE, 0x6B, 0x28, 0x00, // swap_total = 4GB
        0x00, 0x00, 0x00, 0x00, 0xB2, 0xD0, 0x5E, 0x00, // swap_free = 3GB
        0x00, 0x00, 0x03, 0xE8, // page_in = 1000
        0x00, 0x00, 0x01, 0xF4, // page_out = 500
        0x00, 0x00, 0x00, 0x0A, // swap_in = 10
        0x00, 0x00, 0x00, 0x00, // page_out = 0
    ];

    let data = build_counter_sample_test(0x07D4, &record_data); // record type = 2004

    let result = parse_datagram(&data);
    if let Err(e) = &result {
        eprintln!("Parse error: {}", e);
    }
    assert!(result.is_ok());

    let datagram = result.unwrap();
    match &datagram.samples[0].sample_data {
        SampleData::CountersSample(counters) => {
            assert_eq!(counters.counters.len(), 1);
            match &counters.counters[0].counter_data {
                CounterData::HostMemory(mem) => {
                    assert_eq!(mem.mem_total, 16_000_000_000);
                    assert_eq!(mem.mem_free, 8_000_000_000);
                    assert_eq!(mem.swap_total, 4_000_000_000);
                }
                _ => panic!("Expected HostMemory"),
            }
        }
        _ => panic!("Expected CountersSample"),
    }
}

#[test]
fn test_parse_host_disk_io_counters() {
    // Host Disk I/O counters: 2 u64 + 1 u32 + 1 u32 + 1 u64 + 1 u32 + 1 u32 + 1 u64 + 1 u32 = 52 bytes
    let record_data = [
        0x00, 0x00, 0x00, 0xE8, 0xD4, 0xA5, 0x10, 0x00, // disk_total = 1TB
        0x00, 0x00, 0x00, 0x74, 0x6A, 0x52, 0x88, 0x00, // disk_free = 500GB
        0x00, 0x00, 0x00, 0x4B, // part_max_used = 75%
        0x00, 0x00, 0x27, 0x10, // reads = 10000
        0x00, 0x00, 0x00, 0x05, 0xF5, 0xE1, 0x00, 0x00, // bytes_read = 100MB
        0x00, 0x00, 0x13, 0x88, // read_time = 5000ms
        0x00, 0x00, 0x13, 0x88, // writes = 5000
        0x00, 0x00, 0x00, 0x02, 0xFA, 0xF0, 0x80, 0x00, // bytes_written = 50MB
        0x00, 0x00, 0x0B, 0xB8, // write_time = 3000ms
    ];

    let data = build_counter_sample_test(0x07D5, &record_data); // record type = 2005

    let result = parse_datagram(&data);
    if let Err(e) = &result {
        eprintln!("Parse error: {}", e);
    }
    assert!(result.is_ok());

    let datagram = result.unwrap();
    match &datagram.samples[0].sample_data {
        SampleData::CountersSample(counters) => {
            assert_eq!(counters.counters.len(), 1);
            match &counters.counters[0].counter_data {
                CounterData::HostDiskIo(disk) => {
                    assert_eq!(disk.disk_total, 1_000_000_000_000);
                    assert_eq!(disk.disk_free, 500_000_000_000);
                    assert_eq!(disk.part_max_used, 75);
                    assert_eq!(disk.reads, 10000);
                }
                _ => panic!("Expected HostDiskIo"),
            }
        }
        _ => panic!("Expected CountersSample"),
    }
}

#[test]
fn test_parse_host_net_io_counters() {
    // Host Network I/O counters: 2 u64 + 2 u32 + 2 u64 + 2 u32 = 36 bytes
    let record_data = [
        0x00, 0x00, 0x00, 0x02, 0x54, 0x0B, 0xE4, 0x00, // bytes_in = 10GB
        0x00, 0x0F, 0x42, 0x40, // pkts_in = 1000000
        0x00, 0x00, 0x00, 0x0A, // errs_in = 10
        0x00, 0x00, 0x00, 0x05, // drops_in = 5
        0x00, 0x00, 0x00, 0x01, 0x2A, 0x05, 0xF2, 0x00, // bytes_out = 5GB
        0x00, 0x07, 0xA1, 0x20, // packets_out = 500000
        0x00, 0x00, 0x00, 0x02, // errs_out = 2
        0x00, 0x00, 0x00, 0x01, // drops_out = 1
    ];

    let data = build_counter_sample_test(0x07D6, &record_data); // record type = 2006

    let result = parse_datagram(&data);
    assert!(result.is_ok());

    let datagram = result.unwrap();
    match &datagram.samples[0].sample_data {
        SampleData::CountersSample(counters) => {
            assert_eq!(counters.counters.len(), 1);
            match &counters.counters[0].counter_data {
                CounterData::HostNetIo(net) => {
                    assert_eq!(net.bytes_in, 10_000_000_000);
                    assert_eq!(net.pkts_in, 1_000_000);
                    assert_eq!(net.bytes_out, 5_000_000_000);
                    assert_eq!(net.packets_out, 500_000);
                }
                _ => panic!("Expected HostNetIo"),
            }
        }
        _ => panic!("Expected CountersSample"),
    }
}

#[test]
fn test_parse_virtual_node() {
    // Virtual Node: mhz(4) + cpus(4) + memory(8) + memory_free(8) + num_domains(4) = 28 bytes
    let record_data = [
        0x00, 0x00, 0x09, 0x60, // mhz = 2400
        0x00, 0x00, 0x00, 0x04, // cpus = 4
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, // memory = 4 GB
        0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, // memory_free = 2 GB
        0x00, 0x00, 0x00, 0x02, // num_domains = 2
    ];

    let data = build_counter_sample_test(0x0834, &record_data); // record type = 2100

    let result = parse_datagram(&data);
    assert!(result.is_ok());

    let datagram = result.unwrap();
    match &datagram.samples[0].sample_data {
        SampleData::CountersSample(counters) => {
            assert_eq!(counters.counters.len(), 1);
            match &counters.counters[0].counter_data {
                CounterData::VirtualNode(node) => {
                    // Fields: mhz, cpus, memory, memory_free, num_domains
                    assert_eq!(node.mhz, 2400);
                    assert_eq!(node.cpus, 4);
                    assert_eq!(node.memory, 4_294_967_296);
                    assert_eq!(node.memory_free, 2_147_483_648);
                    assert_eq!(node.num_domains, 2);
                }
                _ => panic!("Expected VirtualNode"),
            }
        }
        _ => panic!("Expected CountersSample"),
    }
}

#[test]
fn test_parse_virtual_cpu() {
    // Virtual CPU: state(4) + cpu_time(4) + nr_virt_cpu(4) = 12 bytes
    let record_data = [
        0x00, 0x00, 0x00, 0x00, // state = 0 (running)
        0x00, 0x00, 0x13, 0x88, // cpu_time = 5000 ms
        0x00, 0x00, 0x00, 0x02, // nr_virt_cpu = 2
    ];

    let data = build_counter_sample_test(0x0835, &record_data); // record type = 2101

    let result = parse_datagram(&data);
    assert!(result.is_ok());

    let datagram = result.unwrap();
    match &datagram.samples[0].sample_data {
        SampleData::CountersSample(counters) => {
            assert_eq!(counters.counters.len(), 1);
            match &counters.counters[0].counter_data {
                CounterData::VirtualCpu(cpu) => {
                    assert_eq!(cpu.state, 0);
                    assert_eq!(cpu.cpu_time, 5000);
                    assert_eq!(cpu.nr_virt_cpu, 2);
                }
                _ => panic!("Expected VirtualCpu"),
            }
        }
        _ => panic!("Expected CountersSample"),
    }
}

#[test]
fn test_parse_virtual_memory() {
    // Virtual Memory: memory(8) + max_memory(8) = 16 bytes
    let record_data = [
        0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, // memory = 1 GB
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, // max_memory = 4 GB
    ];

    let data = build_counter_sample_test(0x0836, &record_data); // record type = 2102

    let result = parse_datagram(&data);
    assert!(result.is_ok());

    let datagram = result.unwrap();
    match &datagram.samples[0].sample_data {
        SampleData::CountersSample(counters) => {
            assert_eq!(counters.counters.len(), 1);
            match &counters.counters[0].counter_data {
                CounterData::VirtualMemory(mem) => {
                    assert_eq!(mem.memory, 1_073_741_824);
                    assert_eq!(mem.max_memory, 4_294_967_296);
                }
                _ => panic!("Expected VirtualMemory"),
            }
        }
        _ => panic!("Expected CountersSample"),
    }
}

#[test]
fn test_parse_virtual_disk_io() {
    // Virtual Disk I/O: capacity(8) + allocation(8) + available(8) + rd_req(4) + rd_bytes(8) + wr_req(4) + wr_bytes(8) + errs(4) = 52 bytes
    let record_data = [
        0x00, 0x00, 0x00, 0x02, 0x54, 0x0B, 0xE4, 0x00, // capacity = 10 GB
        0x00, 0x00, 0x00, 0x01, 0x2A, 0x05, 0xF2, 0x00, // allocation = 5 GB
        0x00, 0x00, 0x00, 0x01, 0x2A, 0x05, 0xF2, 0x00, // available = 5 GB
        0x00, 0x00, 0x03, 0xE8, // rd_req = 1000
        0x00, 0x00, 0x00, 0x00, 0x00, 0x98, 0x96, 0x80, // rd_bytes = 10 MB
        0x00, 0x00, 0x07, 0xD0, // wr_req = 2000
        0x00, 0x00, 0x00, 0x00, 0x01, 0x31, 0x2D, 0x00, // wr_bytes = 20 MB
        0x00, 0x00, 0x00, 0x05, // errs = 5
    ];

    let data = build_counter_sample_test(0x0837, &record_data); // record type = 2103

    let result = parse_datagram(&data);
    assert!(result.is_ok());

    let datagram = result.unwrap();
    match &datagram.samples[0].sample_data {
        SampleData::CountersSample(counters) => {
            assert_eq!(counters.counters.len(), 1);
            match &counters.counters[0].counter_data {
                CounterData::VirtualDiskIo(disk) => {
                    assert_eq!(disk.capacity, 10_000_000_000);
                    assert_eq!(disk.allocation, 5_000_000_000);
                    assert_eq!(disk.available, 5_000_000_000);
                    assert_eq!(disk.rd_req, 1000);
                    assert_eq!(disk.rd_bytes, 10_000_000);
                    assert_eq!(disk.wr_req, 2000);
                    assert_eq!(disk.wr_bytes, 20_000_000);
                    assert_eq!(disk.errs, 5);
                }
                _ => panic!("Expected VirtualDiskIo"),
            }
        }
        _ => panic!("Expected CountersSample"),
    }
}

#[test]
fn test_parse_virtual_net_io() {
    // Virtual Network I/O: rx_bytes(8) + rx_packets(4) + rx_errs(4) + rx_drop(4) + tx_bytes(8) + tx_packets(4) + tx_errs(4) + tx_drop(4) = 44 bytes
    let record_data = [
        0x00, 0x00, 0x00, 0x00, 0x3B, 0x9A, 0xCA, 0x00, // rx_bytes = 1 GB
        0x00, 0x00, 0x27, 0x10, // rx_packets = 10000
        0x00, 0x00, 0x00, 0x02, // rx_errs = 2
        0x00, 0x00, 0x00, 0x01, // rx_drop = 1
        0x00, 0x00, 0x00, 0x00, 0x77, 0x35, 0x94, 0x00, // tx_bytes = 2 GB
        0x00, 0x00, 0x4E, 0x20, // tx_pkts = 20000
        0x00, 0x00, 0x00, 0x03, // tx_errs = 3
        0x00, 0x00, 0x00, 0x02, // tx_drop = 2
    ];

    let data = build_counter_sample_test(0x0838, &record_data); // record type = 2104

    let result = parse_datagram(&data);
    assert!(result.is_ok());

    let datagram = result.unwrap();
    match &datagram.samples[0].sample_data {
        SampleData::CountersSample(counters) => {
            assert_eq!(counters.counters.len(), 1);
            match &counters.counters[0].counter_data {
                CounterData::VirtualNetIo(net) => {
                    assert_eq!(net.rx_bytes, 1_000_000_000);
                    assert_eq!(net.rx_packets, 10000);
                    assert_eq!(net.rx_errs, 2);
                    assert_eq!(net.rx_drop, 1);
                    assert_eq!(net.tx_bytes, 2_000_000_000);
                    assert_eq!(net.tx_packets, 20000);
                    assert_eq!(net.tx_errs, 3);
                    assert_eq!(net.tx_drop, 2);
                }
                _ => panic!("Expected VirtualNetIo"),
            }
        }
        _ => panic!("Expected CountersSample"),
    }
}

#[test]
fn test_parse_app_resources() {
    // App Resources: user_time(4) + system_time(4) + mem_used(8) + mem_max(8) + fd_open(4) + fd_max(4) + conn_open(4) + conn_max(4) = 40 bytes
    let record_data = [
        0x00, 0x00, 0x13, 0x88, // user_time = 5000 ms
        0x00, 0x00, 0x07, 0xD0, // system_time = 2000 ms
        0x00, 0x00, 0x00, 0x00, 0x06, 0x40, 0x00, 0x00, // mem_used = 100 MB
        0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, // mem_max = 1 GB
        0x00, 0x00, 0x00, 0x32, // fd_open = 50
        0x00, 0x00, 0x04, 0x00, // fd_max = 1024
        0x00, 0x00, 0x00, 0x0A, // conn_open = 10
        0x00, 0x00, 0x00, 0x64, // conn_max = 100
    ];

    let data = build_counter_sample_test(0x089B, &record_data); // record type = 2203

    let result = parse_datagram(&data);
    assert!(result.is_ok());

    let datagram = result.unwrap();
    match &datagram.samples[0].sample_data {
        SampleData::CountersSample(counters) => {
            assert_eq!(counters.counters.len(), 1);
            match &counters.counters[0].counter_data {
                CounterData::AppResources(app) => {
                    assert_eq!(app.user_time, 5000);
                    assert_eq!(app.system_time, 2000);
                    assert_eq!(app.mem_used, 104_857_600);
                    assert_eq!(app.mem_max, 1_073_741_824);
                    assert_eq!(app.fd_open, 50);
                    assert_eq!(app.fd_max, 1024);
                    assert_eq!(app.conn_open, 10);
                    assert_eq!(app.conn_max, 100);
                }
                other => panic!("Expected AppResources, got: {:?}", other),
            }
        }
        _ => panic!("Expected CountersSample"),
    }
}

#[test]
fn test_parse_app_operations() {
    // App Operations: application + success + other + timeout + internal_error + bad_request + forbidden + too_large + not_implemented + not_found + unavailable + unauthorized
    let record_data = [
        0x00, 0x00, 0x00, 0x05, // application length = 5
        b'n', b'g', b'i', b'n', b'x', 0x00, 0x00, 0x00, // "nginx" + padding
        0x00, 0x00, 0x27, 0x10, // success = 10000
        0x00, 0x00, 0x00, 0x05, // other = 5
        0x00, 0x00, 0x00, 0x02, // timeout = 2
        0x00, 0x00, 0x00, 0x01, // internal_error = 1
        0x00, 0x00, 0x00, 0x03, // bad_request = 3
        0x00, 0x00, 0x00, 0x00, // forbidden = 0
        0x00, 0x00, 0x00, 0x00, // too_large = 0
        0x00, 0x00, 0x00, 0x00, // not_implemented = 0
        0x00, 0x00, 0x00, 0x04, // not_found = 4
        0x00, 0x00, 0x00, 0x01, // unavailable = 1
        0x00, 0x00, 0x00, 0x00, // unauthorized = 0
    ];

    let data = build_counter_sample_test(0x089A, &record_data); // record type = 2202

    let result = parse_datagram(&data);
    assert!(result.is_ok());

    let datagram = result.unwrap();
    match &datagram.samples[0].sample_data {
        SampleData::CountersSample(counters) => {
            assert_eq!(counters.counters.len(), 1);
            match &counters.counters[0].counter_data {
                CounterData::AppOperations(app) => {
                    assert_eq!(app.application, "nginx");
                    assert_eq!(app.success, 10000);
                    assert_eq!(app.other, 5);
                    assert_eq!(app.timeout, 2);
                    assert_eq!(app.internal_error, 1);
                    assert_eq!(app.bad_request, 3);
                    assert_eq!(app.not_found, 4);
                    assert_eq!(app.unavailable, 1);
                }
                _ => panic!("Expected AppOperations"),
            }
        }
        _ => panic!("Expected CountersSample"),
    }
}

#[test]
fn test_parse_http_counters() {
    // HTTP Counters: 15 u32 fields = 60 bytes
    let record_data = [
        0x00, 0x00, 0x00, 0x0A, // method_option_count = 10
        0x00, 0x00, 0x03, 0xE8, // method_get_count = 1000
        0x00, 0x00, 0x00, 0x32, // method_head_count = 50
        0x00, 0x00, 0x01, 0xF4, // method_post_count = 500
        0x00, 0x00, 0x00, 0x14, // method_put_count = 20
        0x00, 0x00, 0x00, 0x05, // method_delete_count = 5
        0x00, 0x00, 0x00, 0x02, // method_trace_count = 2
        0x00, 0x00, 0x00, 0x01, // method_connect_count = 1
        0x00, 0x00, 0x00, 0x03, // method_other_count = 3
        0x00, 0x00, 0x00, 0x0F, // status_1xx_count = 15
        0x00, 0x00, 0x04, 0xB0, // status_2xx_count = 1200
        0x00, 0x00, 0x00, 0xC8, // status_3xx_count = 200
        0x00, 0x00, 0x00, 0x64, // status_4xx_count = 100
        0x00, 0x00, 0x00, 0x0A, // status_5xx_count = 10
        0x00, 0x00, 0x00, 0x02, // status_other_count = 2
    ];

    let data = build_counter_sample_test(0x0899, &record_data); // record type = 2201

    let result = parse_datagram(&data);
    assert!(result.is_ok());

    let datagram = result.unwrap();
    match &datagram.samples[0].sample_data {
        SampleData::CountersSample(counters) => {
            assert_eq!(counters.counters.len(), 1);
            match &counters.counters[0].counter_data {
                CounterData::HttpCounters(http) => {
                    assert_eq!(http.method_option_count, 10);
                    assert_eq!(http.method_get_count, 1000);
                    assert_eq!(http.method_head_count, 50);
                    assert_eq!(http.method_post_count, 500);
                    assert_eq!(http.method_put_count, 20);
                    assert_eq!(http.method_delete_count, 5);
                    assert_eq!(http.method_trace_count, 2);
                    assert_eq!(http.method_connect_count, 1);
                    assert_eq!(http.method_other_count, 3);
                    assert_eq!(http.status_1xx_count, 15);
                    assert_eq!(http.status_2xx_count, 1200);
                    assert_eq!(http.status_3xx_count, 200);
                    assert_eq!(http.status_4xx_count, 100);
                    assert_eq!(http.status_5xx_count, 10);
                    assert_eq!(http.status_other_count, 2);
                }
                _ => panic!("Expected HttpCounters"),
            }
        }
        _ => panic!("Expected CountersSample"),
    }
}

#[test]
fn test_parse_app_workers() {
    // App Workers: workers_active(4) + workers_idle(4) + workers_max(4) + req_delayed(4) + req_dropped(4)
    let record_data = [
        0x00, 0x00, 0x00, 0x08, // workers_active = 8
        0x00, 0x00, 0x00, 0x04, // workers_idle = 4
        0x00, 0x00, 0x00, 0x10, // workers_max = 16
        0x00, 0x00, 0x00, 0x05, // req_delayed = 5
        0x00, 0x00, 0x00, 0x02, // req_dropped = 2
    ];

    let data = build_counter_sample_test(0x089E, &record_data); // record type = 2206

    let result = parse_datagram(&data);
    assert!(result.is_ok());

    let datagram = result.unwrap();
    match &datagram.samples[0].sample_data {
        SampleData::CountersSample(counters) => {
            assert_eq!(counters.counters.len(), 1);
            match &counters.counters[0].counter_data {
                CounterData::AppWorkers(workers) => {
                    assert_eq!(workers.workers_active, 8);
                    assert_eq!(workers.workers_idle, 4);
                    assert_eq!(workers.workers_max, 16);
                    assert_eq!(workers.req_delayed, 5);
                    assert_eq!(workers.req_dropped, 2);
                }
                _ => panic!("Expected AppWorkers"),
            }
        }
        _ => panic!("Expected CountersSample"),
    }
}
