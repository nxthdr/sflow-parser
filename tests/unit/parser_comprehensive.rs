//! Comprehensive parser tests with binary data
//!
//! These tests exercise the actual parsing logic with crafted binary data
//! following the sFlow v5 specification exactly.
//!
//! Reference: https://sflow.org/sflow_version_5.txt

use sflow_parser::models::core::*;
use sflow_parser::parser::parse_datagram;

/// Encode a u32 as big-endian bytes
fn u32_bytes(value: u32) -> [u8; 4] {
    [
        (value >> 24) as u8,
        (value >> 16) as u8,
        (value >> 8) as u8,
        value as u8,
    ]
}

/// Calculate the total sample length for a flow sample
/// Sample length = flow_sample_header + sum(flow_record_header + flow_record_data)
/// Flow sample header = 32 bytes (8 fields × 4 bytes)
/// Flow record header = 8 bytes (type + length)
/// Flow record data = varies (must be 4-byte aligned)
fn calculate_flow_sample_length(flow_records_data: &[usize]) -> u32 {
    const FLOW_SAMPLE_HEADER: usize = 32; // 8 fields × 4 bytes
    const RECORD_HEADER: usize = 8; // type(4) + length(4)

    let records_total: usize = flow_records_data
        .iter()
        .map(|&data_len| RECORD_HEADER + data_len)
        .sum();

    (FLOW_SAMPLE_HEADER + records_total) as u32
}

/// Build a flow sample test with a single flow record
/// This reduces code duplication across tests
fn build_flow_sample_test(record_type: u32, record_data: &[u8]) -> Vec<u8> {
    let mut data = create_datagram_header(1);

    let record_length = record_data.len();
    let sample_length = calculate_flow_sample_length(&[record_length]);

    // Flow sample header
    data.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // sample type = flow sample
    data.extend_from_slice(&u32_bytes(sample_length));
    data.extend_from_slice(&[
        0x00, 0x00, 0x00, 0x01, // sequence number
        0x00, 0x00, 0x00, 0x01, // source ID
        0x00, 0x00, 0x04, 0x00, // sampling rate = 1024
        0x00, 0x00, 0x00, 0x64, // sample pool = 100
        0x00, 0x00, 0x00, 0x00, // drops = 0
        0x00, 0x00, 0x00, 0x01, // input interface = 1
        0x00, 0x00, 0x00, 0x02, // output interface = 2
        0x00, 0x00, 0x00, 0x01, // number of flow records = 1
    ]);

    // Flow record
    data.extend_from_slice(&u32_bytes(record_type));
    data.extend_from_slice(&u32_bytes(record_length as u32));
    data.extend_from_slice(record_data);

    data
}

/// Build a counter sample test with a single counter record
/// This reduces code duplication across counter tests
fn build_counter_sample_test(record_type: u32, record_data: &[u8]) -> Vec<u8> {
    let mut data = create_datagram_header(1);

    let record_length = record_data.len();
    // Counter sample length = 12 bytes (header) + 8 bytes (record header) + record data
    let sample_length = 12 + 8 + record_length;

    // Counter sample header
    data.extend_from_slice(&[0x00, 0x00, 0x00, 0x02]); // sample type = counter sample
    data.extend_from_slice(&u32_bytes(sample_length as u32));
    data.extend_from_slice(&[
        0x00, 0x00, 0x00, 0x01, // sequence number
        0x00, 0x00, 0x00, 0x01, // source ID
        0x00, 0x00, 0x00, 0x01, // number of counter records = 1
    ]);

    // Counter record
    data.extend_from_slice(&u32_bytes(record_type));
    data.extend_from_slice(&u32_bytes(record_length as u32));
    data.extend_from_slice(record_data);

    data
}

/// Helper to create a datagram header
/// Format: version(4) + agent_addr_type(4) + agent_addr(4 for IPv4) +
///         sub_agent_id(4) + sequence(4) + uptime(4) + num_samples(4)
fn create_datagram_header(num_samples: u32) -> Vec<u8> {
    let mut header = vec![
        0x00, 0x00, 0x00, 0x05, // version = 5
        0x00, 0x00, 0x00, 0x01, // agent address type = IPv4
        0xC0, 0xA8, 0x01, 0x01, // agent address = 192.168.1.1
        0x00, 0x00, 0x00, 0x00, // sub agent ID = 0
        0x00, 0x00, 0x00, 0x01, // sequence number = 1
        0x00, 0x00, 0x00, 0x64, // uptime = 100ms
    ];
    header.extend_from_slice(&u32_bytes(num_samples));
    header
}

#[test]
fn test_parse_flow_sample_with_sampled_header() {
    // Sampled header: protocol(4) + frame_length(4) + stripped(4) + header_len(4) + header(14) + padding(2) = 32 bytes
    let record_data = [
        0x00, 0x00, 0x00, 0x01, // protocol = Ethernet
        0x00, 0x00, 0x05, 0xDC, // frame length = 1500
        0x00, 0x00, 0x00, 0x00, // stripped bytes = 0
        0x00, 0x00, 0x00, 0x0E, // header length = 14 bytes
        // Ethernet header (14 bytes + 2 padding)
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // dst MAC
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // src MAC
        0x08, 0x00, // EtherType = IPv4
        0x00, 0x00, // padding
    ];

    let data = build_flow_sample_test(0x0001, &record_data); // record type = 1

    let result = parse_datagram(&data);
    if let Err(e) = &result {
        panic!("Parse failed: {}", e);
    }
    assert!(result.is_ok());

    let datagram = result.unwrap();
    assert_eq!(datagram.samples.len(), 1);

    match &datagram.samples[0].sample_data {
        SampleData::FlowSample(flow) => {
            assert_eq!(flow.sampling_rate, 1024);
            assert_eq!(flow.flow_records.len(), 1);

            match &flow.flow_records[0].flow_data {
                FlowData::SampledHeader(header) => {
                    assert_eq!(header.frame_length, 1500);
                    assert_eq!(header.header.len(), 14);
                }
                _ => panic!("Expected SampledHeader"),
            }
        }
        _ => panic!("Expected FlowSample"),
    }
}

#[test]
fn test_parse_counter_sample_generic_interface() {
    let mut data = create_datagram_header(1);
    data.extend_from_slice(&[
        // Counter sample
        0x00, 0x00, 0x00, 0x02, // sample type = counter sample
        0x00, 0x00, 0x00, 0x6C, // sample length = 108 bytes (12 + 96)
        0x00, 0x00, 0x00, 0x03, // sequence number
        0x00, 0x00, 0x00, 0x01, // source ID
        0x00, 0x00, 0x00, 0x01, // number of counter records = 1
        // Generic interface counters
        0x00, 0x00, 0x00, 0x01, // record type = generic interface
        0x00, 0x00, 0x00, 0x58, // record length = 88 bytes
        0x00, 0x00, 0x00, 0x01, // if_index = 1
        0x00, 0x00, 0x00, 0x06, // if_type = 6
        0x00, 0x00, 0x00, 0x00, 0x3B, 0x9A, 0xCA, 0x00, // if_speed = 1 Gbps
        0x00, 0x00, 0x00, 0x01, // if_direction = 1
        0x00, 0x00, 0x00, 0x03, // if_status = 3
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x27, 0x10, // if_in_octets
        0x00, 0x00, 0x00, 0x64, // if_in_ucast_pkts = 100
        0x00, 0x00, 0x00, 0x0A, // if_in_multicast_pkts = 10
        0x00, 0x00, 0x00, 0x05, // if_in_broadcast_pkts = 5
        0x00, 0x00, 0x00, 0x00, // if_in_discards = 0
        0x00, 0x00, 0x00, 0x00, // if_in_errors = 0
        0x00, 0x00, 0x00, 0x00, // if_in_unknown_protos = 0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4E, 0x20, // if_out_octets
        0x00, 0x00, 0x00, 0xC8, // if_out_ucast_pkts = 200
        0x00, 0x00, 0x00, 0x14, // if_out_multicast_pkts = 20
        0x00, 0x00, 0x00, 0x0A, // if_out_broadcast_pkts = 10
        0x00, 0x00, 0x00, 0x00, // if_out_discards = 0
        0x00, 0x00, 0x00, 0x00, // if_out_errors = 0
        0x00, 0x00, 0x00, 0x00, // if_promiscuous_mode = 0
    ]);

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
                CounterData::GenericInterface(iface) => {
                    assert_eq!(iface.if_in_ucast_pkts, 100);
                    assert_eq!(iface.if_out_ucast_pkts, 200);
                }
                _ => panic!("Expected GenericInterface"),
            }
        }
        _ => panic!("Expected CountersSample"),
    }
}

#[test]
fn test_parse_expanded_flow_sample() {
    let mut data = create_datagram_header(1);
    data.extend_from_slice(&[
        // Expanded flow sample
        0x00, 0x00, 0x00, 0x03, // sample type = expanded flow sample
        0x00, 0x00, 0x00, 0x2C, // sample length = 44 bytes
        0x00, 0x00, 0x00, 0x05, // sequence number
        0x00, 0x00, 0x00, 0x00, // source ID type = 0
        0x00, 0x00, 0x00, 0x0A, // source ID index = 10
        0x00, 0x00, 0x08, 0x00, // sampling rate = 2048
        0x00, 0x00, 0x00, 0xC8, // sample pool = 200
        0x00, 0x00, 0x00, 0x00, // drops = 0
        0x00, 0x00, 0x00, 0x00, // input interface format = 0
        0x00, 0x00, 0x03, 0xE8, // input interface value = 1000
        0x00, 0x00, 0x00, 0x00, // output interface format = 0
        0x00, 0x00, 0x07, 0xD0, // output interface value = 2000
        0x00, 0x00, 0x00, 0x00, // number of flow records = 0
    ]);

    let result = parse_datagram(&data);
    if let Err(e) = &result {
        eprintln!("Parse error: {}", e);
    }
    assert!(result.is_ok());

    let datagram = result.unwrap();
    match &datagram.samples[0].sample_data {
        SampleData::FlowSampleExpanded(flow) => {
            assert_eq!(flow.sampling_rate, 2048);
            assert_eq!(flow.input.format, 0);
            assert_eq!(flow.input.value, 1000);
        }
        _ => panic!("Expected FlowSampleExpanded"),
    }
}

#[test]
fn test_parse_expanded_counter_sample() {
    let mut data = create_datagram_header(1);
    data.extend_from_slice(&[
        // Expanded counter sample
        0x00, 0x00, 0x00, 0x04, // sample type = expanded counter sample
        0x00, 0x00, 0x00, 0x10, // sample length = 16 bytes
        0x00, 0x00, 0x00, 0x06, // sequence number
        0x00, 0x00, 0x00, 0x00, // source ID type = 0
        0x00, 0x00, 0x00, 0x14, // source ID index = 20
        0x00, 0x00, 0x00, 0x00, // number of counter records = 0
    ]);

    let result = parse_datagram(&data);
    if let Err(e) = &result {
        eprintln!("Parse error: {}", e);
    }
    assert!(result.is_ok());

    let datagram = result.unwrap();
    match &datagram.samples[0].sample_data {
        SampleData::CountersSampleExpanded(counters) => {
            assert_eq!(counters.sequence_number, 6);
        }
        _ => panic!("Expected CountersSampleExpanded"),
    }
}

#[test]
fn test_parse_multiple_samples() {
    let mut data = create_datagram_header(2);
    data.extend_from_slice(&[
        // First sample - flow sample (minimal)
        0x00, 0x00, 0x00, 0x01, // sample type = flow sample
        0x00, 0x00, 0x00, 0x20, // sample length = 32 bytes
        0x00, 0x00, 0x00, 0x01, // sequence number
        0x00, 0x00, 0x00, 0x01, // source ID
        0x00, 0x00, 0x04, 0x00, // sampling rate
        0x00, 0x00, 0x00, 0x64, // sample pool
        0x00, 0x00, 0x00, 0x00, // drops
        0x00, 0x00, 0x00, 0x01, // input interface
        0x00, 0x00, 0x00, 0x02, // output interface
        0x00, 0x00, 0x00, 0x00, // number of flow records = 0
        // Second sample - counter sample (minimal)
        0x00, 0x00, 0x00, 0x02, // sample type = counter sample
        0x00, 0x00, 0x00, 0x0C, // sample length = 12 bytes
        0x00, 0x00, 0x00, 0x02, // sequence number
        0x00, 0x00, 0x00, 0x01, // source ID
        0x00, 0x00, 0x00, 0x00, // number of counter records = 0
    ]);

    let result = parse_datagram(&data);
    if let Err(e) = &result {
        eprintln!("Parse error: {}", e);
    }
    assert!(result.is_ok());

    let datagram = result.unwrap();
    assert_eq!(datagram.samples.len(), 2);
}

#[test]
fn test_parse_unknown_sample_type() {
    let mut data = create_datagram_header(1);
    data.extend_from_slice(&[
        // Unknown sample type
        0x00, 0x00, 0x00, 0xFF, // sample type = 255 (unknown)
        0x00, 0x00, 0x00, 0x08, // sample length = 8 bytes
        0x01, 0x02, 0x03, 0x04, // sample data
        0x05, 0x06, 0x07, 0x08,
    ]);

    let result = parse_datagram(&data);
    if let Err(e) = &result {
        eprintln!("Parse error: {}", e);
    }
    assert!(result.is_ok());

    let datagram = result.unwrap();
    assert_eq!(datagram.samples.len(), 1);

    match &datagram.samples[0].sample_data {
        SampleData::Unknown { format, data } => {
            assert_eq!(format.format(), 255);
            assert_eq!(data.len(), 8);
        }
        _ => panic!("Expected Unknown sample"),
    }
}

#[test]
fn test_parse_unknown_flow_record() {
    let mut data = create_datagram_header(1);
    data.extend_from_slice(&[
        // Flow sample
        0x00, 0x00, 0x00, 0x01, // sample type = flow sample
        0x00, 0x00, 0x00, 0x30, // sample length = 48 bytes (32 + 16)
        0x00, 0x00, 0x00, 0x01, // sequence number
        0x00, 0x00, 0x00, 0x01, // source ID
        0x00, 0x00, 0x04, 0x00, // sampling rate
        0x00, 0x00, 0x00, 0x64, // sample pool
        0x00, 0x00, 0x00, 0x00, // drops
        0x00, 0x00, 0x00, 0x01, // input interface
        0x00, 0x00, 0x00, 0x02, // output interface
        0x00, 0x00, 0x00, 0x01, // number of flow records = 1
        // Unknown flow record
        0x00, 0x00, 0xFF, 0xFF, // record type = 65535 (unknown)
        0x00, 0x00, 0x00, 0x08, // record length = 8 bytes
        0xAA, 0xBB, 0xCC, 0xDD, // record data
        0xEE, 0xFF, 0x00, 0x11,
    ]);

    let result = parse_datagram(&data);
    if let Err(e) = &result {
        eprintln!("Parse error: {}", e);
    }
    assert!(result.is_ok());

    let datagram = result.unwrap();
    match &datagram.samples[0].sample_data {
        SampleData::FlowSample(flow) => {
            assert_eq!(flow.flow_records.len(), 1);

            match &flow.flow_records[0].flow_data {
                FlowData::Unknown { format, data } => {
                    assert_eq!(format.format(), 4095); // 12-bit format field
                    assert_eq!(data.len(), 8);
                }
                _ => panic!("Expected Unknown flow record"),
            }
        }
        _ => panic!("Expected FlowSample"),
    }
}

#[test]
fn test_parse_unknown_counter_record() {
    let mut data = create_datagram_header(1);
    data.extend_from_slice(&[
        // Counter sample
        0x00, 0x00, 0x00, 0x02, // sample type = counter sample
        0x00, 0x00, 0x00, 0x1C, // sample length = 28 bytes (12 + 16)
        0x00, 0x00, 0x00, 0x01, // sequence number
        0x00, 0x00, 0x00, 0x01, // source ID
        0x00, 0x00, 0x00, 0x01, // number of counter records = 1
        // Unknown counter record
        0x00, 0x00, 0xFF, 0xFF, // record type = 65535 (unknown)
        0x00, 0x00, 0x00, 0x08, // record length = 8 bytes
        0x11, 0x22, 0x33, 0x44, // record data
        0x55, 0x66, 0x77, 0x88,
    ]);

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
                CounterData::Unknown { format, data } => {
                    assert_eq!(format.format(), 4095); // 12-bit format field
                    assert_eq!(data.len(), 8);
                }
                _ => panic!("Expected Unknown counter record"),
            }
        }
        _ => panic!("Expected CountersSample"),
    }
}

#[test]
fn test_parse_interface_formats() {
    // Test different interface formats
    let mut data = create_datagram_header(1);
    data.extend_from_slice(&[
        // Flow sample with special interface values
        0x00, 0x00, 0x00, 0x01, // sample type = flow sample
        0x00, 0x00, 0x00, 0x20, // sample length = 32 bytes
        0x00, 0x00, 0x00, 0x01, // sequence number
        0x00, 0x00, 0x00, 0x01, // source ID
        0x00, 0x00, 0x04, 0x00, // sampling rate
        0x00, 0x00, 0x00, 0x64, // sample pool
        0x00, 0x00, 0x00, 0x00, // drops
        0x80, 0x00, 0x00, 0x01, // input interface = Multiple (format=2, value=1)
        0x40, 0x00, 0x00, 0x02, // output interface = Discarded (format=1, value=2)
        0x00, 0x00, 0x00, 0x00, // number of flow records = 0
    ]);

    let result = parse_datagram(&data);
    if let Err(e) = &result {
        eprintln!("Parse error: {}", e);
    }
    assert!(result.is_ok());

    let datagram = result.unwrap();
    match &datagram.samples[0].sample_data {
        SampleData::FlowSample(flow) => {
            assert!(flow.input.is_multiple());
            assert!(flow.output.is_discarded());
        }
        _ => panic!("Expected FlowSample"),
    }
}

#[test]
fn test_parse_sampled_ethernet() {
    // Sampled Ethernet data: length(4) + src_mac(6) + dst_mac(6) + eth_type(4) = 20 bytes
    let record_data = [
        0x00, 0x00, 0x05, 0xDC, // length = 1500
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // src_mac
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // dst_mac (broadcast)
        0x00, 0x00, 0x08, 0x00, // eth_type = 0x0800 (IPv4)
    ];

    let data = build_flow_sample_test(0x0002, &record_data); // record type = 2

    let result = parse_datagram(&data);
    if let Err(e) = &result {
        eprintln!("Parse error: {}", e);
    }
    assert!(result.is_ok());

    let datagram = result.unwrap();
    match &datagram.samples[0].sample_data {
        SampleData::FlowSample(flow) => {
            assert_eq!(flow.flow_records.len(), 1);
            match &flow.flow_records[0].flow_data {
                FlowData::SampledEthernet(eth) => {
                    assert_eq!(eth.length, 1500);
                    assert_eq!(eth.eth_type, 0x0800);
                }
                _ => panic!("Expected SampledEthernet"),
            }
        }
        _ => panic!("Expected FlowSample"),
    }
}

#[test]
fn test_parse_sampled_ipv4() {
    // Sampled IPv4 data: length(4) + protocol(4) + src_ip(4) + dst_ip(4) + src_port(4) + dst_port(4) + tcp_flags(4) + tos(4) = 32 bytes
    let record_data = [
        0x00, 0x00, 0x00, 0x14, // length = 20
        0x00, 0x00, 0x00, 0x06, // protocol = TCP
        0xC0, 0xA8, 0x01, 0x64, // src_ip = 192.168.1.100
        0x08, 0x08, 0x08, 0x08, // dst_ip = 8.8.8.8
        0x00, 0x00, 0x00, 0x50, // src_port = 80
        0x00, 0x00, 0x1F, 0x90, // dst_port = 8080
        0x00, 0x00, 0x00, 0x00, // tcp_flags = 0
        0x00, 0x00, 0x00, 0x00, // tos = 0
    ];

    let data = build_flow_sample_test(0x0003, &record_data); // record type = 3

    let result = parse_datagram(&data);
    assert!(result.is_ok());

    let datagram = result.unwrap();
    match &datagram.samples[0].sample_data {
        SampleData::FlowSample(flow) => {
            assert_eq!(flow.flow_records.len(), 1);
            match &flow.flow_records[0].flow_data {
                FlowData::SampledIpv4(ipv4) => {
                    assert_eq!(ipv4.protocol, 6); // TCP
                    assert_eq!(ipv4.src_port, 80);
                    assert_eq!(ipv4.dst_port, 8080);
                }
                _ => panic!("Expected SampledIpv4"),
            }
        }
        _ => panic!("Expected FlowSample"),
    }
}

#[test]
fn test_parse_sampled_ipv6() {
    // Sampled IPv6 data: length(4) + protocol(4) + src_ip(16) + dst_ip(16) + src_port(4) + dst_port(4) + tcp_flags(4) + priority(4) = 56 bytes
    let record_data = [
        0x00, 0x00, 0x00, 0x28, // length = 40
        0x00, 0x00, 0x00, 0x06, // protocol = TCP
        // src_ip = 2001:db8::1
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, // dst_ip = 2001:db8::2
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00, 0x50, // src_port = 80
        0x00, 0x00, 0x1F, 0x90, // dst_port = 8080
        0x00, 0x00, 0x00, 0x00, // tcp_flags = 0
        0x00, 0x00, 0x00, 0x00, // priority = 0
    ];

    let data = build_flow_sample_test(0x0004, &record_data); // record type = 4

    let result = parse_datagram(&data);
    if let Err(e) = &result {
        eprintln!("Parse error: {}", e);
    }
    assert!(result.is_ok());

    let datagram = result.unwrap();
    match &datagram.samples[0].sample_data {
        SampleData::FlowSample(flow) => {
            assert_eq!(flow.flow_records.len(), 1);
            match &flow.flow_records[0].flow_data {
                FlowData::SampledIpv6(ipv6) => {
                    assert_eq!(ipv6.protocol, 6); // TCP
                    assert_eq!(ipv6.src_port, 80);
                    assert_eq!(ipv6.dst_port, 8080);
                }
                _ => panic!("Expected SampledIpv6"),
            }
        }
        _ => panic!("Expected FlowSample"),
    }
}

#[test]
fn test_parse_extended_switch() {
    // Extended Switch data: src_vlan(4) + src_priority(4) + dst_vlan(4) + dst_priority(4) = 16 bytes
    let record_data = [
        0x00, 0x00, 0x00, 0x64, // src_vlan = 100
        0x00, 0x00, 0x00, 0x03, // src_priority = 3
        0x00, 0x00, 0x00, 0xC8, // dst_vlan = 200
        0x00, 0x00, 0x00, 0x05, // dst_priority = 5
    ];

    let data = build_flow_sample_test(0x03E9, &record_data); // record type = 1001

    let result = parse_datagram(&data);
    assert!(result.is_ok());

    let datagram = result.unwrap();
    match &datagram.samples[0].sample_data {
        SampleData::FlowSample(flow) => {
            assert_eq!(flow.flow_records.len(), 1);
            match &flow.flow_records[0].flow_data {
                FlowData::ExtendedSwitch(sw) => {
                    assert_eq!(sw.src_vlan, 100);
                    assert_eq!(sw.dst_vlan, 200);
                }
                _ => panic!("Expected ExtendedSwitch"),
            }
        }
        _ => panic!("Expected FlowSample"),
    }
}

#[test]
fn test_parse_extended_router() {
    // Extended Router data: next_hop_type(4) + next_hop(4 for IPv4) + src_mask_len(4) + dst_mask_len(4) = 16 bytes
    let record_data = [
        0x00, 0x00, 0x00, 0x01, // next_hop address type = IPv4
        0xC0, 0xA8, 0x01, 0x01, // next_hop = 192.168.1.1
        0x00, 0x00, 0x00, 0x18, // src_mask_len = 24
        0x00, 0x00, 0x00, 0x10, // dst_mask_len = 16
    ];

    let data = build_flow_sample_test(0x03EA, &record_data); // record type = 1002

    let result = parse_datagram(&data);
    assert!(result.is_ok());

    let datagram = result.unwrap();
    match &datagram.samples[0].sample_data {
        SampleData::FlowSample(flow) => {
            assert_eq!(flow.flow_records.len(), 1);
            match &flow.flow_records[0].flow_data {
                FlowData::ExtendedRouter(router) => {
                    assert_eq!(router.src_mask_len, 24);
                    assert_eq!(router.dst_mask_len, 16);
                }
                _ => panic!("Expected ExtendedRouter"),
            }
        }
        _ => panic!("Expected FlowSample"),
    }
}

#[test]
fn test_parse_extended_user() {
    // Extended User data: src_charset(4) + src_user_len(4) + "alice"(5) + padding(3) +
    //                     dst_charset(4) + dst_user_len(4) + "bob"(3) + padding(1) = 28 bytes
    let record_data = [
        0x00, 0x00, 0x00, 0x03, // src_charset = 3 (UTF-8)
        0x00, 0x00, 0x00, 0x05, // src_user length = 5
        b'a', b'l', b'i', b'c', b'e', 0x00, 0x00, 0x00, // "alice" + padding
        0x00, 0x00, 0x00, 0x03, // dst_charset = 3 (UTF-8)
        0x00, 0x00, 0x00, 0x03, // dst_user length = 3
        b'b', b'o', b'b', 0x00, // "bob" + padding
    ];

    let data = build_flow_sample_test(0x03EC, &record_data); // record type = 1004

    let result = parse_datagram(&data);
    assert!(result.is_ok());

    let datagram = result.unwrap();
    match &datagram.samples[0].sample_data {
        SampleData::FlowSample(flow) => {
            assert_eq!(flow.flow_records.len(), 1);
            match &flow.flow_records[0].flow_data {
                FlowData::ExtendedUser(user) => {
                    assert_eq!(user.src_user, "alice");
                    assert_eq!(user.dst_user, "bob");
                    assert_eq!(user.src_charset, 3);
                }
                _ => panic!("Expected ExtendedUser"),
            }
        }
        _ => panic!("Expected FlowSample"),
    }
}

#[test]
fn test_parse_extended_url() {
    // Extended URL data: direction(4) + url_len(4) + "https://example.com"(19) + padding(1) +
    //                    host_len(4) + "example.com"(11) + padding(1) = 44 bytes
    let record_data = [
        0x00, 0x00, 0x00, 0x01, // direction = 1 (source)
        0x00, 0x00, 0x00, 0x13, // url length = 19
        b'h', b't', b't', b'p', b's', b':', b'/', b'/', b'e', b'x', b'a', b'm', b'p', b'l', b'e',
        b'.', b'c', b'o', b'm', 0x00, // "https://example.com" + padding
        0x00, 0x00, 0x00, 0x0B, // host length = 11
        b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm',
        0x00, // "example.com" + padding
    ];

    let data = build_flow_sample_test(0x03ED, &record_data); // record type = 1005

    let result = parse_datagram(&data);
    assert!(result.is_ok());

    let datagram = result.unwrap();
    match &datagram.samples[0].sample_data {
        SampleData::FlowSample(flow) => {
            assert_eq!(flow.flow_records.len(), 1);
            match &flow.flow_records[0].flow_data {
                FlowData::ExtendedUrl(url) => {
                    assert_eq!(url.url, "https://example.com");
                    assert_eq!(url.host, "example.com");
                    assert_eq!(url.direction, 1);
                }
                _ => panic!("Expected ExtendedUrl"),
            }
        }
        _ => panic!("Expected FlowSample"),
    }
}

#[test]
fn test_parse_extended_mpls() {
    // Extended MPLS data: next_hop_type(4) + next_hop(4 for IPv4) +
    //                     in_stack_len(4) + in_labels(3*4=12) +
    //                     out_stack_len(4) + out_labels(2*4=8) = 36 bytes
    let record_data = [
        0x00, 0x00, 0x00, 0x01, // next_hop address type = IPv4
        0x0A, 0x00, 0x00, 0x01, // next_hop = 10.0.0.1
        0x00, 0x00, 0x00, 0x03, // in_label_stack_len = 3
        0x00, 0x00, 0x00, 0x64, // label 100
        0x00, 0x00, 0x00, 0xC8, // label 200
        0x00, 0x00, 0x01, 0x2C, // label 300
        0x00, 0x00, 0x00, 0x02, // out_label_stack_len = 2
        0x00, 0x00, 0x01, 0x90, // label 400
        0x00, 0x00, 0x01, 0xF4, // label 500
    ];

    let data = build_flow_sample_test(0x03EE, &record_data); // record type = 1006

    let result = parse_datagram(&data);
    assert!(result.is_ok());

    let datagram = result.unwrap();
    match &datagram.samples[0].sample_data {
        SampleData::FlowSample(flow) => {
            assert_eq!(flow.flow_records.len(), 1);
            match &flow.flow_records[0].flow_data {
                FlowData::ExtendedMpls(mpls) => {
                    assert_eq!(mpls.in_label_stack.len(), 3);
                    assert_eq!(mpls.in_label_stack[0], 100);
                    assert_eq!(mpls.out_label_stack.len(), 2);
                    assert_eq!(mpls.out_label_stack[0], 400);
                }
                _ => panic!("Expected ExtendedMpls"),
            }
        }
        _ => panic!("Expected FlowSample"),
    }
}

#[test]
fn test_parse_extended_nat() {
    // Extended NAT data: src_addr_type(4) + src_addr(4) + dst_addr_type(4) + dst_addr(4) = 16 bytes
    let record_data = [
        0x00, 0x00, 0x00, 0x01, // src_address type = IPv4
        0xC0, 0xA8, 0x01, 0x64, // src_address = 192.168.1.100
        0x00, 0x00, 0x00, 0x01, // dst_address type = IPv4
        0x0A, 0x00, 0x00, 0x01, // dst_address = 10.0.0.1
    ];

    let data = build_flow_sample_test(0x03EF, &record_data); // record type = 1007

    let result = parse_datagram(&data);
    assert!(result.is_ok());

    let datagram = result.unwrap();
    match &datagram.samples[0].sample_data {
        SampleData::FlowSample(flow) => {
            assert_eq!(flow.flow_records.len(), 1);
            match &flow.flow_records[0].flow_data {
                FlowData::ExtendedNat(nat) => {
                    match nat.src_address {
                        Address::IPv4(ip) => assert_eq!(ip.to_string(), "192.168.1.100"),
                        _ => panic!("Expected IPv4"),
                    }
                    match nat.dst_address {
                        Address::IPv4(ip) => assert_eq!(ip.to_string(), "10.0.0.1"),
                        _ => panic!("Expected IPv4"),
                    }
                }
                _ => panic!("Expected ExtendedNat"),
            }
        }
        _ => panic!("Expected FlowSample"),
    }
}

#[test]
fn test_parse_extended_vlan_tunnel() {
    // Extended VLAN Tunnel data: num_vlans(4) + vlans(4*4=16) = 20 bytes
    let record_data = [
        0x00, 0x00, 0x00, 0x04, // num_vlans = 4
        0x00, 0x00, 0x00, 0x0A, // vlan 10
        0x00, 0x00, 0x00, 0x14, // vlan 20
        0x00, 0x00, 0x00, 0x1E, // vlan 30
        0x00, 0x00, 0x00, 0x28, // vlan 40
    ];

    let data = build_flow_sample_test(0x03F4, &record_data); // record type = 1012

    let result = parse_datagram(&data);
    assert!(result.is_ok());

    let datagram = result.unwrap();
    match &datagram.samples[0].sample_data {
        SampleData::FlowSample(flow) => {
            assert_eq!(flow.flow_records.len(), 1);
            match &flow.flow_records[0].flow_data {
                FlowData::ExtendedVlanTunnel(vlan) => {
                    assert_eq!(vlan.vlan_stack.len(), 4);
                    assert_eq!(vlan.vlan_stack[0], 10);
                    assert_eq!(vlan.vlan_stack[3], 40);
                }
                _ => panic!("Expected ExtendedVlanTunnel"),
            }
        }
        _ => panic!("Expected FlowSample"),
    }
}

#[test]
fn test_parse_extended_gateway() {
    // Extended Gateway data: next_hop_type(4) + next_hop(4) + as_number(4) + src_as(4) + src_peer_as(4) +
    //                        num_segments(4) + [path_type(4) + path_len(4) + as_path(2*4)] +
    //                        num_communities(4) + communities(2*4) + local_pref(4) = 56 bytes
    let record_data = [
        0x00, 0x00, 0x00, 0x01, // next_hop address type = IPv4
        0xC0, 0xA8, 0x01, 0x01, // next_hop = 192.168.1.1
        0x00, 0x00, 0xFD, 0xE8, // as_number = 65000
        0x00, 0x00, 0xFD, 0xE9, // src_as = 65001
        0x00, 0x00, 0xFD, 0xEA, // src_peer_as = 65002
        0x00, 0x00, 0x00, 0x01, // num_segments = 1
        0x00, 0x00, 0x00, 0x02, // path_type = 2 (AS_SEQUENCE)
        0x00, 0x00, 0x00, 0x02, // path_length = 2
        0x00, 0x00, 0xFD, 0xEB, // AS 65003
        0x00, 0x00, 0xFD, 0xEC, // AS 65004
        0x00, 0x00, 0x00, 0x02, // num_communities = 2
        0x00, 0x01, 0x00, 0x01, // community 65537
        0x00, 0x01, 0x00, 0x02, // community 65538
        0x00, 0x00, 0x00, 0x64, // local_pref = 100
    ];

    let data = build_flow_sample_test(0x03EB, &record_data); // record type = 1003

    let result = parse_datagram(&data);
    if let Err(e) = &result {
        eprintln!("Parse error: {}", e);
    }
    assert!(result.is_ok());

    let datagram = result.unwrap();
    match &datagram.samples[0].sample_data {
        SampleData::FlowSample(flow) => {
            assert_eq!(flow.flow_records.len(), 1);
            match &flow.flow_records[0].flow_data {
                FlowData::ExtendedGateway(gw) => {
                    assert_eq!(gw.as_number, 65000);
                    assert_eq!(gw.src_as, 65001);
                    assert_eq!(gw.as_path_segments.len(), 1);
                    assert_eq!(gw.as_path_segments[0].path.len(), 2);
                    assert_eq!(gw.as_path_segments[0].path[0], 65003);
                    assert_eq!(gw.communities.len(), 2);
                    assert_eq!(gw.local_pref, 100);
                }
                _ => panic!("Expected ExtendedGateway"),
            }
        }
        _ => panic!("Expected FlowSample"),
    }
}

#[test]
fn test_parse_extended_mpls_tunnel() {
    // Extended MPLS Tunnel data: tunnel_name_len(4) + "mpls0"(5) + padding(3) + tunnel_id(4) + tunnel_cos(4) = 20 bytes
    let record_data = [
        0x00, 0x00, 0x00, 0x05, // tunnel_name length = 5
        b'm', b'p', b'l', b's', b'0', 0x00, 0x00, 0x00, // "mpls0" + padding
        0x00, 0x00, 0x30, 0x39, // tunnel_id = 12345
        0x00, 0x00, 0x00, 0x03, // tunnel_cos = 3
    ];

    let data = build_flow_sample_test(0x03F0, &record_data); // record type = 1008

    let result = parse_datagram(&data);
    assert!(result.is_ok());

    let datagram = result.unwrap();
    match &datagram.samples[0].sample_data {
        SampleData::FlowSample(flow) => {
            assert_eq!(flow.flow_records.len(), 1);
            match &flow.flow_records[0].flow_data {
                FlowData::ExtendedMplsTunnel(tunnel) => {
                    assert_eq!(tunnel.tunnel_name, "mpls0");
                    assert_eq!(tunnel.tunnel_id, 12345);
                    assert_eq!(tunnel.tunnel_cos, 3);
                }
                _ => panic!("Expected ExtendedMplsTunnel"),
            }
        }
        _ => panic!("Expected FlowSample"),
    }
}

#[test]
fn test_parse_extended_mpls_vc() {
    // Extended MPLS VC data: vc_name_len(4) + "vc100"(5) + padding(3) + vll_vc_id(4) + vc_label(4) + vc_cos(4) = 24 bytes
    let record_data = [
        0x00, 0x00, 0x00, 0x05, // vc_instance_name length = 5
        b'v', b'c', b'1', b'0', b'0', 0x00, 0x00, 0x00, // "vc100" + padding
        0x00, 0x00, 0x00, 0x64, // vll_vc_id = 100
        0x00, 0x00, 0x03, 0xE8, // vc_label = 1000
        0x00, 0x00, 0x00, 0x03, // vc_cos = 3
    ];

    let data = build_flow_sample_test(0x03F1, &record_data); // record type = 1009

    let result = parse_datagram(&data);
    if let Err(e) = &result {
        eprintln!("Parse error: {}", e);
    }
    assert!(result.is_ok());

    let datagram = result.unwrap();
    match &datagram.samples[0].sample_data {
        SampleData::FlowSample(flow) => {
            assert_eq!(flow.flow_records.len(), 1);
            match &flow.flow_records[0].flow_data {
                FlowData::ExtendedMplsVc(vc) => {
                    assert_eq!(vc.vc_instance_name, "vc100");
                    assert_eq!(vc.vll_vc_id, 100);
                    assert_eq!(vc.vc_label, 1000);
                    assert_eq!(vc.vc_cos, 3);
                }
                _ => panic!("Expected ExtendedMplsVc"),
            }
        }
        _ => panic!("Expected FlowSample"),
    }
}

#[test]
fn test_parse_extended_mpls_fec() {
    // Extended MPLS FEC data: fec_addr_type(4) + fec_addr(4) + fec_prefix_len(4) = 12 bytes
    let record_data = [
        0x00, 0x00, 0x00, 0x01, // fec_addr_prefix type = IPv4
        0x0A, 0x00, 0x00, 0x00, // fec_addr_prefix = 10.0.0.0
        0x00, 0x00, 0x00, 0x08, // fec_prefix_len = 8
    ];

    let data = build_flow_sample_test(0x03F2, &record_data); // record type = 1010

    let result = parse_datagram(&data);
    assert!(result.is_ok());

    let datagram = result.unwrap();
    match &datagram.samples[0].sample_data {
        SampleData::FlowSample(flow) => {
            assert_eq!(flow.flow_records.len(), 1);
            match &flow.flow_records[0].flow_data {
                FlowData::ExtendedMplsFec(fec) => {
                    assert_eq!(fec.fec_prefix_len, 8);
                    match fec.fec_addr_prefix {
                        Address::IPv4(ip) => assert_eq!(ip.to_string(), "10.0.0.0"),
                        _ => panic!("Expected IPv4"),
                    }
                }
                _ => panic!("Expected ExtendedMplsFec"),
            }
        }
        _ => panic!("Expected FlowSample"),
    }
}

#[test]
fn test_parse_extended_mpls_lvp_fec() {
    // Extended MPLS LVP FEC data: fec_addr_prefix_len(4) = 4 bytes
    let record_data = [
        0x00, 0x00, 0x00, 0x18, // fec_addr_prefix_len = 24
    ];

    let data = build_flow_sample_test(0x03F3, &record_data); // record type = 1011

    let result = parse_datagram(&data);
    assert!(result.is_ok());

    let datagram = result.unwrap();
    match &datagram.samples[0].sample_data {
        SampleData::FlowSample(flow) => {
            assert_eq!(flow.flow_records.len(), 1);
            match &flow.flow_records[0].flow_data {
                FlowData::ExtendedMplsLvpFec(fec) => {
                    assert_eq!(fec.fec_addr_prefix_len, 24);
                }
                _ => panic!("Expected ExtendedMplsLvpFec"),
            }
        }
        _ => panic!("Expected FlowSample"),
    }
}

#[test]
fn test_parse_extended_80211_payload() {
    // Extended 802.11 Payload: cipher_suite(4) + rssi(4) + noise(4) + channel(4) + speed(4) = 20 bytes
    let record_data = [
        0x00, 0x00, 0x00, 0x04, // cipher_suite = 4 (CCMP/AES)
        0x00, 0x00, 0x00, 0xC8, // rssi = 200 (-55 dBm)
        0x00, 0x00, 0x00, 0x28, // noise = 40
        0x00, 0x00, 0x00, 0x06, // channel = 6
        0x00, 0x00, 0x01, 0xF4, // speed = 500 Mbps
    ];

    let data = build_flow_sample_test(0x03F6, &record_data); // record type = 1014

    let result = parse_datagram(&data);
    assert!(result.is_ok());

    let datagram = result.unwrap();
    match &datagram.samples[0].sample_data {
        SampleData::FlowSample(flow) => {
            assert_eq!(flow.flow_records.len(), 1);
            match &flow.flow_records[0].flow_data {
                FlowData::Extended80211Payload(wifi) => {
                    assert_eq!(wifi.cipher_suite, 4);
                    assert_eq!(wifi.rssi, 200);
                    assert_eq!(wifi.noise, 40);
                    assert_eq!(wifi.channel, 6);
                    assert_eq!(wifi.speed, 500);
                }
                _ => panic!("Expected Extended80211Payload"),
            }
        }
        _ => panic!("Expected FlowSample"),
    }
}

#[test]
fn test_parse_extended_80211_rx() {
    // Extended 802.11 RX: ssid_len(4) + "TestNet"(7) + padding(1) + bssid(6) + padding(2) +
    //                     version(4) + channel(4) + speed(8) + rssi(4) + noise(4) = 40 bytes
    let record_data = [
        0x00, 0x00, 0x00, 0x07, // ssid length = 7
        b'T', b'e', b's', b't', b'N', b'e', b't', 0x00, // "TestNet" + padding
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x00, 0x00, // bssid (6 bytes) + padding (2 bytes)
        0x00, 0x00, 0x00, 0x02, // version = 802.11n
        0x00, 0x00, 0x00, 0x24, // channel = 36
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xE8, // speed = 1000 Mbps (u64)
        0x00, 0x00, 0x00, 0xB4, // rssi = 180
        0x00, 0x00, 0x00, 0x32, // noise = 50
    ];

    let data = build_flow_sample_test(0x03F7, &record_data); // record type = 1015

    let result = parse_datagram(&data);
    if let Err(e) = &result {
        eprintln!("Parse error: {}", e);
    }
    assert!(result.is_ok());

    let datagram = result.unwrap();
    match &datagram.samples[0].sample_data {
        SampleData::FlowSample(flow) => {
            assert_eq!(flow.flow_records.len(), 1);
            match &flow.flow_records[0].flow_data {
                FlowData::Extended80211Rx(rx) => {
                    assert_eq!(rx.ssid, "TestNet");
                    assert_eq!(rx.bssid, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
                    assert_eq!(rx.version, 2);
                    assert_eq!(rx.channel, 36);
                    assert_eq!(rx.speed, 1000);
                }
                _ => panic!("Expected Extended80211Rx"),
            }
        }
        _ => panic!("Expected FlowSample"),
    }
}

#[test]
fn test_parse_extended_80211_tx() {
    // Extended 802.11 TX: ssid_len(4) + "MyAP"(4) + bssid(6) + padding(2) +
    //                     version(4) + transmissions(4) + packet_duration(4) + retrans_duration(4) +
    //                     channel(4) + speed(8) + power(4) = 48 bytes
    let record_data = [
        0x00, 0x00, 0x00, 0x04, // ssid length = 4
        b'M', b'y', b'A', b'P', // "MyAP"
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x00, // bssid (6 bytes) + padding (2 bytes)
        0x00, 0x00, 0x00, 0x03, // version = 802.11ac
        0x00, 0x00, 0x00, 0x02, // transmissions = 2
        0x00, 0x00, 0x00, 0x64, // packet_duration = 100
        0x00, 0x00, 0x00, 0x32, // retrans_duration = 50
        0x00, 0x00, 0x00, 0x06, // channel = 6
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0xB0, // speed = 1200 Mbps (u64)
        0x00, 0x00, 0x00, 0x14, // power = 20 dBm
    ];

    let data = build_flow_sample_test(0x03F8, &record_data); // record type = 1016

    let result = parse_datagram(&data);
    assert!(result.is_ok());

    let datagram = result.unwrap();
    match &datagram.samples[0].sample_data {
        SampleData::FlowSample(flow) => {
            assert_eq!(flow.flow_records.len(), 1);
            match &flow.flow_records[0].flow_data {
                FlowData::Extended80211Tx(tx) => {
                    assert_eq!(tx.ssid, "MyAP");
                    assert_eq!(tx.bssid, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
                    assert_eq!(tx.version, 3);
                    assert_eq!(tx.transmissions, 2);
                    assert_eq!(tx.channel, 6);
                    assert_eq!(tx.speed, 1200);
                    assert_eq!(tx.power, 20);
                }
                _ => panic!("Expected Extended80211Tx"),
            }
        }
        _ => panic!("Expected FlowSample"),
    }
}

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
                        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]
                    );
                    assert_eq!(adapters.adapters[1].if_index, 2);
                    assert_eq!(
                        adapters.adapters[1].mac_addresses[0],
                        [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]
                    );
                }
                _ => panic!("Expected HostAdapters"),
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
        0x00, 0x07, 0xA1, 0x20, // pkts_out = 500000
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
                    assert_eq!(net.pkts_out, 500_000);
                }
                _ => panic!("Expected HostNetIo"),
            }
        }
        _ => panic!("Expected CountersSample"),
    }
}
