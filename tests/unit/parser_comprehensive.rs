//! Comprehensive parser tests with binary data
//!
//! These tests exercise the actual parsing logic with crafted binary data
//! following the sFlow v5 specification exactly.
//!
//! Reference: https://sflow.org/sflow_version_5.txt

use sflow_parser::models::core::*;
use sflow_parser::parser::parse_datagram;

/// Helper to create datagram header (28 bytes)
/// Format: version(4) + agent_addr_type(4) + agent_addr(4 for IPv4) +
///         sub_agent_id(4) + sequence(4) + uptime(4) + num_samples(4)
fn create_datagram_header(num_samples: u32) -> Vec<u8> {
    vec![
        0x00,
        0x00,
        0x00,
        0x05, // version = 5
        0x00,
        0x00,
        0x00,
        0x01, // agent address type = IPv4
        0xC0,
        0xA8,
        0x01,
        0x01, // agent address = 192.168.1.1
        0x00,
        0x00,
        0x00,
        0x00, // sub agent ID = 0
        0x00,
        0x00,
        0x00,
        0x01, // sequence number = 1
        0x00,
        0x00,
        0x00,
        0x64, // uptime = 100ms
        // num_samples encoded as u32
        ((num_samples >> 24) & 0xFF) as u8,
        ((num_samples >> 16) & 0xFF) as u8,
        ((num_samples >> 8) & 0xFF) as u8,
        (num_samples & 0xFF) as u8,
    ]
}

#[test]
fn test_parse_flow_sample_with_sampled_header() {
    let mut data = create_datagram_header(1);
    data.extend_from_slice(&[
        // Flow sample
        0x00, 0x00, 0x00, 0x01, // sample type = flow sample
        0x00, 0x00, 0x00, 0x48, // sample length = 72 bytes
        0x00, 0x00, 0x00, 0x01, // sequence number
        0x00, 0x00, 0x00, 0x02, // source ID
        0x00, 0x00, 0x04, 0x00, // sampling rate = 1024
        0x00, 0x00, 0x00, 0x64, // sample pool = 100
        0x00, 0x00, 0x00, 0x00, // drops = 0
        0x00, 0x00, 0x00, 0x01, // input interface = 1
        0x00, 0x00, 0x00, 0x02, // output interface = 2
        0x00, 0x00, 0x00, 0x01, // number of flow records = 1
        // Sampled header record
        0x00, 0x00, 0x00, 0x01, // record type = sampled header
        0x00, 0x00, 0x00, 0x20, // record length = 32 bytes
        0x00, 0x00, 0x00, 0x01, // protocol = Ethernet
        0x00, 0x00, 0x05, 0xDC, // frame length = 1500
        0x00, 0x00, 0x00, 0x00, // stripped bytes = 0
        0x00, 0x00, 0x00, 0x0E, // header length = 14 bytes
        // Ethernet header (14 bytes + 2 padding)
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // dst MAC
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // src MAC
        0x08, 0x00, // EtherType = IPv4
        0x00, 0x00, // padding
    ]);

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
