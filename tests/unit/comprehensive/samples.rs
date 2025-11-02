//! Sample-level parsing tests
//!
//! Tests for parsing different **sample types** and sample-level functionality.
//!
//! ## Purpose
//!
//! This file tests the sample parsing layer, NOT individual flow/counter records.
//! Individual record tests are in:
//! - `flows.rs` - Tests individual flow record types (0,1 through 4413,1)
//! - `counters.rs` - Tests individual counter record types (0,1 through 5703,1)
//!
//! ## What This File Tests
//!
//! 1. **Sample Types**: FlowSample, CountersSample, ExpandedFlowSample, ExpandedCountersSample
//! 2. **Special Samples**: DiscardedPacket, RtMetric, RtFlow
//! 3. **Sample-level Features**:
//!    - Multiple samples in one datagram
//!    - Unknown sample types
//!    - Unknown record types within samples
//!    - Interface format handling
//!
//! ## Test Organization
//!
//! Tests are organized by sample type and functionality, not by (enterprise, format).

use super::helpers::*;
use sflow_parser::parsers::parse_datagram;

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
fn test_parse_discarded_packet_sample() {
    let mut data = create_datagram_header(1);

    // Build a discarded packet sample with a sampled header record
    let sampled_header_data = [
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

    data.extend_from_slice(&[
        // Discarded packet sample
        0x00, 0x00, 0x00, 0x05, // sample type = discarded packet (format 5)
        0x00, 0x00, 0x00,
        0x48, // sample length = 72 bytes (7*4 fields + 4 num_records + 8 record_header + 32 record_data)
        0x00, 0x00, 0x00, 0x01, // sequence number = 1
        0x00, 0x00, 0x00, 0x00, // source_id_type = 0
        0x00, 0x00, 0x00, 0x01, // source_id_index = 1
        0x00, 0x00, 0x00, 0x00, // drops = 0
        0x00, 0x00, 0x00, 0x02, // input_ifindex = 2
        0x00, 0x00, 0x00, 0x00, // output_ifindex = 0 (not egress drop)
        0x00, 0x00, 0x01, 0x02, // reason = 258 (ACL)
        0x00, 0x00, 0x00, 0x01, // number of flow records = 1
        // Flow record: sampled header
        0x00, 0x00, 0x00, 0x01, // flow format = sampled header (0,1)
        0x00, 0x00, 0x00, 0x20, // flow data length = 32 bytes
    ]);
    data.extend_from_slice(&sampled_header_data);

    let result = parse_datagram(&data);
    if let Err(e) = &result {
        eprintln!("Parse error: {}", e);
    }
    assert!(result.is_ok());

    let datagram = result.unwrap();
    assert_eq!(datagram.samples.len(), 1);

    match &datagram.samples[0].sample_data {
        SampleData::DiscardedPacket(discarded) => {
            assert_eq!(discarded.sequence_number, 1);
            assert_eq!(discarded.source_id.source_id_type, 0);
            assert_eq!(discarded.source_id.source_id_index, 1);
            assert_eq!(discarded.drops, 0);
            assert_eq!(discarded.input_ifindex, 2);
            assert_eq!(discarded.output_ifindex, 0);
            assert_eq!(discarded.reason as u32, 258); // ACL
            assert_eq!(discarded.flow_records.len(), 1);

            match &discarded.flow_records[0].flow_data {
                FlowData::SampledHeader(header) => {
                    assert_eq!(header.frame_length, 1500);
                    assert_eq!(header.header.len(), 14);
                }
                _ => panic!("Expected SampledHeader"),
            }
        }
        _ => panic!("Expected DiscardedPacket"),
    }
}

#[test]
fn test_parse_rtmetric_sample() {
    // sFlow-RT custom metric sample - opaque data
    let mut data = create_datagram_header(1);

    // Sample with enterprise 4300, format 1002
    let sample_data = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

    data.extend_from_slice(&[
        0x01, 0x0C, 0xC3, 0xEA, // sample type = (4300 << 12) | 1002 = 0x010CC3EA
        0x00, 0x00, 0x00, 0x08, // sample length = 8 bytes
    ]);
    data.extend_from_slice(&sample_data);

    let result = parse_datagram(&data);
    if let Err(e) = &result {
        eprintln!("Parse error: {}", e);
    }
    assert!(result.is_ok());

    let datagram = result.unwrap();
    assert_eq!(datagram.samples.len(), 1);

    match &datagram.samples[0].sample_data {
        SampleData::RtMetric { format, data } => {
            assert_eq!(format.enterprise(), 4300);
            assert_eq!(format.format(), 1002);
            assert_eq!(data.len(), 8);
            assert_eq!(&data[..], &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        }
        _ => panic!("Expected RtMetric"),
    }
}

#[test]
fn test_parse_rtflow_sample() {
    // sFlow-RT custom flow metric sample - opaque data
    let mut data = create_datagram_header(1);

    // Sample with enterprise 4300, format 1003
    let sample_data = vec![0xAA, 0xBB, 0xCC, 0xDD];

    data.extend_from_slice(&[
        0x01, 0x0C, 0xC3, 0xEB, // sample type = (4300 << 12) | 1003 = 0x010CC3EB
        0x00, 0x00, 0x00, 0x04, // sample length = 4 bytes
    ]);
    data.extend_from_slice(&sample_data);

    let result = parse_datagram(&data);
    assert!(result.is_ok());

    let datagram = result.unwrap();
    assert_eq!(datagram.samples.len(), 1);

    match &datagram.samples[0].sample_data {
        SampleData::RtFlow { format, data } => {
            assert_eq!(format.enterprise(), 4300);
            assert_eq!(format.format(), 1003);
            assert_eq!(data.len(), 4);
            assert_eq!(&data[..], &[0xAA, 0xBB, 0xCC, 0xDD]);
        }
        _ => panic!("Expected RtFlow"),
    }
}
