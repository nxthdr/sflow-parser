//! Tests for parser error handling
//!
//! These tests validate that the parser correctly handles invalid input
//! and returns appropriate errors.

use sflow_parser::parsers::parse_datagram;

#[test]
fn test_invalid_version() {
    // Create a datagram with version 4 instead of 5
    let data = vec![
        0x00, 0x00, 0x00, 0x04, // version = 4 (invalid)
        0x00, 0x00, 0x00, 0x01, // agent address type = IPv4
        0xC0, 0xA8, 0x01, 0x01, // agent address = 192.168.1.1
        0x00, 0x00, 0x00, 0x00, // sub agent ID
        0x00, 0x00, 0x00, 0x01, // sequence number
        0x00, 0x00, 0x00, 0x64, // uptime
        0x00, 0x00, 0x00, 0x00, // number of samples
    ];

    let result = parse_datagram(&data);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("Invalid version"));
}

#[test]
fn test_invalid_address_type() {
    // Create a datagram with invalid address type
    let data = vec![
        0x00, 0x00, 0x00, 0x05, // version = 5
        0x00, 0x00, 0x00, 0x99, // agent address type = 99 (invalid)
        0xC0, 0xA8, 0x01, 0x01, // agent address (will fail before reading this)
    ];

    let result = parse_datagram(&data);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("Invalid address type"));
}

#[test]
fn test_truncated_datagram_header() {
    // Datagram header is incomplete
    let data = vec![
        0x00, 0x00, 0x00, 0x05, // version = 5
        0x00, 0x00, 0x00,
        0x01, // agent address type = IPv4
              // Missing rest of header
    ];

    let result = parse_datagram(&data);
    assert!(result.is_err());
}

#[test]
fn test_truncated_sample() {
    // Valid header but truncated sample
    let data = vec![
        0x00, 0x00, 0x00, 0x05, // version = 5
        0x00, 0x00, 0x00, 0x01, // agent address type = IPv4
        0xC0, 0xA8, 0x01, 0x01, // agent address = 192.168.1.1
        0x00, 0x00, 0x00, 0x00, // sub agent ID
        0x00, 0x00, 0x00, 0x01, // sequence number
        0x00, 0x00, 0x00, 0x64, // uptime
        0x00, 0x00, 0x00, 0x01, // number of samples = 1
        0x00, 0x00, 0x00,
        0x01, // sample type = flow sample
              // Missing rest of sample data
    ];

    let result = parse_datagram(&data);
    assert!(result.is_err());
}

#[test]
fn test_invalid_utf8_string() {
    // This test would require crafting a sample with an invalid UTF-8 string
    // in a field that expects a string (like hostname in HostDescription)
    // For now, we document that this error path exists
    // The parser uses String::from_utf8 which will return an error for invalid UTF-8
}

#[test]
fn test_empty_data() {
    let data = vec![];
    let result = parse_datagram(&data);
    assert!(result.is_err());
}

#[test]
fn test_minimal_valid_datagram() {
    // Minimal valid datagram with no samples
    let data = vec![
        0x00, 0x00, 0x00, 0x05, // version = 5
        0x00, 0x00, 0x00, 0x01, // agent address type = IPv4
        0xC0, 0xA8, 0x01, 0x01, // agent address = 192.168.1.1
        0x00, 0x00, 0x00, 0x00, // sub agent ID
        0x00, 0x00, 0x00, 0x01, // sequence number
        0x00, 0x00, 0x00, 0x64, // uptime = 100ms
        0x00, 0x00, 0x00, 0x00, // number of samples = 0
    ];

    let result = parse_datagram(&data);
    assert!(result.is_ok());
    let datagram = result.unwrap();
    assert_eq!(datagram.samples.len(), 0);
    assert_eq!(datagram.sequence_number, 1);
    assert_eq!(datagram.uptime, 100);
}

#[test]
fn test_ipv6_agent_address() {
    // Datagram with IPv6 agent address
    let data = vec![
        0x00, 0x00, 0x00, 0x05, // version = 5
        0x00, 0x00, 0x00, 0x02, // agent address type = IPv6
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, // IPv6 address
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // 2001:db8::1
        0x00, 0x00, 0x00, 0x00, // sub agent ID
        0x00, 0x00, 0x00, 0x01, // sequence number
        0x00, 0x00, 0x00, 0x64, // uptime
        0x00, 0x00, 0x00, 0x00, // number of samples = 0
    ];

    let result = parse_datagram(&data);
    assert!(result.is_ok());
    let datagram = result.unwrap();

    use sflow_parser::models::core::Address;
    match datagram.agent_address {
        Address::IPv6(addr) => {
            assert_eq!(addr.to_string(), "2001:db8::1");
        }
        _ => panic!("Expected IPv6 address"),
    }
}

#[test]
fn test_unknown_agent_address() {
    // Datagram with unknown address type (0)
    let data = vec![
        0x00, 0x00, 0x00, 0x05, // version = 5
        0x00, 0x00, 0x00, 0x00, // agent address type = Unknown
        0x00, 0x00, 0x00, 0x00, // sub agent ID
        0x00, 0x00, 0x00, 0x01, // sequence number
        0x00, 0x00, 0x00, 0x64, // uptime
        0x00, 0x00, 0x00, 0x00, // number of samples = 0
    ];

    let result = parse_datagram(&data);
    assert!(result.is_ok());
    let datagram = result.unwrap();

    use sflow_parser::models::core::Address;
    match datagram.agent_address {
        Address::Unknown => {
            // Expected
        }
        _ => panic!("Expected Unknown address"),
    }
}

#[test]
fn test_unknown_header_protocol() {
    // Test that HeaderProtocol::from_u32 rejects invalid values
    use sflow_parser::models::record_flows::HeaderProtocol;

    // Valid protocols (1-17) should return Some
    for protocol in 1..=17 {
        assert!(
            HeaderProtocol::from_u32(protocol).is_some(),
            "Protocol {} should be valid",
            protocol
        );
    }

    // Invalid protocols should return None
    let invalid_protocols = vec![0, 18, 100, 255, 1000, u32::MAX];
    for protocol in invalid_protocols {
        assert!(
            HeaderProtocol::from_u32(protocol).is_none(),
            "Protocol {} should be invalid",
            protocol
        );
    }
}

#[test]
fn test_valid_header_protocol_values() {
    // Test that all valid header protocol values (1-17) are accepted
    let valid_protocols: Vec<u32> = vec![
        1,  // ETHERNET-ISO88023
        2,  // ISO88024-TOKENBUS
        3,  // ISO88025-TOKENRING
        4,  // FDDI
        5,  // FRAME-RELAY
        6,  // X25
        7,  // PPP
        8,  // SMDS
        9,  // AAL5
        10, // AAL5-IP
        11, // IPv4
        12, // IPv6
        13, // MPLS
        14, // POS
        15, // IEEE80211MAC
        16, // IEEE80211AMPDU
        17, // IEEE80211AMSDU
    ];

    for protocol in valid_protocols.iter() {
        let mut data = vec![
            0x00, 0x00, 0x00, 0x05, // version = 5
            0x00, 0x00, 0x00, 0x01, // agent address type = IPv4
            0xC0, 0xA8, 0x01, 0x01, // agent address = 192.168.1.1
            0x00, 0x00, 0x00, 0x00, // sub agent ID
            0x00, 0x00, 0x00, 0x01, // sequence number
            0x00, 0x00, 0x00, 0x64, // uptime = 100ms
            0x00, 0x00, 0x00, 0x01, // number of samples = 1
            // Flow sample
            0x00, 0x00, 0x00, 0x01, // sample type = flow sample
        ];

        // Calculate sample length: 32 (flow sample header) + 12 (flow record header) + 20 (flow data)
        let sample_length: u32 = 32 + 12 + 20;
        data.extend_from_slice(&sample_length.to_be_bytes());

        data.extend_from_slice(&[
            0x00, 0x00, 0x00, 0x01, // sequence number
            0x00, 0x00, 0x00, 0x01, // source ID
            0x00, 0x00, 0x03, 0xE8, // sampling rate = 1000
            0x00, 0x00, 0x00, 0x64, // sample pool = 100
            0x00, 0x00, 0x00, 0x00, // drops = 0
            0x00, 0x00, 0x00, 0x01, // input interface = 1
            0x00, 0x00, 0x00, 0x02, // output interface = 2
            0x00, 0x00, 0x00, 0x01, // number of flow records = 1
            // Flow record: sampled_header
            0x00, 0x00, 0x00, 0x00, // enterprise = 0
            0x00, 0x00, 0x00, 0x01, // format = 1 (sampled_header)
            0x00, 0x00, 0x00, 0x14, // flow data length = 20 bytes (16 + 4 header bytes)
        ]);

        data.extend_from_slice(&(*protocol).to_be_bytes()); // protocol (valid value)
        data.extend_from_slice(&[
            0x00, 0x00, 0x00, 0x40, // frame_length = 64
            0x00, 0x00, 0x00, 0x00, // stripped = 0
            0x00, 0x00, 0x00, 0x04, // header length = 4
            0xAA, 0xBB, 0xCC, 0xDD, // header bytes
        ]);

        let result = parse_datagram(&data);
        assert!(
            result.is_ok(),
            "Protocol {} should be valid but got error: {:?}",
            protocol,
            result.err()
        );
    }
}
