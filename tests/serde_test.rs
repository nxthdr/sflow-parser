//! Tests for serde serialization/deserialization
//!
//! These tests verify that all sFlow data structures can be properly
//! serialized and deserialized when the serde feature is enabled.

#![cfg(feature = "serde")]

use sflow_parser::models::*;
use std::net::{Ipv4Addr, Ipv6Addr};

#[test]
fn test_mac_address_serde() {
    let mac = MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let json = serde_json::to_string(&mac).unwrap();
    let deserialized: MacAddress = serde_json::from_str(&json).unwrap();
    assert_eq!(mac, deserialized);
}

#[test]
fn test_address_serde() {
    // Test IPv4
    let addr_v4 = Address::IPv4(Ipv4Addr::new(192, 168, 1, 1));
    let json = serde_json::to_string(&addr_v4).unwrap();
    let deserialized: Address = serde_json::from_str(&json).unwrap();
    assert_eq!(addr_v4, deserialized);

    // Test IPv6
    let addr_v6 = Address::IPv6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
    let json = serde_json::to_string(&addr_v6).unwrap();
    let deserialized: Address = serde_json::from_str(&json).unwrap();
    assert_eq!(addr_v6, deserialized);

    // Test Unknown
    let addr_unknown = Address::Unknown;
    let json = serde_json::to_string(&addr_unknown).unwrap();
    let deserialized: Address = serde_json::from_str(&json).unwrap();
    assert_eq!(addr_unknown, deserialized);
}

#[test]
fn test_data_format_serde() {
    let format = DataFormat::new(0, 1);
    let json = serde_json::to_string(&format).unwrap();
    let deserialized: DataFormat = serde_json::from_str(&json).unwrap();
    assert_eq!(format, deserialized);
    assert_eq!(deserialized.enterprise(), 0);
    assert_eq!(deserialized.format(), 1);
}

#[test]
fn test_sampled_header_serde() {
    let header = SampledHeader {
        protocol: HeaderProtocol::EthernetIso88023,
        frame_length: 1500,
        stripped: 0,
        header: vec![0x00, 0x11, 0x22, 0x33],
    };
    let json = serde_json::to_string(&header).unwrap();
    let deserialized: SampledHeader = serde_json::from_str(&json).unwrap();
    assert_eq!(header, deserialized);
}

#[test]
fn test_sampled_ethernet_serde() {
    let ethernet = SampledEthernet {
        length: 1500,
        src_mac: MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
        dst_mac: MacAddress::new([0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
        eth_type: 0x0800,
    };
    let json = serde_json::to_string(&ethernet).unwrap();
    let deserialized: SampledEthernet = serde_json::from_str(&json).unwrap();
    assert_eq!(ethernet, deserialized);
}

#[test]
fn test_sampled_ipv4_serde() {
    let ipv4 = SampledIpv4 {
        length: 1500,
        protocol: 6, // TCP
        src_ip: Ipv4Addr::new(192, 168, 1, 100),
        dst_ip: Ipv4Addr::new(10, 0, 0, 1),
        src_port: 12345,
        dst_port: 80,
        tcp_flags: 0x02, // SYN
        tos: 0,
    };
    let json = serde_json::to_string(&ipv4).unwrap();
    let deserialized: SampledIpv4 = serde_json::from_str(&json).unwrap();
    assert_eq!(ipv4, deserialized);
}

#[test]
fn test_sampled_ipv6_serde() {
    let ipv6 = SampledIpv6 {
        length: 1500,
        protocol: 6, // TCP
        src_ip: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
        dst_ip: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2),
        src_port: 12345,
        dst_port: 443,
        tcp_flags: 0x02, // SYN
        priority: 0,
    };
    let json = serde_json::to_string(&ipv6).unwrap();
    let deserialized: SampledIpv6 = serde_json::from_str(&json).unwrap();
    assert_eq!(ipv6, deserialized);
}

#[test]
fn test_extended_switch_serde() {
    let switch = ExtendedSwitch {
        src_vlan: 100,
        src_priority: 5,
        dst_vlan: 200,
        dst_priority: 3,
    };
    let json = serde_json::to_string(&switch).unwrap();
    let deserialized: ExtendedSwitch = serde_json::from_str(&json).unwrap();
    assert_eq!(switch, deserialized);
}

#[test]
fn test_extended_router_serde() {
    let router = ExtendedRouter {
        next_hop: Address::IPv4(Ipv4Addr::new(192, 168, 1, 1)),
        src_mask_len: 24,
        dst_mask_len: 16,
    };
    let json = serde_json::to_string(&router).unwrap();
    let deserialized: ExtendedRouter = serde_json::from_str(&json).unwrap();
    assert_eq!(router, deserialized);
}

#[test]
fn test_flow_sample_serde() {
    let sample = FlowSample {
        sequence_number: 12345,
        source_id: DataSource::new(0, 1),
        sampling_rate: 1000,
        sample_pool: 1000000,
        drops: 0,
        input: Interface(1),
        output: Interface(2),
        flow_records: vec![],
    };
    let json = serde_json::to_string(&sample).unwrap();
    let deserialized: FlowSample = serde_json::from_str(&json).unwrap();
    assert_eq!(sample, deserialized);
}

#[test]
fn test_sflow_datagram_serde() {
    let datagram = SFlowDatagram {
        version: DatagramVersion::Version5,
        agent_address: Address::IPv4(Ipv4Addr::new(192, 168, 1, 1)),
        sub_agent_id: 0,
        sequence_number: 1,
        uptime: 123456789,
        samples: vec![],
    };
    let json = serde_json::to_string(&datagram).unwrap();
    let deserialized: SFlowDatagram = serde_json::from_str(&json).unwrap();
    assert_eq!(datagram, deserialized);
}

#[test]
fn test_drop_reason_serde() {
    let reason = DropReason::Acl;
    let json = serde_json::to_string(&reason).unwrap();
    let deserialized: DropReason = serde_json::from_str(&json).unwrap();
    assert_eq!(reason, deserialized);
}

#[test]
fn test_http_method_serde() {
    let method = HttpMethod::Get;
    let json = serde_json::to_string(&method).unwrap();
    let deserialized: HttpMethod = serde_json::from_str(&json).unwrap();
    assert_eq!(method, deserialized);
}

#[test]
fn test_app_status_serde() {
    let status = AppStatus::Success;
    let json = serde_json::to_string(&status).unwrap();
    let deserialized: AppStatus = serde_json::from_str(&json).unwrap();
    assert_eq!(status, deserialized);
}
