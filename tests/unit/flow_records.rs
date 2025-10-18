//! Tests for flow record structures

use sflow_parser::models::flow_records::*;
use sflow_parser::models::*;
use std::net::{Ipv4Addr, Ipv6Addr};

#[test]
fn test_sampled_header() {
    let header = SampledHeader {
        protocol: 1,
        frame_length: 64,
        stripped: 0,
        header: vec![0xff; 64],
    };
    assert_eq!(header.protocol, 1);
    assert_eq!(header.frame_length, 64);
    assert_eq!(header.stripped, 0);
    assert_eq!(header.header.len(), 64);
}

#[test]
fn test_sampled_ipv4() {
    let ipv4 = SampledIpv4 {
        length: 40,
        protocol: 6, // TCP
        src_ip: Ipv4Addr::new(192, 168, 1, 1),
        dst_ip: Ipv4Addr::new(10, 0, 0, 1),
        src_port: 12345,
        dst_port: 80,
        tcp_flags: 0x02, // SYN
        tos: 0,
    };
    assert_eq!(ipv4.length, 40);
    assert_eq!(ipv4.protocol, 6);
    assert_eq!(ipv4.src_ip, Ipv4Addr::new(192, 168, 1, 1));
    assert_eq!(ipv4.dst_ip, Ipv4Addr::new(10, 0, 0, 1));
    assert_eq!(ipv4.src_port, 12345);
    assert_eq!(ipv4.dst_port, 80);
    assert_eq!(ipv4.tcp_flags, 0x02);
}

#[test]
fn test_sampled_ipv6() {
    let ipv6 = SampledIpv6 {
        length: 60,
        protocol: 17, // UDP
        src_ip: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
        dst_ip: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2),
        src_port: 5000,
        dst_port: 53,
        tcp_flags: 0,
        priority: 0,
    };
    assert_eq!(ipv6.protocol, 17);
    assert_eq!(ipv6.dst_port, 53);
}

#[test]
fn test_extended_switch() {
    let switch = ExtendedSwitch {
        src_vlan: 100,
        src_priority: 3,
        dst_vlan: 200,
        dst_priority: 5,
    };
    assert_eq!(switch.src_vlan, 100);
    assert_eq!(switch.src_priority, 3);
    assert_eq!(switch.dst_vlan, 200);
    assert_eq!(switch.dst_priority, 5);
}

#[test]
fn test_extended_router() {
    let router = ExtendedRouter {
        next_hop: Address::IPv4(Ipv4Addr::new(10, 0, 0, 1)),
        src_mask_len: 24,
        dst_mask_len: 16,
    };
    assert_eq!(router.src_mask_len, 24);
    assert_eq!(router.dst_mask_len, 16);
}

#[test]
fn test_as_path_segment() {
    let segment = AsPathSegment {
        path_type: 2, // AS_SEQUENCE
        path_length: 3,
        path: vec![100, 200, 300],
    };
    assert_eq!(segment.path_type, 2);
    assert_eq!(segment.path_length, 3);
    assert_eq!(segment.path.len(), 3);
    assert_eq!(segment.path[0], 100);
    assert_eq!(segment.path[1], 200);
    assert_eq!(segment.path[2], 300);
}

#[test]
fn test_extended_gateway() {
    let gateway = ExtendedGateway {
        next_hop: Address::IPv4(Ipv4Addr::new(192, 168, 1, 1)),
        as_number: 65000,
        src_as: 100,
        src_peer_as: 200,
        as_path_segments: vec![AsPathSegment {
            path_type: 2,
            path_length: 2,
            path: vec![100, 200],
        }],
        communities: vec![100, 200, 300],
        local_pref: 100,
    };
    assert_eq!(gateway.as_number, 65000);
    assert_eq!(gateway.src_as, 100);
    assert_eq!(gateway.as_path_segments.len(), 1);
    assert_eq!(gateway.communities.len(), 3);
}

#[test]
fn test_flow_record_structure() {
    let record = FlowRecord {
        flow_format: DataFormat::new(0, 1),
        flow_data: FlowData::Unknown {
            format: DataFormat::new(0, 1),
            data: vec![1, 2, 3, 4],
        },
    };

    assert_eq!(record.flow_format.enterprise(), 0);
    assert_eq!(record.flow_format.format(), 1);

    match &record.flow_data {
        FlowData::Unknown { format, data } => {
            assert_eq!(format.enterprise(), 0);
            assert_eq!(format.format(), 1);
            assert_eq!(data.len(), 4);
        }
        _ => panic!("Expected Unknown flow data"),
    }
}
