//! Tests for flow record structures

use sflow_parser::models::record_flows::*;
use sflow_parser::models::*;
use std::net::{Ipv4Addr, Ipv6Addr};

#[test]
fn test_sampled_header() {
    let header = SampledHeader {
        protocol: HeaderProtocol::EthernetIso88023,
        frame_length: 64,
        stripped: 0,
        header: vec![0xff; 64],
    };
    assert_eq!(header.protocol, HeaderProtocol::EthernetIso88023);
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
        path_type: AsPathType::AsSequence,
        path_length: 3,
        path: vec![100, 200, 300],
    };
    assert_eq!(segment.path_type, AsPathType::AsSequence);
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
        dst_as_path: vec![AsPathSegment {
            path_type: AsPathType::AsSequence,
            path_length: 2,
            path: vec![100, 200],
        }],
        communities: vec![100, 200, 300],
        local_pref: 100,
    };
    assert_eq!(gateway.as_number, 65000);
    assert_eq!(gateway.src_as, 100);
    assert_eq!(gateway.dst_as_path.len(), 1);
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

#[test]
fn test_drop_reason_variants() {
    // Test standard ICMP unreachable codes
    assert_eq!(DropReason::NetUnreachable as u32, 0);
    assert_eq!(DropReason::HostUnreachable as u32, 1);
    assert_eq!(DropReason::ProtocolUnreachable as u32, 2);
    assert_eq!(DropReason::PortUnreachable as u32, 3);
    assert_eq!(DropReason::FragNeeded as u32, 4);
    assert_eq!(DropReason::SrcRouteFailed as u32, 5);
    assert_eq!(DropReason::DstNetUnknown as u32, 6);
    assert_eq!(DropReason::DstHostUnknown as u32, 7);
    assert_eq!(DropReason::SrcHostIsolated as u32, 8);
    assert_eq!(DropReason::DstNetProhibited as u32, 9);
    assert_eq!(DropReason::DstHostProhibited as u32, 10);
    assert_eq!(DropReason::DstNetTosUnreachable as u32, 11);
    assert_eq!(DropReason::DstHostTosUnreachable as u32, 12);
    assert_eq!(DropReason::CommAdminProhibited as u32, 13);
    assert_eq!(DropReason::HostPrecedenceViolation as u32, 14);
    assert_eq!(DropReason::PrecedenceCutoff as u32, 15);

    // Test extended drop reasons
    assert_eq!(DropReason::Unknown as u32, 256);
    assert_eq!(DropReason::TtlExceeded as u32, 257);
    assert_eq!(DropReason::Acl as u32, 258);
    assert_eq!(DropReason::NoBufferSpace as u32, 259);
    assert_eq!(DropReason::Red as u32, 260);
    assert_eq!(DropReason::TrafficShaping as u32, 261);
    assert_eq!(DropReason::PktTooBig as u32, 262);

    // Test devlink trap reasons
    assert_eq!(DropReason::SrcMacIsMulticast as u32, 263);
    assert_eq!(DropReason::VlanTagMismatch as u32, 264);
    assert_eq!(DropReason::IngressVlanFilter as u32, 265);
}

#[test]
fn test_extended_egress_queue() {
    let queue = ExtendedEgressQueue { queue: 5 };
    assert_eq!(queue.queue, 5);
}

#[test]
fn test_extended_acl() {
    let acl = ExtendedAcl {
        number: 100,
        name: "DENY_ALL".to_string(),
        direction: 1,
    };
    assert_eq!(acl.number, 100);
    assert_eq!(acl.name, "DENY_ALL");
    assert_eq!(acl.direction, 1);
}

#[test]
fn test_extended_function() {
    let function = ExtendedFunction {
        symbol: "ip_forward_drop".to_string(),
    };
    assert_eq!(function.symbol, "ip_forward_drop");
}

#[test]
fn test_discarded_packet() {
    let discarded = DiscardedPacket {
        sequence_number: 42,
        source_id: DataSourceExpanded {
            source_id_type: 0,
            source_id_index: 1,
        },
        drops: 10,
        input_ifindex: 2,
        output_ifindex: 0,
        reason: DropReason::Acl,
        flow_records: vec![],
    };
    assert_eq!(discarded.sequence_number, 42);
    assert_eq!(discarded.source_id.source_id_type, 0);
    assert_eq!(discarded.source_id.source_id_index, 1);
    assert_eq!(discarded.drops, 10);
    assert_eq!(discarded.input_ifindex, 2);
    assert_eq!(discarded.output_ifindex, 0);
    assert_eq!(discarded.reason as u32, 258);
    assert_eq!(discarded.flow_records.len(), 0);
}

#[test]
fn test_drop_reason_from_u32() {
    // Test conversion from u32
    let reason: DropReason = unsafe { std::mem::transmute(256u32) };
    assert_eq!(reason as u32, 256);

    let reason2: DropReason = unsafe { std::mem::transmute(0u32) };
    assert_eq!(reason2 as u32, 0);
}

#[test]
fn test_extended_egress_queue_clone() {
    let queue1 = ExtendedEgressQueue { queue: 3 };
    let queue2 = queue1.clone();
    assert_eq!(queue1.queue, queue2.queue);
}

#[test]
fn test_extended_acl_clone() {
    let acl1 = ExtendedAcl {
        number: 50,
        name: "TEST_ACL".to_string(),
        direction: 0,
    };
    let acl2 = acl1.clone();
    assert_eq!(acl1.number, acl2.number);
    assert_eq!(acl1.name, acl2.name);
    assert_eq!(acl1.direction, acl2.direction);
}

#[test]
fn test_extended_function_clone() {
    let func1 = ExtendedFunction {
        symbol: "test_function".to_string(),
    };
    let func2 = func1.clone();
    assert_eq!(func1.symbol, func2.symbol);
}

#[test]
fn test_discarded_packet_debug() {
    let discarded = DiscardedPacket {
        sequence_number: 1,
        source_id: DataSourceExpanded {
            source_id_type: 0,
            source_id_index: 1,
        },
        drops: 0,
        input_ifindex: 1,
        output_ifindex: 2,
        reason: DropReason::TtlExceeded,
        flow_records: vec![],
    };
    let debug_str = format!("{:?}", discarded);
    assert!(debug_str.contains("DiscardedPacket"));
}

#[test]
fn test_drop_reason_more_variants() {
    // Test more drop reason variants for better coverage
    assert_eq!(DropReason::IngressSpanningTreeFilter as u32, 266);
    assert_eq!(DropReason::PortListIsEmpty as u32, 267);
    assert_eq!(DropReason::PortLoopbackFilter as u32, 268);
    assert_eq!(DropReason::BlackholeRoute as u32, 269);
    assert_eq!(DropReason::NonIp as u32, 270);
    assert_eq!(DropReason::UcDipOverMcDmac as u32, 271);
    assert_eq!(DropReason::DipIsLoopbackAddress as u32, 272);
    assert_eq!(DropReason::SipIsMc as u32, 273);
    assert_eq!(DropReason::SipIsLoopbackAddress as u32, 274);
    assert_eq!(DropReason::IpHeaderCorrupted as u32, 275);
    assert_eq!(DropReason::Ipv4SipIsLimitedBc as u32, 276);
    assert_eq!(DropReason::Ipv6McDipReservedScope as u32, 277);
    assert_eq!(DropReason::Ipv6McDipInterfaceLocalScope as u32, 278);
    assert_eq!(DropReason::UnresolvedNeigh as u32, 279);
    assert_eq!(DropReason::McReversePathForwarding as u32, 280);
    assert_eq!(DropReason::NonRoutablePacket as u32, 281);
    assert_eq!(DropReason::DecapError as u32, 282);
    assert_eq!(DropReason::OverlaySmacIsMc as u32, 283);
    assert_eq!(DropReason::UnknownL2 as u32, 284);
    assert_eq!(DropReason::UnknownL3 as u32, 285);
    assert_eq!(DropReason::UnknownL3Exception as u32, 286);
    assert_eq!(DropReason::UnknownBuffer as u32, 287);
    assert_eq!(DropReason::UnknownTunnel as u32, 288);
    assert_eq!(DropReason::UnknownL4 as u32, 289);
    assert_eq!(DropReason::SipIsUnspecified as u32, 290);
    assert_eq!(DropReason::MlagPortIsolation as u32, 291);
    assert_eq!(DropReason::BlackholeArpNeigh as u32, 292);
    assert_eq!(DropReason::SrcMacIsDmac as u32, 293);
    assert_eq!(DropReason::DmacIsReserved as u32, 294);
    assert_eq!(DropReason::SipIsClassE as u32, 295);
    assert_eq!(DropReason::McDmacMismatch as u32, 296);
    assert_eq!(DropReason::SipIsDip as u32, 297);
    assert_eq!(DropReason::DipIsLocalNetwork as u32, 298);
    assert_eq!(DropReason::DipIsLinkLocal as u32, 299);
    assert_eq!(DropReason::OverlaySmacIsDmac as u32, 300);
    assert_eq!(DropReason::EgressVlanFilter as u32, 301);
    assert_eq!(DropReason::UcReversePathForwarding as u32, 302);
    assert_eq!(DropReason::SplitHorizon as u32, 303);
}

#[test]
fn test_drop_reason_from_u32_method() {
    // Test the from_u32 method
    assert_eq!(DropReason::from_u32(0), Some(DropReason::NetUnreachable));
    assert_eq!(DropReason::from_u32(256), Some(DropReason::Unknown));
    assert_eq!(DropReason::from_u32(258), Some(DropReason::Acl));
    assert_eq!(DropReason::from_u32(303), Some(DropReason::SplitHorizon));
    assert_eq!(DropReason::from_u32(999), None); // Invalid value
}
