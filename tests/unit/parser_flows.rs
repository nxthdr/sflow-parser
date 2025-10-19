//! Tests for all flow record types and their parsing

use sflow_parser::models::record_flows::*;
use sflow_parser::models::*;
use std::net::{Ipv4Addr, Ipv6Addr};

// ============================================================================
// Sampled Flow Records
// ============================================================================

#[test]
fn test_sampled_header_complete() {
    let header = SampledHeader {
        protocol: HeaderProtocol::EthernetIso88023, // Ethernet
        frame_length: 1500,                         // Standard MTU
        stripped: 4,                                // VLAN tag stripped
        header: vec![0xAA; 128],                    // 128 bytes captured
    };

    assert_eq!(header.protocol, HeaderProtocol::EthernetIso88023);
    assert_eq!(header.frame_length, 1500);
    assert_eq!(header.stripped, 4);
    assert_eq!(header.header.len(), 128);
    assert_eq!(header.header[0], 0xAA);
}

#[test]
fn test_sampled_header_minimal() {
    let header = SampledHeader {
        protocol: HeaderProtocol::EthernetIso88023,
        frame_length: 64, // Minimum Ethernet frame
        stripped: 0,
        header: vec![0xFF; 64],
    };

    assert_eq!(header.frame_length, 64);
    assert_eq!(header.stripped, 0);
}

#[test]
fn test_sampled_ethernet_complete() {
    let eth = SampledEthernet {
        length: 1500,
        src_mac: MacAddress::from([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
        dst_mac: MacAddress::from([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]), // Broadcast
        eth_type: 0x0800,                                                // IPv4
    };

    assert_eq!(eth.length, 1500);
    assert_eq!(
        eth.src_mac,
        MacAddress::from([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
    );
    assert_eq!(
        eth.dst_mac,
        MacAddress::from([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
    );
    assert_eq!(eth.eth_type, 0x0800);
}

#[test]
fn test_sampled_ethernet_vlan() {
    let eth = SampledEthernet {
        length: 1504, // With VLAN tag
        src_mac: MacAddress::from([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]),
        dst_mac: MacAddress::from([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]),
        eth_type: 0x8100, // VLAN tagged
    };

    assert_eq!(eth.eth_type, 0x8100);
}

#[test]
fn test_sampled_ipv4_tcp() {
    let ipv4 = SampledIpv4 {
        length: 52,  // 20 byte IP + 32 byte TCP
        protocol: 6, // TCP
        src_ip: Ipv4Addr::new(192, 168, 1, 100),
        dst_ip: Ipv4Addr::new(10, 0, 0, 1),
        src_port: 54321,
        dst_port: 443,   // HTTPS
        tcp_flags: 0x12, // SYN+ACK
        tos: 0x00,
    };

    assert_eq!(ipv4.protocol, 6);
    assert_eq!(ipv4.src_port, 54321);
    assert_eq!(ipv4.dst_port, 443);
    assert_eq!(ipv4.tcp_flags, 0x12);
}

#[test]
fn test_sampled_ipv4_udp() {
    let ipv4 = SampledIpv4 {
        length: 28,   // 20 byte IP + 8 byte UDP
        protocol: 17, // UDP
        src_ip: Ipv4Addr::new(8, 8, 8, 8),
        dst_ip: Ipv4Addr::new(192, 168, 1, 1),
        src_port: 53, // DNS
        dst_port: 12345,
        tcp_flags: 0,
        tos: 0x00,
    };

    assert_eq!(ipv4.protocol, 17);
    assert_eq!(ipv4.src_port, 53);
}

#[test]
fn test_sampled_ipv4_icmp() {
    let ipv4 = SampledIpv4 {
        length: 28,  // 20 byte IP + 8 byte ICMP
        protocol: 1, // ICMP
        src_ip: Ipv4Addr::new(192, 168, 1, 1),
        dst_ip: Ipv4Addr::new(8, 8, 8, 8),
        src_port: 0,
        dst_port: 0,
        tcp_flags: 0,
        tos: 0x00,
    };

    assert_eq!(ipv4.protocol, 1);
}

#[test]
fn test_sampled_ipv6_complete() {
    let ipv6 = SampledIpv6 {
        length: 72,  // 40 byte IPv6 + 32 byte TCP
        protocol: 6, // TCP
        src_ip: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
        dst_ip: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2),
        src_port: 8080,
        dst_port: 80,
        tcp_flags: 0x02, // SYN
        priority: 0,
    };

    assert_eq!(ipv6.protocol, 6);
    assert_eq!(ipv6.length, 72);
    assert_eq!(ipv6.src_port, 8080);
    assert_eq!(ipv6.dst_port, 80);
}

// ============================================================================
// Extended Flow Records
// ============================================================================

#[test]
fn test_extended_switch_vlan() {
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
fn test_extended_switch_no_vlan() {
    let switch = ExtendedSwitch {
        src_vlan: 0,
        src_priority: 0,
        dst_vlan: 0,
        dst_priority: 0,
    };

    assert_eq!(switch.src_vlan, 0);
    assert_eq!(switch.dst_vlan, 0);
}

#[test]
fn test_extended_router_ipv4() {
    let router = ExtendedRouter {
        next_hop: Address::IPv4(Ipv4Addr::new(10, 0, 0, 1)),
        src_mask_len: 24,
        dst_mask_len: 16,
    };

    assert_eq!(router.src_mask_len, 24);
    assert_eq!(router.dst_mask_len, 16);
    match router.next_hop {
        Address::IPv4(addr) => assert_eq!(addr, Ipv4Addr::new(10, 0, 0, 1)),
        _ => panic!("Expected IPv4"),
    }
}

#[test]
fn test_extended_router_ipv6() {
    let router = ExtendedRouter {
        next_hop: Address::IPv6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        src_mask_len: 64,
        dst_mask_len: 48,
    };

    assert_eq!(router.src_mask_len, 64);
    assert_eq!(router.dst_mask_len, 48);
}

#[test]
fn test_extended_gateway_simple() {
    let gateway = ExtendedGateway {
        next_hop: Address::IPv4(Ipv4Addr::new(192, 168, 1, 1)),
        as_number: 65000,
        src_as: 100,
        src_peer_as: 200,
        as_path_segments: vec![],
        communities: vec![],
        local_pref: 100,
    };

    assert_eq!(gateway.as_number, 65000);
    assert_eq!(gateway.src_as, 100);
    assert_eq!(gateway.src_peer_as, 200);
    assert_eq!(gateway.local_pref, 100);
}

#[test]
fn test_extended_gateway_with_as_path() {
    let gateway = ExtendedGateway {
        next_hop: Address::IPv4(Ipv4Addr::new(10, 0, 0, 1)),
        as_number: 65001,
        src_as: 100,
        src_peer_as: 200,
        as_path_segments: vec![
            AsPathSegment {
                path_type: 2, // AS_SEQUENCE
                path_length: 3,
                path: vec![100, 200, 300],
            },
            AsPathSegment {
                path_type: 1, // AS_SET
                path_length: 2,
                path: vec![400, 500],
            },
        ],
        communities: vec![100, 200, 300],
        local_pref: 150,
    };

    assert_eq!(gateway.as_path_segments.len(), 2);
    assert_eq!(gateway.as_path_segments[0].path.len(), 3);
    assert_eq!(gateway.as_path_segments[1].path_type, 1);
    assert_eq!(gateway.communities.len(), 3);
}

#[test]
fn test_extended_user() {
    let user = ExtendedUser {
        src_charset: 3, // UTF-8
        src_user: "alice".to_string(),
        dst_charset: 3,
        dst_user: "bob".to_string(),
    };

    assert_eq!(user.src_charset, 3);
    assert_eq!(user.src_user, "alice");
    assert_eq!(user.dst_user, "bob");
}

#[test]
fn test_extended_url() {
    let url = ExtendedUrl {
        direction: 1, // Source
        url: "https://example.com/path".to_string(),
        host: "example.com".to_string(),
    };

    assert_eq!(url.direction, 1);
    assert_eq!(url.url, "https://example.com/path");
    assert_eq!(url.host, "example.com");
}

// ============================================================================
// MPLS Records
// ============================================================================

#[test]
fn test_extended_mpls() {
    let mpls = ExtendedMpls {
        next_hop: Address::IPv4(Ipv4Addr::new(10, 0, 0, 1)),
        in_label_stack: vec![100, 200, 300],
        out_label_stack: vec![400, 500],
    };

    assert_eq!(mpls.in_label_stack.len(), 3);
    assert_eq!(mpls.out_label_stack.len(), 2);
    assert_eq!(mpls.in_label_stack[0], 100);
}

#[test]
fn test_extended_mpls_empty_stacks() {
    let mpls = ExtendedMpls {
        next_hop: Address::IPv4(Ipv4Addr::new(10, 0, 0, 1)),
        in_label_stack: vec![],
        out_label_stack: vec![],
    };

    assert_eq!(mpls.in_label_stack.len(), 0);
    assert_eq!(mpls.out_label_stack.len(), 0);
}

#[test]
fn test_extended_nat() {
    let nat = ExtendedNat {
        src_address: Address::IPv4(Ipv4Addr::new(192, 168, 1, 100)),
        dst_address: Address::IPv4(Ipv4Addr::new(10, 0, 0, 1)),
    };

    match nat.src_address {
        Address::IPv4(addr) => assert_eq!(addr, Ipv4Addr::new(192, 168, 1, 100)),
        _ => panic!("Expected IPv4"),
    }
}

#[test]
fn test_extended_mpls_tunnel() {
    let tunnel = ExtendedMplsTunnel {
        tunnel_name: "tunnel0".to_string(),
        tunnel_id: 12345,
        tunnel_cos: 5,
    };

    assert_eq!(tunnel.tunnel_name, "tunnel0");
    assert_eq!(tunnel.tunnel_id, 12345);
    assert_eq!(tunnel.tunnel_cos, 5);
}

#[test]
fn test_extended_mpls_vc() {
    let vc = ExtendedMplsVc {
        vc_instance_name: "vc100".to_string(),
        vll_vc_id: 100,
        vc_label: 1000,
        vc_cos: 3,
    };

    assert_eq!(vc.vc_instance_name, "vc100");
    assert_eq!(vc.vll_vc_id, 100);
    assert_eq!(vc.vc_label, 1000);
}

#[test]
fn test_extended_mpls_fec() {
    let fec = ExtendedMplsFec {
        fec_addr_prefix: Address::IPv4(Ipv4Addr::new(10, 0, 0, 0)),
        fec_prefix_len: 8,
    };

    assert_eq!(fec.fec_prefix_len, 8);
}

#[test]
fn test_extended_mpls_lvp_fec() {
    let fec = ExtendedMplsLvpFec {
        fec_addr_prefix_len: 24,
    };

    assert_eq!(fec.fec_addr_prefix_len, 24);
}

#[test]
fn test_extended_vlan_tunnel() {
    let vlan = ExtendedVlanTunnel {
        vlan_stack: vec![100, 200, 300],
    };

    assert_eq!(vlan.vlan_stack.len(), 3);
    assert_eq!(vlan.vlan_stack[0], 100);
    assert_eq!(vlan.vlan_stack[2], 300);
}

#[test]
fn test_extended_vlan_tunnel_single() {
    let vlan = ExtendedVlanTunnel {
        vlan_stack: vec![100],
    };

    assert_eq!(vlan.vlan_stack.len(), 1);
}

// ============================================================================
// 802.11 Wireless Records
// ============================================================================

#[test]
fn test_extended_80211_payload() {
    let wifi = Extended80211Payload {
        cipher_suite: 4,              // CCMP (OUI 00-0F-AC, Suite Type 4)
        data: vec![0x01, 0x02, 0x03], // Unencrypted payload data
    };

    assert_eq!(wifi.cipher_suite, 4);
    assert_eq!(wifi.data, vec![0x01, 0x02, 0x03]);
}

#[test]
fn test_extended_80211_rx() {
    let rx = Extended80211Rx {
        ssid: "MyNetwork".to_string(),
        bssid: MacAddress::from([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
        version: 4, // 802.11n
        channel: 6,
        speed: 300_000_000, // 300 Mbps in bps
        rsni: 180,
        rcpi: 90,
        packet_duration: 1000, // microseconds
    };

    assert_eq!(rx.ssid, "MyNetwork");
    assert_eq!(
        rx.bssid,
        MacAddress::from([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
    );
    assert_eq!(rx.channel, 6);
    assert_eq!(rx.rsni, 180);
    assert_eq!(rx.rcpi, 90);
}

#[test]
fn test_extended_80211_tx() {
    let tx = Extended80211Tx {
        ssid: "TestAP".to_string(),
        bssid: MacAddress::from([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]),
        version: 3,       // 802.11ac
        transmissions: 2, // Retried once
        packet_duration: 1000,
        retrans_duration: 500,
        channel: 149, // 5 GHz
        speed: 866,
        power: 20, // 20 mW
    };

    assert_eq!(tx.ssid, "TestAP");
    assert_eq!(
        tx.bssid,
        MacAddress::from([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
    );
    assert_eq!(tx.transmissions, 2);
    assert_eq!(tx.channel, 149);
    assert_eq!(tx.power, 20);
}

#[test]
fn test_extended_80211_aggregation() {
    let aggregation = Extended80211Aggregation {
        pdu_count: 5, // 5 PDUs in the aggregation
    };

    assert_eq!(aggregation.pdu_count, 5);
}

// ============================================================================
// Edge Cases and Special Values
// ============================================================================

#[test]
fn test_sampled_header_max_size() {
    let header = SampledHeader {
        protocol: HeaderProtocol::EthernetIso88023,
        frame_length: 9000, // Jumbo frame
        stripped: 0,
        header: vec![0; 256], // Max capture size
    };

    assert_eq!(header.frame_length, 9000);
    assert_eq!(header.header.len(), 256);
}

#[test]
fn test_extended_gateway_max_as_path() {
    let mut path = Vec::new();
    for i in 0..255 {
        path.push(i);
    }

    let gateway = ExtendedGateway {
        next_hop: Address::IPv4(Ipv4Addr::new(10, 0, 0, 1)),
        as_number: 65535,
        src_as: 65534,
        src_peer_as: 65533,
        as_path_segments: vec![AsPathSegment {
            path_type: 2,
            path_length: 255,
            path,
        }],
        communities: vec![],
        local_pref: 100,
    };

    assert_eq!(gateway.as_path_segments[0].path.len(), 255);
}

#[test]
fn test_extended_vlan_tunnel_max_depth() {
    let vlan = ExtendedVlanTunnel {
        vlan_stack: vec![100, 200, 300, 400, 500], // Q-in-Q-in-Q...
    };

    assert_eq!(vlan.vlan_stack.len(), 5);
}
