//! Flow record parsing tests
//!
//! Tests for parsing all flow record types: sampled and extended flow records.

use super::helpers::*;
use sflow_parser::models::AppStatus;
use sflow_parser::parser::parse_datagram;

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
        0x00, 0x00, 0x00, 0x03, // in_stack_len = 3
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
                    assert_eq!(mpls.in_stack.len(), 3);
                    assert_eq!(mpls.in_stack[0], 100);
                    assert_eq!(mpls.out_stack.len(), 2);
                    assert_eq!(mpls.out_stack[0], 400);
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
    // Extended MPLS Tunnel data: tunnel_lsp_name_len(4) + "mpls0"(5) + padding(3) + tunnel_id(4) + tunnel_cos(4) = 20 bytes
    let record_data = [
        0x00, 0x00, 0x00, 0x05, // tunnel_lsp_name length = 5
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
                    assert_eq!(tunnel.tunnel_lsp_name, "mpls0");
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
    // Extended MPLS LVP FEC data: mpls_fec_addr_prefix_length(4) = 4 bytes
    let record_data = [
        0x00, 0x00, 0x00, 0x18, // mpls_fec_addr_prefix_length = 24
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
                    assert_eq!(fec.mpls_fec_addr_prefix_length, 24);
                }
                _ => panic!("Expected ExtendedMplsLvpFec"),
            }
        }
        _ => panic!("Expected FlowSample"),
    }
}

#[test]
fn test_parse_extended_80211_payload() {
    // Extended 802.11 Payload: cipher_suite(4) + data_length(4) + data(8 padded to 12) = 20 bytes
    let record_data = [
        0x00, 0x00, 0x00, 0x04, // cipher_suite = 4 (CCMP/AES)
        0x00, 0x00, 0x00, 0x08, // data length = 8 bytes
        0x01, 0x02, 0x03, 0x04, // data bytes
        0x05, 0x06, 0x07, 0x08, // data bytes
        0x00, 0x00, 0x00, 0x00, // padding to 4-byte boundary
    ];

    let data = build_flow_sample_test(0x03F5, &record_data); // record type = 1013

    let result = parse_datagram(&data);
    assert!(result.is_ok());

    let datagram = result.unwrap();
    match &datagram.samples[0].sample_data {
        SampleData::FlowSample(flow) => {
            assert_eq!(flow.flow_records.len(), 1);
            match &flow.flow_records[0].flow_data {
                FlowData::Extended80211Payload(wifi) => {
                    assert_eq!(wifi.cipher_suite, 4);
                    assert_eq!(wifi.data.len(), 8);
                    assert_eq!(wifi.data[0], 0x01);
                    assert_eq!(wifi.data[7], 0x08);
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
    //                     version(4) + channel(4) + speed(8) + rsni(4) + rcpi(4) + packet_duration(4) = 48 bytes
    let record_data = [
        0x00, 0x00, 0x00, 0x07, // ssid length = 7
        b'T', b'e', b's', b't', b'N', b'e', b't', 0x00, // "TestNet" + padding
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x00, 0x00, // bssid (6 bytes) + padding (2 bytes)
        0x00, 0x00, 0x00, 0x04, // version = 4 (802.11n)
        0x00, 0x00, 0x00, 0x24, // channel = 36
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xE8, // speed = 1000 (u64)
        0x00, 0x00, 0x00, 0xB4, // rsni = 180
        0x00, 0x00, 0x00, 0x5A, // rcpi = 90
        0x00, 0x00, 0x03, 0xE8, // packet_duration = 1000 microseconds
    ];

    let data = build_flow_sample_test(0x03F6, &record_data); // record type = 1014

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
                    assert_eq!(
                        rx.bssid,
                        MacAddress::from([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
                    );
                    assert_eq!(rx.version, 4);
                    assert_eq!(rx.channel, 36);
                    assert_eq!(rx.speed, 1000);
                    assert_eq!(rx.rsni, 180);
                    assert_eq!(rx.rcpi, 90);
                    assert_eq!(rx.packet_duration, 1000);
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

    let data = build_flow_sample_test(0x03F7, &record_data); // record type = 1015

    let result = parse_datagram(&data);
    assert!(result.is_ok());

    let datagram = result.unwrap();
    match &datagram.samples[0].sample_data {
        SampleData::FlowSample(flow) => {
            assert_eq!(flow.flow_records.len(), 1);
            match &flow.flow_records[0].flow_data {
                FlowData::Extended80211Tx(tx) => {
                    assert_eq!(tx.ssid, "MyAP");
                    assert_eq!(
                        tx.bssid,
                        MacAddress::from([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
                    );
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
fn test_parse_extended_80211_aggregation() {
    // Extended 802.11 Aggregation: pdu_count(4) + for each PDU: flow_record_count(4)
    // Simple test with 2 PDUs, each with 0 flow records
    let record_data = [
        0x00, 0x00, 0x00, 0x02, // pdu_count = 2
        0x00, 0x00, 0x00, 0x00, // PDU 1: flow_record_count = 0
        0x00, 0x00, 0x00, 0x00, // PDU 2: flow_record_count = 0
    ];

    let data = build_flow_sample_test(0x03F8, &record_data); // record type = 1016

    let result = parse_datagram(&data);
    assert!(result.is_ok());

    let datagram = result.unwrap();
    match &datagram.samples[0].sample_data {
        SampleData::FlowSample(flow) => {
            assert_eq!(flow.flow_records.len(), 1);
            match &flow.flow_records[0].flow_data {
                FlowData::Extended80211Aggregation(agg) => {
                    assert_eq!(agg.pdus.len(), 2);
                    assert_eq!(agg.pdus[0].flow_records.len(), 0);
                    assert_eq!(agg.pdus[1].flow_records.len(), 0);
                }
                _ => panic!("Expected Extended80211Aggregation"),
            }
        }
        _ => panic!("Expected FlowSample"),
    }
}

#[test]
fn test_parse_extended_socket_ipv4() {
    // Extended Socket IPv4: protocol(4) + local_ip(4) + remote_ip(4) + local_port(4) + remote_port(4) = 20 bytes
    let record_data = [
        0x00, 0x00, 0x00, 0x06, // protocol = 6 (TCP)
        0xC0, 0xA8, 0x01, 0x64, // local_ip = 192.168.1.100
        0x0A, 0x00, 0x00, 0x01, // remote_ip = 10.0.0.1
        0x00, 0x00, 0x1F, 0x90, // local_port = 8080
        0x00, 0x00, 0x01, 0xBB, // remote_port = 443
    ];

    let data = build_flow_sample_test(0x0834, &record_data); // record type = 2100

    let result = parse_datagram(&data);
    assert!(result.is_ok());

    let datagram = result.unwrap();
    match &datagram.samples[0].sample_data {
        SampleData::FlowSample(flow) => {
            assert_eq!(flow.flow_records.len(), 1);
            match &flow.flow_records[0].flow_data {
                FlowData::ExtendedSocketIpv4(sock) => {
                    assert_eq!(sock.protocol, 6);
                    assert_eq!(sock.local_ip.to_string(), "192.168.1.100");
                    assert_eq!(sock.remote_ip.to_string(), "10.0.0.1");
                    assert_eq!(sock.local_port, 8080);
                    assert_eq!(sock.remote_port, 443);
                }
                _ => panic!("Expected ExtendedSocketIpv4"),
            }
        }
        _ => panic!("Expected FlowSample"),
    }
}

#[test]
fn test_parse_extended_socket_ipv6() {
    // Extended Socket IPv6: protocol(4) + local_ip(16) + remote_ip(16) + local_port(4) + remote_port(4) = 44 bytes
    let record_data = [
        0x00, 0x00, 0x00, 0x11, // protocol = 17 (UDP)
        // local_ip = 2001:db8::1
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, // remote_ip = 2001:db8::2
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x14, 0xE9, // local_port = 5353
        0x00, 0x00, 0x00, 0x35, // remote_port = 53
    ];

    let data = build_flow_sample_test(0x0835, &record_data); // record type = 2101

    let result = parse_datagram(&data);
    assert!(result.is_ok());

    let datagram = result.unwrap();
    match &datagram.samples[0].sample_data {
        SampleData::FlowSample(flow) => {
            assert_eq!(flow.flow_records.len(), 1);
            match &flow.flow_records[0].flow_data {
                FlowData::ExtendedSocketIpv6(sock) => {
                    assert_eq!(sock.protocol, 17);
                    assert_eq!(sock.local_ip.to_string(), "2001:db8::1");
                    assert_eq!(sock.remote_ip.to_string(), "2001:db8::2");
                    assert_eq!(sock.local_port, 5353);
                    assert_eq!(sock.remote_port, 53);
                }
                _ => panic!("Expected ExtendedSocketIpv6"),
            }
        }
        _ => panic!("Expected FlowSample"),
    }
}

#[test]
fn test_parse_app_operation() {
    // Application Operation: context + status_descr + req_bytes(8) + resp_bytes(8) + duration_us(4) + status(4)
    // context: application_len(4) + "payment"(7) + padding(1) + operation_len(4) + "process"(7) + padding(1) + attributes_len(4) + "cc=visa"(7) + padding(1)
    let record_data = [
        // application = "payment"
        0x00, 0x00, 0x00, 0x07, // length = 7
        b'p', b'a', b'y', b'm', b'e', b'n', b't', 0x00, // "payment" + padding
        // operation = "process"
        0x00, 0x00, 0x00, 0x07, // length = 7
        b'p', b'r', b'o', b'c', b'e', b's', b's', 0x00, // "process" + padding
        // attributes = "cc=visa"
        0x00, 0x00, 0x00, 0x07, // length = 7
        b'c', b'c', b'=', b'v', b'i', b's', b'a', 0x00, // "cc=visa" + padding
        // status_descr = "OK"
        0x00, 0x00, 0x00, 0x02, // length = 2
        b'O', b'K', 0x00, 0x00, // "OK" + padding
        // req_bytes = 1024
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, // resp_bytes = 512
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, // duration_us = 150000
        0x00, 0x02, 0x49, 0xF0, // status = 0 (SUCCESS)
        0x00, 0x00, 0x00, 0x00,
    ];

    let data = build_flow_sample_test(0x089A, &record_data); // record type = 2202

    let result = parse_datagram(&data);
    assert!(result.is_ok());

    let datagram = result.unwrap();
    match &datagram.samples[0].sample_data {
        SampleData::FlowSample(flow) => {
            assert_eq!(flow.flow_records.len(), 1);
            match &flow.flow_records[0].flow_data {
                FlowData::AppOperation(app) => {
                    assert_eq!(app.context.application, "payment");
                    assert_eq!(app.context.operation, "process");
                    assert_eq!(app.context.attributes, "cc=visa");
                    assert_eq!(app.status_descr, "OK");
                    assert_eq!(app.req_bytes, 1024);
                    assert_eq!(app.resp_bytes, 512);
                    assert_eq!(app.duration_us, 150000);
                    assert_eq!(app.status, AppStatus::Success);
                }
                _ => panic!("Expected AppOperation"),
            }
        }
        _ => panic!("Expected FlowSample"),
    }
}

#[test]
fn test_parse_app_parent_context() {
    // Application Parent Context: context only
    // context: application_len(4) + "mail"(4) + operation_len(4) + "send"(4) + attributes_len(4) + ""(0)
    let record_data = [
        // application = "mail"
        0x00, 0x00, 0x00, 0x04, // length = 4
        b'm', b'a', b'i', b'l', // "mail"
        // operation = "send"
        0x00, 0x00, 0x00, 0x04, // length = 4
        b's', b'e', b'n', b'd', // "send"
        // attributes = "" (empty)
        0x00, 0x00, 0x00, 0x00, // length = 0
    ];

    let data = build_flow_sample_test(0x089B, &record_data); // record type = 2203

    let result = parse_datagram(&data);
    assert!(result.is_ok());

    let datagram = result.unwrap();
    match &datagram.samples[0].sample_data {
        SampleData::FlowSample(flow) => {
            assert_eq!(flow.flow_records.len(), 1);
            match &flow.flow_records[0].flow_data {
                FlowData::AppParentContext(parent) => {
                    assert_eq!(parent.context.application, "mail");
                    assert_eq!(parent.context.operation, "send");
                    assert_eq!(parent.context.attributes, "");
                }
                _ => panic!("Expected AppParentContext"),
            }
        }
        _ => panic!("Expected FlowSample"),
    }
}
