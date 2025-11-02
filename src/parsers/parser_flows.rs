//! Flow record parsers
//!
//! This module contains all parsing functions for sFlow flow records.

use super::error::{ParseError, Result};
use super::Parser;
use crate::models::*;
use std::io::{Cursor, Read};
use std::net::{Ipv4Addr, Ipv6Addr};

impl<R: Read> Parser<R> {
    /// Parse Sampled Header - Format (0,1)
    pub(super) fn parse_sampled_header(
        &mut self,
    ) -> Result<crate::models::record_flows::SampledHeader> {
        let protocol_value = self.read_u32()?;
        let protocol = crate::models::record_flows::HeaderProtocol::from_u32(protocol_value)
            .ok_or_else(|| {
                ParseError::InvalidData(format!("Unknown header protocol: {}", protocol_value))
            })?;
        let frame_length = self.read_u32()?;
        let stripped = self.read_u32()?;
        let header = self.read_opaque()?;

        Ok(crate::models::record_flows::SampledHeader {
            protocol,
            frame_length,
            stripped,
            header,
        })
    }

    /// Parse Sampled Ethernet - Format (0,2)
    pub(super) fn parse_sampled_ethernet(
        &mut self,
    ) -> Result<crate::models::record_flows::SampledEthernet> {
        let length = self.read_u32()?;

        let mut src_mac_bytes = [0u8; 6];
        self.reader.read_exact(&mut src_mac_bytes)?;
        let src_mac = crate::models::MacAddress::from(src_mac_bytes);

        let mut dst_mac_bytes = [0u8; 6];
        self.reader.read_exact(&mut dst_mac_bytes)?;
        let dst_mac = crate::models::MacAddress::from(dst_mac_bytes);

        let eth_type = self.read_u32()?;

        Ok(crate::models::record_flows::SampledEthernet {
            length,
            src_mac,
            dst_mac,
            eth_type,
        })
    }

    /// Parse Sampled IPv4 - Format (0,3)
    pub(super) fn parse_sampled_ipv4(
        &mut self,
    ) -> Result<crate::models::record_flows::SampledIpv4> {
        let length = self.read_u32()?;
        let protocol = self.read_u32()?;
        let src_ip = Ipv4Addr::from(self.read_u32()?);
        let dst_ip = Ipv4Addr::from(self.read_u32()?);
        let src_port = self.read_u32()?;
        let dst_port = self.read_u32()?;
        let tcp_flags = self.read_u32()?;
        let tos = self.read_u32()?;

        Ok(crate::models::record_flows::SampledIpv4 {
            length,
            protocol,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            tcp_flags,
            tos,
        })
    }

    /// Parse Sampled IPv6 - Format (0,4)
    pub(super) fn parse_sampled_ipv6(
        &mut self,
    ) -> Result<crate::models::record_flows::SampledIpv6> {
        let length = self.read_u32()?;
        let protocol = self.read_u32()?;

        // Read 16 bytes for source IPv6
        let mut src_bytes = [0u8; 16];
        self.reader.read_exact(&mut src_bytes)?;
        let src_ip = Ipv6Addr::from(src_bytes);

        // Read 16 bytes for destination IPv6
        let mut dst_bytes = [0u8; 16];
        self.reader.read_exact(&mut dst_bytes)?;
        let dst_ip = Ipv6Addr::from(dst_bytes);

        let src_port = self.read_u32()?;
        let dst_port = self.read_u32()?;
        let tcp_flags = self.read_u32()?;
        let priority = self.read_u32()?;

        Ok(crate::models::record_flows::SampledIpv6 {
            length,
            protocol,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            tcp_flags,
            priority,
        })
    }

    /// Parse Extended Switch - Format (0,1001)
    pub(super) fn parse_extended_switch(
        &mut self,
    ) -> Result<crate::models::record_flows::ExtendedSwitch> {
        let src_vlan = self.read_u32()?;
        let src_priority = self.read_u32()?;
        let dst_vlan = self.read_u32()?;
        let dst_priority = self.read_u32()?;

        Ok(crate::models::record_flows::ExtendedSwitch {
            src_vlan,
            src_priority,
            dst_vlan,
            dst_priority,
        })
    }

    /// Parse Extended Router - Format (0,1002)
    pub(super) fn parse_extended_router(
        &mut self,
    ) -> Result<crate::models::record_flows::ExtendedRouter> {
        let next_hop = self.parse_address()?;
        let src_mask_len = self.read_u32()?;
        let dst_mask_len = self.read_u32()?;

        Ok(crate::models::record_flows::ExtendedRouter {
            next_hop,
            src_mask_len,
            dst_mask_len,
        })
    }

    /// Parse Extended Gateway - Format (0,1003)
    pub(super) fn parse_extended_gateway(
        &mut self,
    ) -> Result<crate::models::record_flows::ExtendedGateway> {
        let next_hop = self.parse_address()?;
        let as_number = self.read_u32()?;
        let src_as = self.read_u32()?;
        let src_peer_as = self.read_u32()?;

        // Parse AS path segments
        let num_segments = self.read_u32()?;
        let capacity_segments = num_segments.min(1024) as usize;
        let mut dst_as_path = Vec::with_capacity(capacity_segments);
        for _ in 0..num_segments {
            let path_type = self.read_u32()?;
            let path_length = self.read_u32()?;
            let capacity_path = path_length.min(1024) as usize;
            let mut path = Vec::with_capacity(capacity_path);
            for _ in 0..path_length {
                path.push(self.read_u32()?);
            }
            dst_as_path.push(crate::models::record_flows::AsPathSegment {
                path_type,
                path_length,
                path,
            });
        }

        // Parse communities
        let num_communities = self.read_u32()?;
        let capacity_communities = num_communities.min(1024) as usize;
        let mut communities = Vec::with_capacity(capacity_communities);
        for _ in 0..num_communities {
            communities.push(self.read_u32()?);
        }

        let local_pref = self.read_u32()?;

        Ok(crate::models::record_flows::ExtendedGateway {
            next_hop,
            as_number,
            src_as,
            src_peer_as,
            dst_as_path,
            communities,
            local_pref,
        })
    }

    /// Parse Extended User - Format (0,1004)
    pub(super) fn parse_extended_user(
        &mut self,
    ) -> Result<crate::models::record_flows::ExtendedUser> {
        let src_charset = self.read_u32()?;
        let src_user = self.read_string()?;
        let dst_charset = self.read_u32()?;
        let dst_user = self.read_string()?;

        Ok(crate::models::record_flows::ExtendedUser {
            src_charset,
            src_user,
            dst_charset,
            dst_user,
        })
    }

    /// Parse Extended URL - Format (0,1005)
    pub(super) fn parse_extended_url(
        &mut self,
    ) -> Result<crate::models::record_flows::ExtendedUrl> {
        let direction = self.read_u32()?;
        let url = self.read_string()?;
        let host = self.read_string()?;

        Ok(crate::models::record_flows::ExtendedUrl {
            direction,
            url,
            host,
        })
    }

    /// Parse Extended MPLS - Format (0,1006)
    pub(super) fn parse_extended_mpls(
        &mut self,
    ) -> Result<crate::models::record_flows::ExtendedMpls> {
        let next_hop = self.parse_address()?;

        let in_stack_len = self.read_u32()?;
        let capacity_in = in_stack_len.min(1024) as usize;
        let mut in_stack = Vec::with_capacity(capacity_in);
        for _ in 0..in_stack_len {
            in_stack.push(self.read_u32()?);
        }

        let out_stack_len = self.read_u32()?;
        let capacity_out = out_stack_len.min(1024) as usize;
        let mut out_stack = Vec::with_capacity(capacity_out);
        for _ in 0..out_stack_len {
            out_stack.push(self.read_u32()?);
        }

        Ok(crate::models::record_flows::ExtendedMpls {
            next_hop,
            in_stack,
            out_stack,
        })
    }

    /// Parse Extended NAT - Format (0,1007)
    pub(super) fn parse_extended_nat(
        &mut self,
    ) -> Result<crate::models::record_flows::ExtendedNat> {
        let src_address = self.parse_address()?;
        let dst_address = self.parse_address()?;

        Ok(crate::models::record_flows::ExtendedNat {
            src_address,
            dst_address,
        })
    }

    /// Parse Extended NAT Port - Format (0,1020)
    pub(super) fn parse_extended_nat_port(
        &mut self,
    ) -> Result<crate::models::record_flows::ExtendedNatPort> {
        Ok(crate::models::record_flows::ExtendedNatPort {
            src_port: self.read_u32()?,
            dst_port: self.read_u32()?,
        })
    }

    /// Parse Extended InfiniBand LRH - Format (0,1031)
    pub(super) fn parse_extended_infiniband_lrh(
        &mut self,
    ) -> Result<crate::models::record_flows::ExtendedInfiniBandLrh> {
        Ok(crate::models::record_flows::ExtendedInfiniBandLrh {
            src_vl: self.read_u32()?,
            src_sl: self.read_u32()?,
            src_dlid: self.read_u32()?,
            src_slid: self.read_u32()?,
            src_lnh: self.read_u32()?,
            dst_vl: self.read_u32()?,
            dst_sl: self.read_u32()?,
            dst_dlid: self.read_u32()?,
            dst_slid: self.read_u32()?,
            dst_lnh: self.read_u32()?,
        })
    }

    /// Parse Extended InfiniBand GRH - Format (0,1032)
    pub(super) fn parse_extended_infiniband_grh(
        &mut self,
    ) -> Result<crate::models::record_flows::ExtendedInfiniBandGrh> {
        let flow_label = self.read_u32()?;
        let tc = self.read_u32()?;

        // Read source GID (16 bytes)
        let mut s_gid = [0u8; 16];
        self.reader.read_exact(&mut s_gid)?;

        // Read destination GID (16 bytes)
        let mut d_gid = [0u8; 16];
        self.reader.read_exact(&mut d_gid)?;

        Ok(crate::models::record_flows::ExtendedInfiniBandGrh {
            flow_label,
            tc,
            s_gid,
            d_gid,
            next_header: self.read_u32()?,
            length: self.read_u32()?,
        })
    }

    /// Parse Extended InfiniBand BTH - Format (0,1033)
    pub(super) fn parse_extended_infiniband_bth(
        &mut self,
    ) -> Result<crate::models::record_flows::ExtendedInfiniBandBth> {
        Ok(crate::models::record_flows::ExtendedInfiniBandBth {
            pkey: self.read_u32()?,
            dst_qp: self.read_u32()?,
            opcode: self.read_u32()?,
        })
    }

    /// Parse Extended VLAN In - Format (0,1034)
    pub(super) fn parse_extended_vlan_in(
        &mut self,
    ) -> Result<crate::models::record_flows::ExtendedVlanIn> {
        let num_vlans = self.read_u32()?;
        let capacity = num_vlans.min(1024) as usize;
        let mut stack = Vec::with_capacity(capacity);
        for _ in 0..num_vlans {
            stack.push(self.read_u32()?);
        }
        Ok(crate::models::record_flows::ExtendedVlanIn { stack })
    }

    /// Parse Extended VLAN Out - Format (0,1035)
    pub(super) fn parse_extended_vlan_out(
        &mut self,
    ) -> Result<crate::models::record_flows::ExtendedVlanOut> {
        let num_vlans = self.read_u32()?;
        let capacity = num_vlans.min(1024) as usize;
        let mut stack = Vec::with_capacity(capacity);
        for _ in 0..num_vlans {
            stack.push(self.read_u32()?);
        }
        Ok(crate::models::record_flows::ExtendedVlanOut { stack })
    }

    /// Parse Extended MPLS Tunnel - Format (0,1008)
    pub(super) fn parse_extended_mpls_tunnel(
        &mut self,
    ) -> Result<crate::models::record_flows::ExtendedMplsTunnel> {
        let tunnel_lsp_name = self.read_string()?;
        let tunnel_id = self.read_u32()?;
        let tunnel_cos = self.read_u32()?;

        Ok(crate::models::record_flows::ExtendedMplsTunnel {
            tunnel_lsp_name,
            tunnel_id,
            tunnel_cos,
        })
    }

    /// Parse Extended MPLS VC - Format (0,1009)
    pub(super) fn parse_extended_mpls_vc(
        &mut self,
    ) -> Result<crate::models::record_flows::ExtendedMplsVc> {
        let vc_instance_name = self.read_string()?;
        let vll_vc_id = self.read_u32()?;
        let vc_label = self.read_u32()?;
        let vc_cos = self.read_u32()?;

        Ok(crate::models::record_flows::ExtendedMplsVc {
            vc_instance_name,
            vll_vc_id,
            vc_label,
            vc_cos,
        })
    }

    /// Parse Extended MPLS FEC - Format (0,1010)
    pub(super) fn parse_extended_mpls_fec(
        &mut self,
    ) -> Result<crate::models::record_flows::ExtendedMplsFec> {
        let fec_addr_prefix = self.parse_address()?;
        let fec_prefix_len = self.read_u32()?;

        Ok(crate::models::record_flows::ExtendedMplsFec {
            fec_addr_prefix,
            fec_prefix_len,
        })
    }

    /// Parse Extended MPLS LVP FEC - Format (0,1011)
    pub(super) fn parse_extended_mpls_lvp_fec(
        &mut self,
    ) -> Result<crate::models::record_flows::ExtendedMplsLvpFec> {
        let mpls_fec_addr_prefix_length = self.read_u32()?;

        Ok(crate::models::record_flows::ExtendedMplsLvpFec {
            mpls_fec_addr_prefix_length,
        })
    }

    /// Parse Extended VLAN Tunnel - Format (0,1012)
    pub(super) fn parse_extended_vlan_tunnel(
        &mut self,
    ) -> Result<crate::models::record_flows::ExtendedVlanTunnel> {
        let num_vlans = self.read_u32()?;
        let capacity = num_vlans.min(1024) as usize;
        let mut stack = Vec::with_capacity(capacity);
        for _ in 0..num_vlans {
            stack.push(self.read_u32()?);
        }

        Ok(crate::models::record_flows::ExtendedVlanTunnel { stack })
    }

    /// Parse Extended 802.11 Payload - Format (0,1013)
    pub(super) fn parse_extended_80211_payload(
        &mut self,
    ) -> Result<crate::models::record_flows::Extended80211Payload> {
        let cipher_suite = self.read_u32()?;
        let data = self.read_opaque()?;

        Ok(crate::models::record_flows::Extended80211Payload { cipher_suite, data })
    }

    /// Parse Extended 802.11 RX - Format (0,1014)
    pub(super) fn parse_extended_80211_rx(
        &mut self,
    ) -> Result<crate::models::record_flows::Extended80211Rx> {
        let ssid = self.read_string()?;

        let mut bssid_bytes = [0u8; 6];
        self.reader.read_exact(&mut bssid_bytes)?;
        let bssid = crate::models::MacAddress::from(bssid_bytes);
        // Skip 2 bytes of padding to maintain 4-byte alignment
        self.reader.read_exact(&mut [0u8; 2])?;

        let version = self.read_u32()?;
        let channel = self.read_u32()?;
        let speed = self.read_u64()?;
        let rsni = self.read_u32()?;
        let rcpi = self.read_u32()?;
        let packet_duration = self.read_u32()?;

        Ok(crate::models::record_flows::Extended80211Rx {
            ssid,
            bssid,
            version,
            channel,
            speed,
            rsni,
            rcpi,
            packet_duration,
        })
    }

    /// Parse Extended 802.11 TX - Format (0,1015)
    pub(super) fn parse_extended_80211_tx(
        &mut self,
    ) -> Result<crate::models::record_flows::Extended80211Tx> {
        let ssid = self.read_string()?;

        let mut bssid_bytes = [0u8; 6];
        self.reader.read_exact(&mut bssid_bytes)?;
        let bssid = crate::models::MacAddress::from(bssid_bytes);
        // Skip 2 bytes of padding to maintain 4-byte alignment
        self.reader.read_exact(&mut [0u8; 2])?;

        let version = self.read_u32()?;
        let transmissions = self.read_u32()?;
        let packet_duration = self.read_u32()?;
        let retrans_duration = self.read_u32()?;
        let channel = self.read_u32()?;
        let speed = self.read_u64()?;
        let power = self.read_u32()?;

        Ok(crate::models::record_flows::Extended80211Tx {
            ssid,
            bssid,
            version,
            transmissions,
            packet_duration,
            retrans_duration,
            channel,
            speed,
            power,
        })
    }

    /// Parse Extended 802.11 Aggregation - Format (0,1016)
    pub(super) fn parse_extended_80211_aggregation(
        &mut self,
    ) -> Result<crate::models::record_flows::Extended80211Aggregation> {
        let pdu_count = self.read_u32()?;
        let capacity = pdu_count.min(256) as usize; // Reasonable limit for PDUs
        let mut pdus = Vec::with_capacity(capacity);

        for _ in 0..pdu_count {
            // Parse flow records for this PDU
            let flow_record_count = self.read_u32()?;
            let flow_capacity = flow_record_count.min(64) as usize;
            let mut flow_records = Vec::with_capacity(flow_capacity);

            for _ in 0..flow_record_count {
                flow_records.push(self.parse_flow_record()?);
            }

            pdus.push(crate::models::record_flows::Pdu { flow_records });
        }

        Ok(crate::models::record_flows::Extended80211Aggregation { pdus })
    }

    /// Parse Extended OpenFlow v1 - Format (0,1017) - DEPRECATED
    pub(super) fn parse_extended_openflow_v1(
        &mut self,
    ) -> Result<crate::models::record_flows::ExtendedOpenFlowV1> {
        let flow_cookie = self.read_u64()?;
        let flow_match = self.read_u32()?;
        let flow_actions = self.read_u32()?;

        Ok(crate::models::record_flows::ExtendedOpenFlowV1 {
            flow_cookie,
            flow_match,
            flow_actions,
        })
    }

    /// Parse Extended L2 Tunnel Egress - Format (0,1021)
    pub(super) fn parse_extended_l2_tunnel_egress(
        &mut self,
    ) -> Result<crate::models::record_flows::ExtendedL2TunnelEgress> {
        let header = self.parse_sampled_ethernet()?;

        Ok(crate::models::record_flows::ExtendedL2TunnelEgress { header })
    }

    /// Parse Extended L2 Tunnel Ingress - Format (0,1022)
    pub(super) fn parse_extended_l2_tunnel_ingress(
        &mut self,
    ) -> Result<crate::models::record_flows::ExtendedL2TunnelIngress> {
        let header = self.parse_sampled_ethernet()?;

        Ok(crate::models::record_flows::ExtendedL2TunnelIngress { header })
    }

    /// Parse Extended IPv4 Tunnel Egress - Format (0,1023)
    pub(super) fn parse_extended_ipv4_tunnel_egress(
        &mut self,
    ) -> Result<crate::models::record_flows::ExtendedIpv4TunnelEgress> {
        let header = self.parse_sampled_ipv4()?;

        Ok(crate::models::record_flows::ExtendedIpv4TunnelEgress { header })
    }

    /// Parse Extended IPv4 Tunnel Ingress - Format (0,1024)
    pub(super) fn parse_extended_ipv4_tunnel_ingress(
        &mut self,
    ) -> Result<crate::models::record_flows::ExtendedIpv4TunnelIngress> {
        let header = self.parse_sampled_ipv4()?;

        Ok(crate::models::record_flows::ExtendedIpv4TunnelIngress { header })
    }

    /// Parse Extended IPv6 Tunnel Egress - Format (0,1025)
    pub(super) fn parse_extended_ipv6_tunnel_egress(
        &mut self,
    ) -> Result<crate::models::record_flows::ExtendedIpv6TunnelEgress> {
        let header = self.parse_sampled_ipv6()?;

        Ok(crate::models::record_flows::ExtendedIpv6TunnelEgress { header })
    }

    /// Parse Extended IPv6 Tunnel Ingress - Format (0,1026)
    pub(super) fn parse_extended_ipv6_tunnel_ingress(
        &mut self,
    ) -> Result<crate::models::record_flows::ExtendedIpv6TunnelIngress> {
        let header = self.parse_sampled_ipv6()?;

        Ok(crate::models::record_flows::ExtendedIpv6TunnelIngress { header })
    }

    /// Parse Extended Decapsulate Egress - Format (0,1027)
    pub(super) fn parse_extended_decapsulate_egress(
        &mut self,
    ) -> Result<crate::models::record_flows::ExtendedDecapsulateEgress> {
        let inner_header_offset = self.read_u32()?;

        Ok(crate::models::record_flows::ExtendedDecapsulateEgress {
            inner_header_offset,
        })
    }

    /// Parse Extended Decapsulate Ingress - Format (0,1028)
    pub(super) fn parse_extended_decapsulate_ingress(
        &mut self,
    ) -> Result<crate::models::record_flows::ExtendedDecapsulateIngress> {
        let inner_header_offset = self.read_u32()?;

        Ok(crate::models::record_flows::ExtendedDecapsulateIngress {
            inner_header_offset,
        })
    }

    /// Parse Extended VNI Egress - Format (0,1029)
    pub(super) fn parse_extended_vni_egress(
        &mut self,
    ) -> Result<crate::models::record_flows::ExtendedVniEgress> {
        let vni = self.read_u32()?;

        Ok(crate::models::record_flows::ExtendedVniEgress { vni })
    }

    /// Parse Extended VNI Ingress - Format (0,1030)
    pub(super) fn parse_extended_vni_ingress(
        &mut self,
    ) -> Result<crate::models::record_flows::ExtendedVniIngress> {
        let vni = self.read_u32()?;

        Ok(crate::models::record_flows::ExtendedVniIngress { vni })
    }

    /// Parse Extended Egress Queue - Format (0,1036)
    pub(super) fn parse_extended_egress_queue(
        &mut self,
    ) -> Result<crate::models::record_flows::ExtendedEgressQueue> {
        let queue = self.read_u32()?;

        Ok(crate::models::record_flows::ExtendedEgressQueue { queue })
    }

    /// Parse Extended ACL - Format (0,1037)
    pub(super) fn parse_extended_acl(
        &mut self,
    ) -> Result<crate::models::record_flows::ExtendedAcl> {
        let number = self.read_u32()?;
        let name = self.read_string()?;
        let direction = self.read_u32()?;

        Ok(crate::models::record_flows::ExtendedAcl {
            number,
            name,
            direction,
        })
    }

    /// Parse Extended Function - Format (0,1038)
    pub(super) fn parse_extended_function(
        &mut self,
    ) -> Result<crate::models::record_flows::ExtendedFunction> {
        let symbol = self.read_string()?;

        Ok(crate::models::record_flows::ExtendedFunction { symbol })
    }

    /// Parse Extended Transit - Format (0,1039)
    pub(super) fn parse_extended_transit(
        &mut self,
    ) -> Result<crate::models::record_flows::ExtendedTransit> {
        let delay = self.read_u32()?;

        Ok(crate::models::record_flows::ExtendedTransit { delay })
    }

    /// Parse Extended Queue - Format (0,1040)
    pub(super) fn parse_extended_queue(
        &mut self,
    ) -> Result<crate::models::record_flows::ExtendedQueue> {
        let depth = self.read_u32()?;

        Ok(crate::models::record_flows::ExtendedQueue { depth })
    }

    /// Parse Extended HW Trap - Format (0,1041)
    pub(super) fn parse_extended_hw_trap(
        &mut self,
    ) -> Result<crate::models::record_flows::ExtendedHwTrap> {
        let group = self.read_string()?;
        let trap = self.read_string()?;

        Ok(crate::models::record_flows::ExtendedHwTrap { group, trap })
    }

    /// Parse Extended Linux Drop Reason - Format (0,1042)
    pub(super) fn parse_extended_linux_drop_reason(
        &mut self,
    ) -> Result<crate::models::record_flows::ExtendedLinuxDropReason> {
        let reason = self.read_string()?;

        Ok(crate::models::record_flows::ExtendedLinuxDropReason { reason })
    }

    /// Parse Transaction - Format (0,2000)
    pub(super) fn parse_transaction(&mut self) -> Result<crate::models::record_flows::Transaction> {
        let direction = self.read_u32()?;
        let wait = self.read_u32()?;
        let duration = self.read_u32()?;
        let status = self.read_u32()?;
        let bytes_received = self.read_u64()?;
        let bytes_sent = self.read_u64()?;

        Ok(crate::models::record_flows::Transaction {
            direction,
            wait,
            duration,
            status,
            bytes_received,
            bytes_sent,
        })
    }

    /// Parse Extended NFS Storage Transaction - Format (0,2001)
    pub(super) fn parse_extended_nfs_storage_transaction(
        &mut self,
    ) -> Result<crate::models::record_flows::ExtendedNfsStorageTransaction> {
        let path = self.read_opaque()?;
        let operation = self.read_u32()?;
        let status = self.read_u32()?;

        Ok(crate::models::record_flows::ExtendedNfsStorageTransaction {
            path,
            operation,
            status,
        })
    }

    /// Parse Extended SCSI Storage Transaction - Format (0,2002)
    pub(super) fn parse_extended_scsi_storage_transaction(
        &mut self,
    ) -> Result<crate::models::record_flows::ExtendedScsiStorageTransaction> {
        let lun = self.read_u32()?;
        let operation = self.read_u32()?;
        let status = self.read_u32()?;

        Ok(
            crate::models::record_flows::ExtendedScsiStorageTransaction {
                lun,
                operation,
                status,
            },
        )
    }

    /// Parse Extended HTTP Transaction - Format (0,2003)
    pub(super) fn parse_extended_http_transaction(
        &mut self,
    ) -> Result<crate::models::record_flows::ExtendedHttpTransaction> {
        let url = self.read_string()?;
        let host = self.read_string()?;
        let referer = self.read_string()?;
        let user_agent = self.read_string()?;
        let user = self.read_string()?;
        let status = self.read_u32()?;

        Ok(crate::models::record_flows::ExtendedHttpTransaction {
            url,
            host,
            referer,
            user_agent,
            user,
            status,
        })
    }

    /// Parse Extended Socket IPv4 - Format (0,2100)
    pub(super) fn parse_extended_socket_ipv4(
        &mut self,
    ) -> Result<crate::models::record_flows::ExtendedSocketIpv4> {
        use std::net::Ipv4Addr;

        let protocol = self.read_u32()?;
        let local_ip = Ipv4Addr::from(self.read_u32()?);
        let remote_ip = Ipv4Addr::from(self.read_u32()?);
        let local_port = self.read_u32()?;
        let remote_port = self.read_u32()?;

        Ok(crate::models::record_flows::ExtendedSocketIpv4 {
            protocol,
            local_ip,
            remote_ip,
            local_port,
            remote_port,
        })
    }

    /// Parse Extended Socket IPv6 - Format (0,2101)
    pub(super) fn parse_extended_socket_ipv6(
        &mut self,
    ) -> Result<crate::models::record_flows::ExtendedSocketIpv6> {
        use std::net::Ipv6Addr;

        let protocol = self.read_u32()?;

        // Read 16 bytes for local IPv6
        let mut local_bytes = [0u8; 16];
        self.reader.read_exact(&mut local_bytes)?;
        let local_ip = Ipv6Addr::from(local_bytes);

        // Read 16 bytes for remote IPv6
        let mut remote_bytes = [0u8; 16];
        self.reader.read_exact(&mut remote_bytes)?;
        let remote_ip = Ipv6Addr::from(remote_bytes);

        let local_port = self.read_u32()?;
        let remote_port = self.read_u32()?;

        Ok(crate::models::record_flows::ExtendedSocketIpv6 {
            protocol,
            local_ip,
            remote_ip,
            local_port,
            remote_port,
        })
    }

    /// Parse Extended Proxy Socket IPv4 - Format (0,2102)
    pub(super) fn parse_extended_proxy_socket_ipv4(
        &mut self,
    ) -> Result<crate::models::record_flows::ExtendedProxySocketIpv4> {
        let socket = self.parse_extended_socket_ipv4()?;

        Ok(crate::models::record_flows::ExtendedProxySocketIpv4 { socket })
    }

    /// Parse Extended Proxy Socket IPv6 - Format (0,2103)
    pub(super) fn parse_extended_proxy_socket_ipv6(
        &mut self,
    ) -> Result<crate::models::record_flows::ExtendedProxySocketIpv6> {
        let socket = self.parse_extended_socket_ipv6()?;

        Ok(crate::models::record_flows::ExtendedProxySocketIpv6 { socket })
    }

    /// Parse Application Context
    fn parse_app_context(&mut self) -> Result<crate::models::record_flows::AppContext> {
        let application = self.read_string()?;
        let operation = self.read_string()?;
        let attributes = self.read_string()?;

        Ok(crate::models::record_flows::AppContext {
            application,
            operation,
            attributes,
        })
    }

    /// Parse Memcache Operation - Format (0,2200)
    pub(super) fn parse_memcache_operation(
        &mut self,
    ) -> Result<crate::models::record_flows::MemcacheOperation> {
        use crate::models::record_flows::{MemcacheCommand, MemcacheProtocol, MemcacheStatus};

        let protocol = MemcacheProtocol::from_u32(self.read_u32()?);
        let cmd = MemcacheCommand::from_u32(self.read_u32()?);
        let key = self.read_string()?;
        let nkeys = self.read_u32()?;
        let value_bytes = self.read_u32()?;
        let duration_us = self.read_u32()?;
        let status = MemcacheStatus::from_u32(self.read_u32()?);

        Ok(crate::models::record_flows::MemcacheOperation {
            protocol,
            cmd,
            key,
            nkeys,
            value_bytes,
            duration_us,
            status,
        })
    }

    /// Parse HTTP Request - Format (0,2201) - DEPRECATED
    pub(super) fn parse_http_request_deprecated(
        &mut self,
    ) -> Result<crate::models::record_flows::HttpRequestDeprecated> {
        let method = crate::models::record_flows::HttpMethod::from(self.read_u32()?);
        let uri = self.read_string()?;
        let host = self.read_string()?;
        let referer = self.read_string()?;
        let useragent = self.read_string()?;
        let xff = self.read_string()?;
        let authuser = self.read_string()?;
        let mime_type = self.read_string()?;
        let req_bytes = self.read_u64()?;
        let resp_bytes = self.read_u64()?;
        let duration_us = self.read_u32()?;
        let status = self.read_i32()?;

        Ok(crate::models::record_flows::HttpRequestDeprecated {
            method,
            uri,
            host,
            referer,
            useragent,
            xff,
            authuser,
            mime_type,
            req_bytes,
            resp_bytes,
            duration_us,
            status,
        })
    }

    /// Parse Application Operation - Format (0,2202)
    pub(super) fn parse_app_operation(
        &mut self,
    ) -> Result<crate::models::record_flows::AppOperation> {
        let context = self.parse_app_context()?;
        let status_descr = self.read_string()?;
        let req_bytes = self.read_u64()?;
        let resp_bytes = self.read_u64()?;
        let duration_us = self.read_u32()?;
        let status = crate::models::record_flows::AppStatus::from(self.read_u32()?);

        Ok(crate::models::record_flows::AppOperation {
            context,
            status_descr,
            req_bytes,
            resp_bytes,
            duration_us,
            status,
        })
    }

    /// Parse Application Parent Context - Format (0,2203)
    pub(super) fn parse_app_parent_context(
        &mut self,
    ) -> Result<crate::models::record_flows::AppParentContext> {
        let context = self.parse_app_context()?;

        Ok(crate::models::record_flows::AppParentContext { context })
    }

    /// Parse Application Initiator - Format (0,2204)
    pub(super) fn parse_app_initiator(
        &mut self,
    ) -> Result<crate::models::record_flows::AppInitiator> {
        let actor = self.read_string()?;

        Ok(crate::models::record_flows::AppInitiator { actor })
    }

    /// Parse Application Target - Format (0,2205)
    pub(super) fn parse_app_target(&mut self) -> Result<crate::models::record_flows::AppTarget> {
        let actor = self.read_string()?;

        Ok(crate::models::record_flows::AppTarget { actor })
    }

    /// Parse HTTP Request - Format (0,2206)
    pub(super) fn parse_http_request(
        &mut self,
    ) -> Result<crate::models::record_flows::HttpRequest> {
        let method = crate::models::record_flows::HttpMethod::from(self.read_u32()?);
        let protocol = self.read_u32()?;
        let uri = self.read_string()?;
        let host = self.read_string()?;
        let referer = self.read_string()?;
        let useragent = self.read_string()?;
        let xff = self.read_string()?;
        let authuser = self.read_string()?;
        let mime_type = self.read_string()?;
        let req_bytes = self.read_u64()?;
        let resp_bytes = self.read_u64()?;
        let duration_us = self.read_u32()?;
        let status = self.read_u32()? as i32;

        Ok(crate::models::record_flows::HttpRequest {
            method,
            protocol,
            uri,
            host,
            referer,
            useragent,
            xff,
            authuser,
            mime_type,
            req_bytes,
            resp_bytes,
            duration_us,
            status,
        })
    }

    /// Parse Extended Proxy Request - Format (0,2207)
    pub(super) fn parse_extended_proxy_request(
        &mut self,
    ) -> Result<crate::models::record_flows::ExtendedProxyRequest> {
        Ok(crate::models::record_flows::ExtendedProxyRequest {
            uri: self.read_string()?,
            host: self.read_string()?,
        })
    }

    /// Parse Extended BST Egress Queue - Format (4413,1)
    pub(super) fn parse_extended_bst_egress_queue(
        &mut self,
    ) -> Result<crate::models::record_flows::ExtendedBstEgressQueue> {
        Ok(crate::models::record_flows::ExtendedBstEgressQueue {
            queue: self.read_u32()?,
        })
    }

    /// Parse flow data based on format
    pub(super) fn parse_flow_data(
        &mut self,
        format: DataFormat,
        data: Vec<u8>,
    ) -> Result<FlowData> {
        let mut cursor = Cursor::new(data.clone());
        let mut parser = Parser::new(&mut cursor);

        // Standard sFlow formats (enterprise = 0)
        if format.enterprise() == 0 {
            match format.format() {
                1 => Ok(FlowData::SampledHeader(parser.parse_sampled_header()?)),
                2 => Ok(FlowData::SampledEthernet(parser.parse_sampled_ethernet()?)),
                3 => Ok(FlowData::SampledIpv4(parser.parse_sampled_ipv4()?)),
                4 => Ok(FlowData::SampledIpv6(parser.parse_sampled_ipv6()?)),
                1001 => Ok(FlowData::ExtendedSwitch(parser.parse_extended_switch()?)),
                1002 => Ok(FlowData::ExtendedRouter(parser.parse_extended_router()?)),
                1003 => Ok(FlowData::ExtendedGateway(parser.parse_extended_gateway()?)),
                1004 => Ok(FlowData::ExtendedUser(parser.parse_extended_user()?)),
                // Note: Format 1005 is deprecated but kept for backward compatibility
                1005 => Ok(FlowData::ExtendedUrl(parser.parse_extended_url()?)),
                1006 => Ok(FlowData::ExtendedMpls(parser.parse_extended_mpls()?)),
                1007 => Ok(FlowData::ExtendedNat(parser.parse_extended_nat()?)),
                1008 => Ok(FlowData::ExtendedMplsTunnel(
                    parser.parse_extended_mpls_tunnel()?,
                )),
                1009 => Ok(FlowData::ExtendedMplsVc(parser.parse_extended_mpls_vc()?)),
                1010 => Ok(FlowData::ExtendedMplsFec(parser.parse_extended_mpls_fec()?)),
                1011 => Ok(FlowData::ExtendedMplsLvpFec(
                    parser.parse_extended_mpls_lvp_fec()?,
                )),
                1012 => Ok(FlowData::ExtendedVlanTunnel(
                    parser.parse_extended_vlan_tunnel()?,
                )),
                1013 => Ok(FlowData::Extended80211Payload(
                    parser.parse_extended_80211_payload()?,
                )),
                1014 => Ok(FlowData::Extended80211Rx(parser.parse_extended_80211_rx()?)),
                1015 => Ok(FlowData::Extended80211Tx(parser.parse_extended_80211_tx()?)),
                1016 => Ok(FlowData::Extended80211Aggregation(
                    parser.parse_extended_80211_aggregation()?,
                )),
                // Note: Format 1017 is deprecated but kept for backward compatibility
                1017 => Ok(FlowData::ExtendedOpenFlowV1(
                    parser.parse_extended_openflow_v1()?,
                )),
                1020 => Ok(FlowData::ExtendedNatPort(parser.parse_extended_nat_port()?)),
                1031 => Ok(FlowData::ExtendedInfiniBandLrh(
                    parser.parse_extended_infiniband_lrh()?,
                )),
                1032 => Ok(FlowData::ExtendedInfiniBandGrh(
                    parser.parse_extended_infiniband_grh()?,
                )),
                1033 => Ok(FlowData::ExtendedInfiniBandBth(
                    parser.parse_extended_infiniband_bth()?,
                )),
                1034 => Ok(FlowData::ExtendedVlanIn(parser.parse_extended_vlan_in()?)),
                1035 => Ok(FlowData::ExtendedVlanOut(parser.parse_extended_vlan_out()?)),
                1021 => Ok(FlowData::ExtendedL2TunnelEgress(
                    parser.parse_extended_l2_tunnel_egress()?,
                )),
                1022 => Ok(FlowData::ExtendedL2TunnelIngress(
                    parser.parse_extended_l2_tunnel_ingress()?,
                )),
                1023 => Ok(FlowData::ExtendedIpv4TunnelEgress(
                    parser.parse_extended_ipv4_tunnel_egress()?,
                )),
                1024 => Ok(FlowData::ExtendedIpv4TunnelIngress(
                    parser.parse_extended_ipv4_tunnel_ingress()?,
                )),
                1025 => Ok(FlowData::ExtendedIpv6TunnelEgress(
                    parser.parse_extended_ipv6_tunnel_egress()?,
                )),
                1026 => Ok(FlowData::ExtendedIpv6TunnelIngress(
                    parser.parse_extended_ipv6_tunnel_ingress()?,
                )),
                1027 => Ok(FlowData::ExtendedDecapsulateEgress(
                    parser.parse_extended_decapsulate_egress()?,
                )),
                1028 => Ok(FlowData::ExtendedDecapsulateIngress(
                    parser.parse_extended_decapsulate_ingress()?,
                )),
                1029 => Ok(FlowData::ExtendedVniEgress(
                    parser.parse_extended_vni_egress()?,
                )),
                1030 => Ok(FlowData::ExtendedVniIngress(
                    parser.parse_extended_vni_ingress()?,
                )),
                1036 => Ok(FlowData::ExtendedEgressQueue(
                    parser.parse_extended_egress_queue()?,
                )),
                1037 => Ok(FlowData::ExtendedAcl(parser.parse_extended_acl()?)),
                1038 => Ok(FlowData::ExtendedFunction(
                    parser.parse_extended_function()?,
                )),
                1039 => Ok(FlowData::ExtendedTransit(parser.parse_extended_transit()?)),
                1040 => Ok(FlowData::ExtendedQueue(parser.parse_extended_queue()?)),
                1041 => Ok(FlowData::ExtendedHwTrap(parser.parse_extended_hw_trap()?)),
                1042 => Ok(FlowData::ExtendedLinuxDropReason(
                    parser.parse_extended_linux_drop_reason()?,
                )),
                2000 => Ok(FlowData::Transaction(parser.parse_transaction()?)),
                2001 => Ok(FlowData::ExtendedNfsStorageTransaction(
                    parser.parse_extended_nfs_storage_transaction()?,
                )),
                2002 => Ok(FlowData::ExtendedScsiStorageTransaction(
                    parser.parse_extended_scsi_storage_transaction()?,
                )),
                2003 => Ok(FlowData::ExtendedHttpTransaction(
                    parser.parse_extended_http_transaction()?,
                )),
                2100 => Ok(FlowData::ExtendedSocketIpv4(
                    parser.parse_extended_socket_ipv4()?,
                )),
                2101 => Ok(FlowData::ExtendedSocketIpv6(
                    parser.parse_extended_socket_ipv6()?,
                )),
                2102 => Ok(FlowData::ExtendedProxySocketIpv4(
                    parser.parse_extended_proxy_socket_ipv4()?,
                )),
                2103 => Ok(FlowData::ExtendedProxySocketIpv6(
                    parser.parse_extended_proxy_socket_ipv6()?,
                )),
                2200 => Ok(FlowData::MemcacheOperation(
                    parser.parse_memcache_operation()?,
                )),
                2201 => Ok(FlowData::HttpRequestDeprecated(
                    parser.parse_http_request_deprecated()?,
                )),
                2202 => Ok(FlowData::AppOperation(parser.parse_app_operation()?)),
                2203 => Ok(FlowData::AppParentContext(
                    parser.parse_app_parent_context()?,
                )),
                2204 => Ok(FlowData::AppInitiator(parser.parse_app_initiator()?)),
                2205 => Ok(FlowData::AppTarget(parser.parse_app_target()?)),
                2206 => Ok(FlowData::HttpRequest(parser.parse_http_request()?)),
                2207 => Ok(FlowData::ExtendedProxyRequest(
                    parser.parse_extended_proxy_request()?,
                )),
                _ => Ok(FlowData::Unknown { format, data }),
            }
        } else if format.enterprise() == 4413 {
            // Broadcom enterprise formats
            match format.format() {
                1 => Ok(FlowData::ExtendedBstEgressQueue(
                    parser.parse_extended_bst_egress_queue()?,
                )),
                _ => Ok(FlowData::Unknown { format, data }),
            }
        } else {
            // Vendor-specific format
            Ok(FlowData::Unknown { format, data })
        }
    }

    /// Parse a flow record
    pub(super) fn parse_flow_record(&mut self) -> Result<FlowRecord> {
        let flow_format = self.parse_data_format()?;
        let flow_data_raw = self.read_opaque()?;
        let flow_data = self.parse_flow_data(flow_format, flow_data_raw)?;

        Ok(FlowRecord {
            flow_format,
            flow_data,
        })
    }
}
