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
        let mut as_path_segments = Vec::with_capacity(capacity_segments);
        for _ in 0..num_segments {
            let path_type = self.read_u32()?;
            let path_length = self.read_u32()?;
            let capacity_path = path_length.min(1024) as usize;
            let mut path = Vec::with_capacity(capacity_path);
            for _ in 0..path_length {
                path.push(self.read_u32()?);
            }
            as_path_segments.push(crate::models::record_flows::AsPathSegment {
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
            as_path_segments,
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
        let mut vlan_stack = Vec::with_capacity(capacity);
        for _ in 0..num_vlans {
            vlan_stack.push(self.read_u32()?);
        }

        Ok(crate::models::record_flows::ExtendedVlanTunnel { vlan_stack })
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
                2100 => Ok(FlowData::ExtendedSocketIpv4(
                    parser.parse_extended_socket_ipv4()?,
                )),
                2101 => Ok(FlowData::ExtendedSocketIpv6(
                    parser.parse_extended_socket_ipv6()?,
                )),
                2202 => Ok(FlowData::AppOperation(parser.parse_app_operation()?)),
                2203 => Ok(FlowData::AppParentContext(
                    parser.parse_app_parent_context()?,
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
