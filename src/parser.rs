//! sFlow v5 parser
//!
//! This module provides parsing functionality for sFlow v5 datagrams.
//! All data is in network byte order (big-endian) as per XDR specification.

use crate::models::*;
use anyhow::{anyhow, Result};
use std::io::{self, Cursor, Read};
use std::net::{Ipv4Addr, Ipv6Addr};

/// Parser for sFlow v5 datagrams
pub struct Parser<R: Read> {
    reader: R,
}

impl<R: Read> Parser<R> {
    /// Create a new parser from a reader
    pub fn new(reader: R) -> Self {
        Self { reader }
    }

    /// Read a u32 in network byte order (big-endian)
    fn read_u32(&mut self) -> Result<u32> {
        let mut buf = [0u8; 4];
        self.reader.read_exact(&mut buf)?;
        Ok(u32::from_be_bytes(buf))
    }

    /// Read a u64 in network byte order (big-endian)
    fn read_u64(&mut self) -> Result<u64> {
        let mut buf = [0u8; 8];
        self.reader.read_exact(&mut buf)?;
        Ok(u64::from_be_bytes(buf))
    }

    /// Read a u8
    #[allow(dead_code)]
    fn read_u8(&mut self) -> Result<u8> {
        let mut buf = [0u8; 1];
        self.reader.read_exact(&mut buf)?;
        Ok(buf[0])
    }

    /// Read a string (length-prefixed opaque data converted to UTF-8)
    fn read_string(&mut self) -> Result<String> {
        let bytes = self.read_opaque()?;
        String::from_utf8(bytes).map_err(|e| anyhow!("Invalid UTF-8 string: {}", e))
    }

    /// Read an opaque byte array (length-prefixed)
    fn read_opaque(&mut self) -> Result<Vec<u8>> {
        let length = self.read_u32()? as usize;
        
        // Sanity check: reject unreasonably large allocations (> 100MB)
        // Valid sFlow packets are typically much smaller
        const MAX_OPAQUE_SIZE: usize = 100 * 1024 * 1024; // 100MB
        if length > MAX_OPAQUE_SIZE {
            return Err(anyhow!(
                "Opaque data length {} exceeds maximum {}",
                length,
                MAX_OPAQUE_SIZE
            ));
        }
        
        let mut data = vec![0u8; length];
        self.reader.read_exact(&mut data)?;

        // XDR requires padding to 4-byte boundary
        let padding = (4 - (length % 4)) % 4;
        if padding > 0 {
            let mut pad = vec![0u8; padding];
            self.reader.read_exact(&mut pad)?;
        }

        Ok(data)
    }

    /// Read a fixed-size byte array
    fn read_fixed(&mut self, size: usize) -> Result<Vec<u8>> {
        let mut data = vec![0u8; size];
        self.reader.read_exact(&mut data)?;
        Ok(data)
    }

    /// Parse an address
    fn parse_address(&mut self) -> Result<Address> {
        let addr_type = self.read_u32()?;

        match addr_type {
            0 => Ok(Address::Unknown),
            1 => {
                let bytes = self.read_fixed(4)?;
                let addr = Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);
                Ok(Address::IPv4(addr))
            }
            2 => {
                let bytes = self.read_fixed(16)?;
                let addr = Ipv6Addr::from(<[u8; 16]>::try_from(bytes).unwrap());
                Ok(Address::IPv6(addr))
            }
            _ => Err(anyhow!("Invalid address type: {}", addr_type)),
        }
    }

    /// Parse a data format
    fn parse_data_format(&mut self) -> Result<DataFormat> {
        let value = self.read_u32()?;
        Ok(DataFormat(value))
    }

    /// Parse a data source
    fn parse_data_source(&mut self) -> Result<DataSource> {
        let value = self.read_u32()?;
        Ok(DataSource(value))
    }

    /// Parse an expanded data source
    fn parse_data_source_expanded(&mut self) -> Result<DataSourceExpanded> {
        let source_id_type = self.read_u32()?;
        let source_id_index = self.read_u32()?;
        Ok(DataSourceExpanded {
            source_id_type,
            source_id_index,
        })
    }

    /// Parse an interface
    fn parse_interface(&mut self) -> Result<Interface> {
        let value = self.read_u32()?;
        Ok(Interface(value))
    }

    /// Parse an expanded interface
    fn parse_interface_expanded(&mut self) -> Result<InterfaceExpanded> {
        let format = self.read_u32()?;
        let value = self.read_u32()?;
        Ok(InterfaceExpanded { format, value })
    }

    /// Parse Sampled Header - Format (0,1)
    fn parse_sampled_header(&mut self) -> Result<crate::models::flow_records::SampledHeader> {
        let protocol = self.read_u32()?;
        let frame_length = self.read_u32()?;
        let stripped = self.read_u32()?;
        let header = self.read_opaque()?;

        Ok(crate::models::flow_records::SampledHeader {
            protocol,
            frame_length,
            stripped,
            header,
        })
    }

    /// Parse Sampled IPv4 - Format (0,3)
    fn parse_sampled_ipv4(&mut self) -> Result<crate::models::flow_records::SampledIpv4> {
        let length = self.read_u32()?;
        let protocol = self.read_u32()?;
        let src_ip = Ipv4Addr::from(self.read_u32()?);
        let dst_ip = Ipv4Addr::from(self.read_u32()?);
        let src_port = self.read_u32()?;
        let dst_port = self.read_u32()?;
        let tcp_flags = self.read_u32()?;
        let tos = self.read_u32()?;

        Ok(crate::models::flow_records::SampledIpv4 {
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
    fn parse_sampled_ipv6(&mut self) -> Result<crate::models::flow_records::SampledIpv6> {
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

        Ok(crate::models::flow_records::SampledIpv6 {
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
    fn parse_extended_switch(&mut self) -> Result<crate::models::flow_records::ExtendedSwitch> {
        let src_vlan = self.read_u32()?;
        let src_priority = self.read_u32()?;
        let dst_vlan = self.read_u32()?;
        let dst_priority = self.read_u32()?;

        Ok(crate::models::flow_records::ExtendedSwitch {
            src_vlan,
            src_priority,
            dst_vlan,
            dst_priority,
        })
    }

    /// Parse Extended Router - Format (0,1002)
    fn parse_extended_router(&mut self) -> Result<crate::models::flow_records::ExtendedRouter> {
        let next_hop = self.parse_address()?;
        let src_mask_len = self.read_u32()?;
        let dst_mask_len = self.read_u32()?;

        Ok(crate::models::flow_records::ExtendedRouter {
            next_hop,
            src_mask_len,
            dst_mask_len,
        })
    }

    /// Parse Extended Gateway - Format (0,1004)
    fn parse_extended_gateway(&mut self) -> Result<crate::models::flow_records::ExtendedGateway> {
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
            as_path_segments.push(crate::models::flow_records::AsPathSegment {
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

        Ok(crate::models::flow_records::ExtendedGateway {
            next_hop,
            as_number,
            src_as,
            src_peer_as,
            as_path_segments,
            communities,
            local_pref,
        })
    }

    /// Parse Sampled Ethernet - Format (0,2)
    fn parse_sampled_ethernet(&mut self) -> Result<crate::models::flow_records::SampledEthernet> {
        let length = self.read_u32()?;

        let mut src_mac = [0u8; 6];
        self.reader.read_exact(&mut src_mac)?;
        let mut dst_mac = [0u8; 6];
        self.reader.read_exact(&mut dst_mac)?;

        let eth_type = self.read_u32()?;

        Ok(crate::models::flow_records::SampledEthernet {
            length,
            src_mac,
            dst_mac,
            eth_type,
        })
    }

    /// Parse Extended User - Format (0,1005)
    fn parse_extended_user(&mut self) -> Result<crate::models::flow_records::ExtendedUser> {
        let src_charset = self.read_u32()?;
        let src_user = self.read_string()?;
        let dst_charset = self.read_u32()?;
        let dst_user = self.read_string()?;

        Ok(crate::models::flow_records::ExtendedUser {
            src_charset,
            src_user,
            dst_charset,
            dst_user,
        })
    }

    /// Parse Extended URL - Format (0,1006)
    fn parse_extended_url(&mut self) -> Result<crate::models::flow_records::ExtendedUrl> {
        let direction = self.read_u32()?;
        let url = self.read_string()?;
        let host = self.read_string()?;

        Ok(crate::models::flow_records::ExtendedUrl {
            direction,
            url,
            host,
        })
    }

    /// Parse Extended MPLS - Format (0,1007)
    fn parse_extended_mpls(&mut self) -> Result<crate::models::flow_records::ExtendedMpls> {
        let next_hop = self.parse_address()?;

        let in_label_stack_len = self.read_u32()?;
        let capacity_in = in_label_stack_len.min(1024) as usize;
        let mut in_label_stack = Vec::with_capacity(capacity_in);
        for _ in 0..in_label_stack_len {
            in_label_stack.push(self.read_u32()?);
        }

        let out_label_stack_len = self.read_u32()?;
        let capacity_out = out_label_stack_len.min(1024) as usize;
        let mut out_label_stack = Vec::with_capacity(capacity_out);
        for _ in 0..out_label_stack_len {
            out_label_stack.push(self.read_u32()?);
        }

        Ok(crate::models::flow_records::ExtendedMpls {
            next_hop,
            in_label_stack,
            out_label_stack,
        })
    }

    /// Parse Extended NAT - Format (0,1008)
    fn parse_extended_nat(&mut self) -> Result<crate::models::flow_records::ExtendedNat> {
        let src_address = self.parse_address()?;
        let dst_address = self.parse_address()?;

        Ok(crate::models::flow_records::ExtendedNat {
            src_address,
            dst_address,
        })
    }

    /// Parse Extended MPLS Tunnel - Format (0,1009)
    fn parse_extended_mpls_tunnel(
        &mut self,
    ) -> Result<crate::models::flow_records::ExtendedMplsTunnel> {
        let tunnel_name = self.read_string()?;
        let tunnel_id = self.read_u32()?;
        let tunnel_cos = self.read_u32()?;

        Ok(crate::models::flow_records::ExtendedMplsTunnel {
            tunnel_name,
            tunnel_id,
            tunnel_cos,
        })
    }

    /// Parse Extended MPLS VC - Format (0,1010)
    fn parse_extended_mpls_vc(&mut self) -> Result<crate::models::flow_records::ExtendedMplsVc> {
        let vc_instance_name = self.read_string()?;
        let vll_vc_id = self.read_u32()?;
        let vc_label = self.read_u32()?;
        let vc_cos = self.read_u32()?;

        Ok(crate::models::flow_records::ExtendedMplsVc {
            vc_instance_name,
            vll_vc_id,
            vc_label,
            vc_cos,
        })
    }

    /// Parse Extended MPLS FEC - Format (0,1011)
    fn parse_extended_mpls_fec(&mut self) -> Result<crate::models::flow_records::ExtendedMplsFec> {
        let fec_addr_prefix = self.parse_address()?;
        let fec_prefix_len = self.read_u32()?;

        Ok(crate::models::flow_records::ExtendedMplsFec {
            fec_addr_prefix,
            fec_prefix_len,
        })
    }

    /// Parse Extended MPLS LVP FEC - Format (0,1012)
    fn parse_extended_mpls_lvp_fec(
        &mut self,
    ) -> Result<crate::models::flow_records::ExtendedMplsLvpFec> {
        let fec_addr_prefix_len = self.read_u32()?;

        Ok(crate::models::flow_records::ExtendedMplsLvpFec {
            fec_addr_prefix_len,
        })
    }

    /// Parse Extended VLAN Tunnel - Format (0,1013)
    fn parse_extended_vlan_tunnel(
        &mut self,
    ) -> Result<crate::models::flow_records::ExtendedVlanTunnel> {
        let num_vlans = self.read_u32()?;
        let capacity = num_vlans.min(1024) as usize;
        let mut vlan_stack = Vec::with_capacity(capacity);
        for _ in 0..num_vlans {
            vlan_stack.push(self.read_u32()?);
        }

        Ok(crate::models::flow_records::ExtendedVlanTunnel { vlan_stack })
    }

    /// Parse Extended 802.11 Payload - Format (0,1014)
    fn parse_extended_80211_payload(
        &mut self,
    ) -> Result<crate::models::flow_records::Extended80211Payload> {
        let cipher_suite = self.read_u32()?;
        let rssi = self.read_u32()?;
        let noise = self.read_u32()?;
        let channel = self.read_u32()?;
        let speed = self.read_u32()?;

        Ok(crate::models::flow_records::Extended80211Payload {
            cipher_suite,
            rssi,
            noise,
            channel,
            speed,
        })
    }

    /// Parse Extended 802.11 RX - Format (0,1015)
    fn parse_extended_80211_rx(&mut self) -> Result<crate::models::flow_records::Extended80211Rx> {
        let ssid = self.read_string()?;

        let mut bssid = [0u8; 6];
        self.reader.read_exact(&mut bssid)?;

        let version = self.read_u32()?;
        let channel = self.read_u32()?;
        let speed = self.read_u64()?;
        let rssi = self.read_u32()?;
        let noise = self.read_u32()?;

        Ok(crate::models::flow_records::Extended80211Rx {
            ssid,
            bssid,
            version,
            channel,
            speed,
            rssi,
            noise,
        })
    }

    /// Parse Extended 802.11 TX - Format (0,1016)
    fn parse_extended_80211_tx(&mut self) -> Result<crate::models::flow_records::Extended80211Tx> {
        let ssid = self.read_string()?;

        let mut bssid = [0u8; 6];
        self.reader.read_exact(&mut bssid)?;

        let version = self.read_u32()?;
        let transmissions = self.read_u32()?;
        let packet_duration = self.read_u32()?;
        let retrans_duration = self.read_u32()?;
        let channel = self.read_u32()?;
        let speed = self.read_u64()?;
        let power = self.read_u32()?;

        Ok(crate::models::flow_records::Extended80211Tx {
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

    /// Parse flow data based on format
    fn parse_flow_data(&mut self, format: DataFormat, data: Vec<u8>) -> Result<FlowData> {
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
                1004 => Ok(FlowData::ExtendedGateway(parser.parse_extended_gateway()?)),
                1005 => Ok(FlowData::ExtendedUser(parser.parse_extended_user()?)),
                1006 => Ok(FlowData::ExtendedUrl(parser.parse_extended_url()?)),
                1007 => Ok(FlowData::ExtendedMpls(parser.parse_extended_mpls()?)),
                1008 => Ok(FlowData::ExtendedNat(parser.parse_extended_nat()?)),
                1009 => Ok(FlowData::ExtendedMplsTunnel(
                    parser.parse_extended_mpls_tunnel()?,
                )),
                1010 => Ok(FlowData::ExtendedMplsVc(parser.parse_extended_mpls_vc()?)),
                1011 => Ok(FlowData::ExtendedMplsFec(parser.parse_extended_mpls_fec()?)),
                1012 => Ok(FlowData::ExtendedMplsLvpFec(
                    parser.parse_extended_mpls_lvp_fec()?,
                )),
                1013 => Ok(FlowData::ExtendedVlanTunnel(
                    parser.parse_extended_vlan_tunnel()?,
                )),
                1014 => Ok(FlowData::Extended80211Payload(
                    parser.parse_extended_80211_payload()?,
                )),
                1015 => Ok(FlowData::Extended80211Rx(parser.parse_extended_80211_rx()?)),
                1016 => Ok(FlowData::Extended80211Tx(parser.parse_extended_80211_tx()?)),
                _ => Ok(FlowData::Unknown { format, data }),
            }
        } else {
            // Vendor-specific format
            Ok(FlowData::Unknown { format, data })
        }
    }

    /// Parse a flow record
    fn parse_flow_record(&mut self) -> Result<FlowRecord> {
        let flow_format = self.parse_data_format()?;
        let flow_data_raw = self.read_opaque()?;
        let flow_data = self.parse_flow_data(flow_format, flow_data_raw)?;

        Ok(FlowRecord {
            flow_format,
            flow_data,
        })
    }

    /// Parse Generic Interface Counters - Format (0,1)
    fn parse_generic_interface_counters(
        &mut self,
    ) -> Result<crate::models::counter_records::GenericInterfaceCounters> {
        let if_index = self.read_u32()?;
        let if_type = self.read_u32()?;
        let if_speed = self.read_u64()?;
        let if_direction = self.read_u32()?;
        let if_status = self.read_u32()?;
        let if_in_octets = self.read_u64()?;
        let if_in_ucast_pkts = self.read_u32()?;
        let if_in_multicast_pkts = self.read_u32()?;
        let if_in_broadcast_pkts = self.read_u32()?;
        let if_in_discards = self.read_u32()?;
        let if_in_errors = self.read_u32()?;
        let if_in_unknown_protos = self.read_u32()?;
        let if_out_octets = self.read_u64()?;
        let if_out_ucast_pkts = self.read_u32()?;
        let if_out_multicast_pkts = self.read_u32()?;
        let if_out_broadcast_pkts = self.read_u32()?;
        let if_out_discards = self.read_u32()?;
        let if_out_errors = self.read_u32()?;
        let if_promiscuous_mode = self.read_u32()?;

        Ok(crate::models::counter_records::GenericInterfaceCounters {
            if_index,
            if_type,
            if_speed,
            if_direction,
            if_status,
            if_in_octets,
            if_in_ucast_pkts,
            if_in_multicast_pkts,
            if_in_broadcast_pkts,
            if_in_discards,
            if_in_errors,
            if_in_unknown_protos,
            if_out_octets,
            if_out_ucast_pkts,
            if_out_multicast_pkts,
            if_out_broadcast_pkts,
            if_out_discards,
            if_out_errors,
            if_promiscuous_mode,
        })
    }

    /// Parse Ethernet Interface Counters - Format (0,2)
    fn parse_ethernet_interface_counters(
        &mut self,
    ) -> Result<crate::models::counter_records::EthernetInterfaceCounters> {
        Ok(crate::models::counter_records::EthernetInterfaceCounters {
            dot3_stats_alignment_errors: self.read_u32()?,
            dot3_stats_fcs_errors: self.read_u32()?,
            dot3_stats_single_collision_frames: self.read_u32()?,
            dot3_stats_multiple_collision_frames: self.read_u32()?,
            dot3_stats_sqe_test_errors: self.read_u32()?,
            dot3_stats_deferred_transmissions: self.read_u32()?,
            dot3_stats_late_collisions: self.read_u32()?,
            dot3_stats_excessive_collisions: self.read_u32()?,
            dot3_stats_internal_mac_transmit_errors: self.read_u32()?,
            dot3_stats_carrier_sense_errors: self.read_u32()?,
            dot3_stats_frame_too_longs: self.read_u32()?,
            dot3_stats_internal_mac_receive_errors: self.read_u32()?,
            dot3_stats_symbol_errors: self.read_u32()?,
        })
    }

    /// Parse Processor Counters - Format (0,1001)
    fn parse_processor_counters(
        &mut self,
    ) -> Result<crate::models::counter_records::ProcessorCounters> {
        Ok(crate::models::counter_records::ProcessorCounters {
            cpu_5s: self.read_u32()?,
            cpu_1m: self.read_u32()?,
            cpu_5m: self.read_u32()?,
            total_memory: self.read_u64()?,
            free_memory: self.read_u64()?,
        })
    }

    /// Parse Host Description - Format (0,2000)
    fn parse_host_description(
        &mut self,
    ) -> Result<crate::models::counter_records::HostDescription> {
        let hostname = self.read_string()?;
        let mut uuid = [0u8; 16];
        self.reader.read_exact(&mut uuid)?;
        let machine_type = self.read_string()?;
        let os_name = self.read_string()?;
        let os_release = self.read_string()?;

        Ok(crate::models::counter_records::HostDescription {
            hostname,
            uuid,
            machine_type,
            os_name,
            os_release,
        })
    }

    /// Parse Host Adapters - Format (0,2001)
    fn parse_host_adapters(&mut self) -> Result<crate::models::counter_records::HostAdapters> {
        let num_adapters = self.read_u32()?;
        let capacity_adapters = num_adapters.min(1024) as usize;
        let mut adapters = Vec::with_capacity(capacity_adapters);

        for _ in 0..num_adapters {
            let if_index = self.read_u32()?;
            let num_macs = self.read_u32()?;
            let capacity_macs = num_macs.min(1024) as usize;
            let mut mac_addresses = Vec::with_capacity(capacity_macs);

            for _ in 0..num_macs {
                let mut mac = [0u8; 6];
                self.reader.read_exact(&mut mac)?;
                mac_addresses.push(mac);
            }

            adapters.push(crate::models::counter_records::HostAdapter {
                if_index,
                mac_addresses,
            });
        }

        Ok(crate::models::counter_records::HostAdapters { adapters })
    }

    /// Parse Host CPU - Format (0,2003)
    fn parse_host_cpu(&mut self) -> Result<crate::models::counter_records::HostCpu> {
        Ok(crate::models::counter_records::HostCpu {
            load_one: self.read_u32()?,
            load_five: self.read_u32()?,
            load_fifteen: self.read_u32()?,
            proc_run: self.read_u32()?,
            proc_total: self.read_u32()?,
            cpu_num: self.read_u32()?,
            cpu_speed: self.read_u32()?,
            uptime: self.read_u32()?,
            cpu_user: self.read_u32()?,
            cpu_nice: self.read_u32()?,
            cpu_system: self.read_u32()?,
            cpu_idle: self.read_u32()?,
            cpu_wio: self.read_u32()?,
            cpu_intr: self.read_u32()?,
            cpu_sintr: self.read_u32()?,
            interrupts: self.read_u32()?,
            contexts: self.read_u32()?,
        })
    }

    /// Parse Host Memory - Format (0,2004)
    fn parse_host_memory(&mut self) -> Result<crate::models::counter_records::HostMemory> {
        Ok(crate::models::counter_records::HostMemory {
            mem_total: self.read_u64()?,
            mem_free: self.read_u64()?,
            mem_shared: self.read_u64()?,
            mem_buffers: self.read_u64()?,
            mem_cached: self.read_u64()?,
            swap_total: self.read_u64()?,
            swap_free: self.read_u64()?,
            page_in: self.read_u32()?,
            page_out: self.read_u32()?,
            swap_in: self.read_u32()?,
            swap_out: self.read_u32()?,
        })
    }

    /// Parse Host Disk I/O - Format (0,2005)
    fn parse_host_disk_io(&mut self) -> Result<crate::models::counter_records::HostDiskIo> {
        Ok(crate::models::counter_records::HostDiskIo {
            disk_total: self.read_u64()?,
            disk_free: self.read_u64()?,
            part_max_used: self.read_u32()?,
            reads: self.read_u32()?,
            bytes_read: self.read_u64()?,
            read_time: self.read_u32()?,
            writes: self.read_u32()?,
            bytes_written: self.read_u64()?,
            write_time: self.read_u32()?,
        })
    }

    /// Parse Host Network I/O - Format (0,2006)
    fn parse_host_net_io(&mut self) -> Result<crate::models::counter_records::HostNetIo> {
        Ok(crate::models::counter_records::HostNetIo {
            bytes_in: self.read_u64()?,
            pkts_in: self.read_u32()?,
            errs_in: self.read_u32()?,
            drops_in: self.read_u32()?,
            bytes_out: self.read_u64()?,
            pkts_out: self.read_u32()?,
            errs_out: self.read_u32()?,
            drops_out: self.read_u32()?,
        })
    }

    /// Parse counter data based on format
    fn parse_counter_data(&mut self, format: DataFormat, data: Vec<u8>) -> Result<CounterData> {
        let mut cursor = Cursor::new(data.clone());
        let mut parser = Parser::new(&mut cursor);

        // Standard sFlow formats (enterprise = 0)
        if format.enterprise() == 0 {
            match format.format() {
                1 => Ok(CounterData::GenericInterface(
                    parser.parse_generic_interface_counters()?,
                )),
                2 => Ok(CounterData::EthernetInterface(
                    parser.parse_ethernet_interface_counters()?,
                )),
                1001 => Ok(CounterData::Processor(parser.parse_processor_counters()?)),
                2000 => Ok(CounterData::HostDescription(
                    parser.parse_host_description()?,
                )),
                2001 => Ok(CounterData::HostAdapters(parser.parse_host_adapters()?)),
                2003 => Ok(CounterData::HostCpu(parser.parse_host_cpu()?)),
                2004 => Ok(CounterData::HostMemory(parser.parse_host_memory()?)),
                2005 => Ok(CounterData::HostDiskIo(parser.parse_host_disk_io()?)),
                2006 => Ok(CounterData::HostNetIo(parser.parse_host_net_io()?)),
                _ => Ok(CounterData::Unknown { format, data }),
            }
        } else {
            // Vendor-specific format
            Ok(CounterData::Unknown { format, data })
        }
    }

    /// Parse a counter record
    fn parse_counter_record(&mut self) -> Result<CounterRecord> {
        let counter_format = self.parse_data_format()?;
        let counter_data_raw = self.read_opaque()?;
        let counter_data = self.parse_counter_data(counter_format, counter_data_raw)?;

        Ok(CounterRecord {
            counter_format,
            counter_data,
        })
    }

    /// Parse a compact flow sample
    fn parse_flow_sample(&mut self) -> Result<FlowSample> {
        let sequence_number = self.read_u32()?;
        let source_id = self.parse_data_source()?;
        let sampling_rate = self.read_u32()?;
        let sample_pool = self.read_u32()?;
        let drops = self.read_u32()?;
        let input = self.parse_interface()?;
        let output = self.parse_interface()?;

        // Parse flow records array
        let num_records = self.read_u32()?;
        // Limit capacity to prevent OOM attacks - allocate conservatively
        let capacity = num_records.min(1024) as usize;
        let mut flow_records = Vec::with_capacity(capacity);
        for _ in 0..num_records {
            flow_records.push(self.parse_flow_record()?);
        }

        Ok(FlowSample {
            sequence_number,
            source_id,
            sampling_rate,
            sample_pool,
            drops,
            input,
            output,
            flow_records,
        })
    }

    /// Parse a compact counter sample
    fn parse_counters_sample(&mut self) -> Result<CountersSample> {
        let sequence_number = self.read_u32()?;
        let source_id = self.parse_data_source()?;

        // Parse counter records array
        let num_records = self.read_u32()?;
        // Limit capacity to prevent OOM attacks - allocate conservatively
        let capacity = num_records.min(1024) as usize;
        let mut counters = Vec::with_capacity(capacity);
        for _ in 0..num_records {
            counters.push(self.parse_counter_record()?);
        }

        Ok(CountersSample {
            sequence_number,
            source_id,
            counters,
        })
    }

    /// Parse an expanded flow sample
    fn parse_flow_sample_expanded(&mut self) -> Result<FlowSampleExpanded> {
        let sequence_number = self.read_u32()?;
        let source_id = self.parse_data_source_expanded()?;
        let sampling_rate = self.read_u32()?;
        let sample_pool = self.read_u32()?;
        let drops = self.read_u32()?;
        let input = self.parse_interface_expanded()?;
        let output = self.parse_interface_expanded()?;

        // Parse flow records array
        let num_records = self.read_u32()?;
        // Limit capacity to prevent OOM attacks - allocate conservatively
        let capacity = num_records.min(1024) as usize;
        let mut flow_records = Vec::with_capacity(capacity);
        for _ in 0..num_records {
            flow_records.push(self.parse_flow_record()?);
        }

        Ok(FlowSampleExpanded {
            sequence_number,
            source_id,
            sampling_rate,
            sample_pool,
            drops,
            input,
            output,
            flow_records,
        })
    }

    /// Parse an expanded counter sample
    fn parse_counters_sample_expanded(&mut self) -> Result<CountersSampleExpanded> {
        let sequence_number = self.read_u32()?;
        let source_id = self.parse_data_source_expanded()?;

        // Parse counter records array
        let num_records = self.read_u32()?;
        // Limit capacity to prevent OOM attacks - allocate conservatively
        let capacity = num_records.min(1024) as usize;
        let mut counters = Vec::with_capacity(capacity);
        for _ in 0..num_records {
            counters.push(self.parse_counter_record()?);
        }

        Ok(CountersSampleExpanded {
            sequence_number,
            source_id,
            counters,
        })
    }

    /// Parse sample data based on format
    fn parse_sample_data(&mut self, format: DataFormat, data: Vec<u8>) -> Result<SampleData> {
        let mut cursor = Cursor::new(data.clone());
        let mut parser = Parser::new(&mut cursor);

        // Standard sFlow formats (enterprise = 0)
        if format.enterprise() == 0 {
            match format.format() {
                1 => {
                    let sample = parser.parse_flow_sample()?;
                    Ok(SampleData::FlowSample(sample))
                }
                2 => {
                    let sample = parser.parse_counters_sample()?;
                    Ok(SampleData::CountersSample(sample))
                }
                3 => {
                    let sample = parser.parse_flow_sample_expanded()?;
                    Ok(SampleData::FlowSampleExpanded(sample))
                }
                4 => {
                    let sample = parser.parse_counters_sample_expanded()?;
                    Ok(SampleData::CountersSampleExpanded(sample))
                }
                _ => Ok(SampleData::Unknown { format, data }),
            }
        } else {
            // Vendor-specific format
            Ok(SampleData::Unknown { format, data })
        }
    }

    /// Parse a sample record
    fn parse_sample_record(&mut self) -> Result<SampleRecord> {
        let sample_type = self.parse_data_format()?;
        let sample_data_raw = self.read_opaque()?;
        let sample_data = self.parse_sample_data(sample_type, sample_data_raw)?;

        Ok(SampleRecord {
            sample_type,
            sample_data,
        })
    }

    /// Parse an sFlow v5 datagram
    pub fn parse_datagram(&mut self) -> Result<SFlowDatagram> {
        // Parse version
        let version = self.read_u32()?;
        if version != 5 {
            return Err(anyhow!("Invalid version: expected 5, got {}", version));
        }

        // Parse agent address
        let agent_address = self.parse_address()?;

        // Parse sub-agent ID
        let sub_agent_id = self.read_u32()?;

        // Parse sequence number
        let sequence_number = self.read_u32()?;

        // Parse uptime
        let uptime = self.read_u32()?;

        // Parse samples array
        let num_samples = self.read_u32()?;
        // Limit capacity to prevent OOM attacks - allocate conservatively
        let capacity = num_samples.min(1024) as usize;
        let mut samples = Vec::with_capacity(capacity);
        for _ in 0..num_samples {
            samples.push(self.parse_sample_record()?);
        }

        Ok(SFlowDatagram {
            version: DatagramVersion::Version5,
            agent_address,
            sub_agent_id,
            sequence_number,
            uptime,
            samples,
        })
    }
}

/// Parse an sFlow v5 datagram from a byte slice
pub fn parse_datagram(data: &[u8]) -> Result<SFlowDatagram> {
    let mut parser = Parser::new(Cursor::new(data));
    parser.parse_datagram()
}

/// Parse multiple sFlow v5 datagrams from a byte slice
/// This is useful when multiple datagrams are concatenated (like in our test file)
pub fn parse_datagrams(data: &[u8]) -> Result<Vec<SFlowDatagram>> {
    let mut datagrams = Vec::new();
    let mut cursor = Cursor::new(data);

    loop {
        let pos = cursor.position();
        if pos >= data.len() as u64 {
            break;
        }

        match Parser::new(&mut cursor).parse_datagram() {
            Ok(datagram) => datagrams.push(datagram),
            Err(e)
                if e.downcast_ref::<io::Error>()
                    .map(|e| e.kind() == io::ErrorKind::UnexpectedEof)
                    .unwrap_or(false) =>
            {
                // End of data
                break;
            }
            Err(e) => return Err(e),
        }
    }

    Ok(datagrams)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_format() {
        let format = DataFormat::new(0, 1);
        assert_eq!(format.enterprise(), 0);
        assert_eq!(format.format(), 1);

        let format = DataFormat::new(4413, 5);
        assert_eq!(format.enterprise(), 4413);
        assert_eq!(format.format(), 5);
    }

    #[test]
    fn test_data_source() {
        let source = DataSource::new(0, 42);
        assert_eq!(source.source_type(), 0);
        assert_eq!(source.index(), 42);

        let source = DataSource::new(1, 100);
        assert_eq!(source.source_type(), 1);
        assert_eq!(source.index(), 100);
    }

    #[test]
    fn test_interface() {
        // Single interface
        let iface = Interface(42);
        assert!(iface.is_single());
        assert_eq!(iface.value(), 42);

        // Discarded packet
        let iface = Interface(0x40000001);
        assert!(iface.is_discarded());
        assert_eq!(iface.value(), 1);

        // Multiple interfaces
        let iface = Interface(0x80000007);
        assert!(iface.is_multiple());
        assert_eq!(iface.value(), 7);
    }

    #[test]
    fn test_parse_u32() {
        let data = vec![0x00, 0x00, 0x00, 0x05];
        let mut parser = Parser::new(Cursor::new(data));
        assert_eq!(parser.read_u32().unwrap(), 5);
    }

    #[test]
    fn test_parse_address_ipv4() {
        let data = vec![
            0x00, 0x00, 0x00, 0x01, // type = IPv4
            0xC0, 0xA8, 0x01, 0x01, // 192.168.1.1
        ];
        let mut parser = Parser::new(Cursor::new(data));
        let addr = parser.parse_address().unwrap();
        assert_eq!(addr, Address::IPv4(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn test_parse_address_unknown() {
        let data = vec![0x00, 0x00, 0x00, 0x00]; // type = Unknown
        let mut parser = Parser::new(Cursor::new(data));
        let addr = parser.parse_address().unwrap();
        assert_eq!(addr, Address::Unknown);
    }
}
