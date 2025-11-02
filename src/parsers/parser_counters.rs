//! Counter record parsers
//!
//! This module contains all parsing functions for sFlow counter records.

use super::error::Result;
use super::Parser;
use crate::models::*;
use std::io::{Cursor, Read};

impl<R: Read> Parser<R> {
    /// Parse Generic Interface Counters - Format (0,1)
    pub(super) fn parse_generic_interface_counters(
        &mut self,
    ) -> Result<crate::models::record_counters::GenericInterfaceCounters> {
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

        Ok(crate::models::record_counters::GenericInterfaceCounters {
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
    pub(super) fn parse_ethernet_interface_counters(
        &mut self,
    ) -> Result<crate::models::record_counters::EthernetInterfaceCounters> {
        Ok(crate::models::record_counters::EthernetInterfaceCounters {
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

    /// Parse Token Ring Counters - Format (0,3)
    pub(super) fn parse_token_ring_counters(
        &mut self,
    ) -> Result<crate::models::record_counters::TokenRingCounters> {
        Ok(crate::models::record_counters::TokenRingCounters {
            dot5_stats_line_errors: self.read_u32()?,
            dot5_stats_burst_errors: self.read_u32()?,
            dot5_stats_ac_errors: self.read_u32()?,
            dot5_stats_abort_trans_errors: self.read_u32()?,
            dot5_stats_internal_errors: self.read_u32()?,
            dot5_stats_lost_frame_errors: self.read_u32()?,
            dot5_stats_receive_congestions: self.read_u32()?,
            dot5_stats_frame_copied_errors: self.read_u32()?,
            dot5_stats_token_errors: self.read_u32()?,
            dot5_stats_soft_errors: self.read_u32()?,
            dot5_stats_hard_errors: self.read_u32()?,
            dot5_stats_signal_loss: self.read_u32()?,
            dot5_stats_transmit_beacons: self.read_u32()?,
            dot5_stats_recoverys: self.read_u32()?,
            dot5_stats_lobe_wires: self.read_u32()?,
            dot5_stats_removes: self.read_u32()?,
            dot5_stats_singles: self.read_u32()?,
            dot5_stats_freq_errors: self.read_u32()?,
        })
    }

    /// Parse 100BaseVG Interface Counters - Format (0,4)
    pub(super) fn parse_vg100_interface_counters(
        &mut self,
    ) -> Result<crate::models::record_counters::Vg100InterfaceCounters> {
        Ok(crate::models::record_counters::Vg100InterfaceCounters {
            dot12_in_high_priority_frames: self.read_u32()?,
            dot12_in_high_priority_octets: self.read_u64()?,
            dot12_in_norm_priority_frames: self.read_u32()?,
            dot12_in_norm_priority_octets: self.read_u64()?,
            dot12_in_ipm_errors: self.read_u32()?,
            dot12_in_oversize_frame_errors: self.read_u32()?,
            dot12_in_data_errors: self.read_u32()?,
            dot12_in_null_addressed_frames: self.read_u32()?,
            dot12_out_high_priority_frames: self.read_u32()?,
            dot12_out_high_priority_octets: self.read_u64()?,
            dot12_transition_into_trainings: self.read_u32()?,
            dot12_hc_in_high_priority_octets: self.read_u64()?,
            dot12_hc_in_norm_priority_octets: self.read_u64()?,
            dot12_hc_out_high_priority_octets: self.read_u64()?,
        })
    }

    /// Parse VLAN Counters - Format (0,5)
    pub(super) fn parse_vlan_counters(
        &mut self,
    ) -> Result<crate::models::record_counters::VlanCounters> {
        Ok(crate::models::record_counters::VlanCounters {
            vlan_id: self.read_u32()?,
            octets: self.read_u64()?,
            ucast_pkts: self.read_u32()?,
            multicast_pkts: self.read_u32()?,
            broadcast_pkts: self.read_u32()?,
            discards: self.read_u32()?,
        })
    }

    /// Parse IEEE 802.11 Counters - Format (0,6)
    pub(super) fn parse_ieee80211_counters(
        &mut self,
    ) -> Result<crate::models::record_counters::Ieee80211Counters> {
        Ok(crate::models::record_counters::Ieee80211Counters {
            dot11_transmitted_fragment_count: self.read_u32()?,
            dot11_multicast_transmitted_frame_count: self.read_u32()?,
            dot11_failed_count: self.read_u32()?,
            dot11_retry_count: self.read_u32()?,
            dot11_multiple_retry_count: self.read_u32()?,
            dot11_frame_duplicate_count: self.read_u32()?,
            dot11_rts_success_count: self.read_u32()?,
            dot11_rts_failure_count: self.read_u32()?,
            dot11_ack_failure_count: self.read_u32()?,
            dot11_received_fragment_count: self.read_u32()?,
            dot11_multicast_received_frame_count: self.read_u32()?,
            dot11_fcs_error_count: self.read_u32()?,
            dot11_transmitted_frame_count: self.read_u32()?,
            dot11_wep_undecryptable_count: self.read_u32()?,
            dot11_qos_discarded_fragment_count: self.read_u32()?,
            dot11_associated_station_count: self.read_u32()?,
            dot11_qos_cf_polls_received_count: self.read_u32()?,
            dot11_qos_cf_polls_unused_count: self.read_u32()?,
            dot11_qos_cf_polls_unusable_count: self.read_u32()?,
            dot11_qos_cf_polls_lost_count: self.read_u32()?,
        })
    }

    /// Parse LAG Port Statistics - Format (0,7)
    pub(super) fn parse_lag_port_stats(
        &mut self,
    ) -> Result<crate::models::record_counters::LagPortStats> {
        // Read actor system ID (MAC address - 6 bytes)
        let mut actor_system_id = [0u8; 6];
        self.reader.read_exact(&mut actor_system_id)?;

        // Read partner operational system ID (MAC address - 6 bytes)
        let mut partner_oper_system_id = [0u8; 6];
        self.reader.read_exact(&mut partner_oper_system_id)?;

        // Read attached aggregator ID
        let dot3ad_agg_port_attached_agg_id = self.read_u32()?;

        // Read port state (4 bytes fixed array)
        let mut dot3ad_agg_port_state = [0u8; 4];
        self.reader.read_exact(&mut dot3ad_agg_port_state)?;

        Ok(crate::models::record_counters::LagPortStats {
            dot3ad_agg_port_actor_system_id: crate::models::MacAddress::from(actor_system_id),
            dot3ad_agg_port_partner_oper_system_id: crate::models::MacAddress::from(
                partner_oper_system_id,
            ),
            dot3ad_agg_port_attached_agg_id,
            dot3ad_agg_port_state,
            dot3ad_agg_port_stats_lacpd_us_rx: self.read_u32()?,
            dot3ad_agg_port_stats_marker_pdus_rx: self.read_u32()?,
            dot3ad_agg_port_stats_marker_response_pdus_rx: self.read_u32()?,
            dot3ad_agg_port_stats_unknown_rx: self.read_u32()?,
            dot3ad_agg_port_stats_illegal_rx: self.read_u32()?,
            dot3ad_agg_port_stats_lacpd_us_tx: self.read_u32()?,
            dot3ad_agg_port_stats_marker_pdus_tx: self.read_u32()?,
            dot3ad_agg_port_stats_marker_response_pdus_tx: self.read_u32()?,
        })
    }

    /// Parse InfiniBand Counters - Format (0,9)
    pub(super) fn parse_infiniband_counters(
        &mut self,
    ) -> Result<crate::models::record_counters::InfiniBandCounters> {
        Ok(crate::models::record_counters::InfiniBandCounters {
            port_xmit_pkts: self.read_u64()?,
            port_rcv_pkts: self.read_u64()?,
            symbol_error_counter: self.read_u32()?,
            link_error_recovery_counter: self.read_u32()?,
            link_downed_counter: self.read_u32()?,
            port_rcv_errors: self.read_u32()?,
            port_rcv_remote_physical_errors: self.read_u32()?,
            port_rcv_switch_relay_errors: self.read_u32()?,
            port_xmit_discards: self.read_u32()?,
            port_xmit_constraint_errors: self.read_u32()?,
            port_rcv_constraint_errors: self.read_u32()?,
            local_link_integrity_errors: self.read_u32()?,
            excessive_buffer_overrun_errors: self.read_u32()?,
            vl15_dropped: self.read_u32()?,
        })
    }

    /// Parse Optical Lane
    fn parse_lane(&mut self) -> Result<crate::models::record_counters::Lane> {
        Ok(crate::models::record_counters::Lane {
            index: self.read_u32()?,
            tx_bias_current: self.read_u32()?,
            tx_power: self.read_u32()?,
            tx_power_min: self.read_u32()?,
            tx_power_max: self.read_u32()?,
            tx_wavelength: self.read_u32()?,
            rx_power: self.read_u32()?,
            rx_power_min: self.read_u32()?,
            rx_power_max: self.read_u32()?,
            rx_wavelength: self.read_u32()?,
        })
    }

    /// Parse Optical SFP/QSFP Counters - Format (0,10)
    pub(super) fn parse_optical_sfp_qsfp(
        &mut self,
    ) -> Result<crate::models::record_counters::OpticalSfpQsfp> {
        let module_id = self.read_u32()?;
        let module_num_lanes = self.read_u32()?;
        let module_supply_voltage = self.read_u32()?;
        let module_temperature = self.read_i32()?;

        // Parse variable-length array of lanes
        let num_lanes = self.read_u32()?;
        let mut lanes = Vec::with_capacity(num_lanes as usize);
        for _ in 0..num_lanes {
            lanes.push(self.parse_lane()?);
        }

        Ok(crate::models::record_counters::OpticalSfpQsfp {
            module_id,
            module_num_lanes,
            module_supply_voltage,
            module_temperature,
            lanes,
        })
    }

    /// Parse Processor Counters - Format (0,1001)
    pub(super) fn parse_processor_counters(
        &mut self,
    ) -> Result<crate::models::record_counters::ProcessorCounters> {
        Ok(crate::models::record_counters::ProcessorCounters {
            cpu_5s: self.read_u32()?,
            cpu_1m: self.read_u32()?,
            cpu_5m: self.read_u32()?,
            total_memory: self.read_u64()?,
            free_memory: self.read_u64()?,
        })
    }

    /// Parse Radio Utilization - Format (0,1002)
    pub(super) fn parse_radio_utilization(
        &mut self,
    ) -> Result<crate::models::record_counters::RadioUtilization> {
        Ok(crate::models::record_counters::RadioUtilization {
            elapsed_time: self.read_u32()?,
            on_channel_time: self.read_u32()?,
            on_channel_busy_time: self.read_u32()?,
        })
    }

    /// Parse OpenFlow Port - Format (0,1004)
    pub(super) fn parse_openflow_port(
        &mut self,
    ) -> Result<crate::models::record_counters::OpenFlowPort> {
        Ok(crate::models::record_counters::OpenFlowPort {
            datapath_id: self.read_u64()?,
            port_no: self.read_u32()?,
        })
    }

    /// Parse OpenFlow Port Name - Format (0,1005)
    pub(super) fn parse_openflow_port_name(
        &mut self,
    ) -> Result<crate::models::record_counters::OpenFlowPortName> {
        Ok(crate::models::record_counters::OpenFlowPortName {
            port_name: self.read_string()?,
        })
    }

    /// Parse Host Description - Format (0,2000)
    pub(super) fn parse_host_description(
        &mut self,
    ) -> Result<crate::models::record_counters::HostDescription> {
        let hostname = self.read_string()?;
        let mut uuid = [0u8; 16];
        self.reader.read_exact(&mut uuid)?;
        let machine_type = self.read_u32()?.into(); // Convert u32 to MachineType enum
        let os_name = self.read_u32()?.into(); // Convert u32 to OsName enum
        let os_release = self.read_string()?;

        Ok(crate::models::record_counters::HostDescription {
            hostname,
            uuid,
            machine_type,
            os_name,
            os_release,
        })
    }

    /// Parse Host Adapters - Format (0,2001)
    pub(super) fn parse_host_adapters(
        &mut self,
    ) -> Result<crate::models::record_counters::HostAdapters> {
        let num_adapters = self.read_u32()?;
        let capacity_adapters = num_adapters.min(1024) as usize;
        let mut adapters = Vec::with_capacity(capacity_adapters);

        for _ in 0..num_adapters {
            let if_index = self.read_u32()?;
            let num_macs = self.read_u32()?;
            let capacity_macs = num_macs.min(1024) as usize;
            let mut mac_addresses = Vec::with_capacity(capacity_macs);

            for _ in 0..num_macs {
                let mut mac_bytes = [0u8; 6];
                self.reader.read_exact(&mut mac_bytes)?;
                // Skip 2 bytes of padding (MAC addresses are padded to 8 bytes for 4-byte alignment)
                let mut padding = [0u8; 2];
                self.reader.read_exact(&mut padding)?;
                mac_addresses.push(crate::models::MacAddress::from(mac_bytes));
            }

            adapters.push(crate::models::record_counters::HostAdapter {
                if_index,
                mac_addresses,
            });
        }

        Ok(crate::models::record_counters::HostAdapters { adapters })
    }

    /// Parse Host Parent - Format (0,2002)
    pub(super) fn parse_host_parent(
        &mut self,
    ) -> Result<crate::models::record_counters::HostParent> {
        Ok(crate::models::record_counters::HostParent {
            container_type: self.read_u32()?,
            container_index: self.read_u32()?,
        })
    }

    /// Parse Host CPU - Format (0,2003)
    pub(super) fn parse_host_cpu(&mut self) -> Result<crate::models::record_counters::HostCpu> {
        Ok(crate::models::record_counters::HostCpu {
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
    pub(super) fn parse_host_memory(
        &mut self,
    ) -> Result<crate::models::record_counters::HostMemory> {
        Ok(crate::models::record_counters::HostMemory {
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
    pub(super) fn parse_host_disk_io(
        &mut self,
    ) -> Result<crate::models::record_counters::HostDiskIo> {
        Ok(crate::models::record_counters::HostDiskIo {
            disk_total: self.read_u64()?,
            disk_free: self.read_u64()?,
            part_max_used: self.read_i32()?,
            reads: self.read_u32()?,
            bytes_read: self.read_u64()?,
            read_time: self.read_u32()?,
            writes: self.read_u32()?,
            bytes_written: self.read_u64()?,
            write_time: self.read_u32()?,
        })
    }

    /// Parse Host Network I/O - Format (0,2006)
    pub(super) fn parse_host_net_io(
        &mut self,
    ) -> Result<crate::models::record_counters::HostNetIo> {
        Ok(crate::models::record_counters::HostNetIo {
            bytes_in: self.read_u64()?,
            pkts_in: self.read_u32()?,
            errs_in: self.read_u32()?,
            drops_in: self.read_u32()?,
            bytes_out: self.read_u64()?,
            packets_out: self.read_u32()?,
            errs_out: self.read_u32()?,
            drops_out: self.read_u32()?,
        })
    }

    /// Parse MIB-2 IP Group - Format (0,2007)
    pub(super) fn parse_mib2_ip_group(
        &mut self,
    ) -> Result<crate::models::record_counters::Mib2IpGroup> {
        Ok(crate::models::record_counters::Mib2IpGroup {
            ip_forwarding: self.read_u32()?,
            ip_default_ttl: self.read_u32()?,
            ip_in_receives: self.read_u32()?,
            ip_in_hdr_errors: self.read_u32()?,
            ip_in_addr_errors: self.read_u32()?,
            ip_forw_datagrams: self.read_u32()?,
            ip_in_unknown_protos: self.read_u32()?,
            ip_in_discards: self.read_u32()?,
            ip_in_delivers: self.read_u32()?,
            ip_out_requests: self.read_u32()?,
            ip_out_discards: self.read_u32()?,
            ip_out_no_routes: self.read_u32()?,
            ip_reasm_timeout: self.read_u32()?,
            ip_reasm_reqds: self.read_u32()?,
            ip_reasm_oks: self.read_u32()?,
            ip_reasm_fails: self.read_u32()?,
            ip_frag_oks: self.read_u32()?,
            ip_frag_fails: self.read_u32()?,
            ip_frag_creates: self.read_u32()?,
        })
    }

    /// Parse MIB-2 ICMP Group - Format (0,2008)
    pub(super) fn parse_mib2_icmp_group(
        &mut self,
    ) -> Result<crate::models::record_counters::Mib2IcmpGroup> {
        Ok(crate::models::record_counters::Mib2IcmpGroup {
            icmp_in_msgs: self.read_u32()?,
            icmp_in_errors: self.read_u32()?,
            icmp_in_dest_unreachs: self.read_u32()?,
            icmp_in_time_excds: self.read_u32()?,
            icmp_in_param_probs: self.read_u32()?,
            icmp_in_src_quenchs: self.read_u32()?,
            icmp_in_redirects: self.read_u32()?,
            icmp_in_echos: self.read_u32()?,
            icmp_in_echo_reps: self.read_u32()?,
            icmp_in_timestamps: self.read_u32()?,
            icmp_in_addr_masks: self.read_u32()?,
            icmp_in_addr_mask_reps: self.read_u32()?,
            icmp_out_msgs: self.read_u32()?,
            icmp_out_errors: self.read_u32()?,
            icmp_out_dest_unreachs: self.read_u32()?,
            icmp_out_time_excds: self.read_u32()?,
            icmp_out_param_probs: self.read_u32()?,
            icmp_out_src_quenchs: self.read_u32()?,
            icmp_out_redirects: self.read_u32()?,
            icmp_out_echos: self.read_u32()?,
            icmp_out_echo_reps: self.read_u32()?,
            icmp_out_timestamps: self.read_u32()?,
            icmp_out_timestamp_reps: self.read_u32()?,
            icmp_out_addr_masks: self.read_u32()?,
            icmp_out_addr_mask_reps: self.read_u32()?,
        })
    }

    /// Parse MIB-2 TCP Group - Format (0,2009)
    pub(super) fn parse_mib2_tcp_group(
        &mut self,
    ) -> Result<crate::models::record_counters::Mib2TcpGroup> {
        Ok(crate::models::record_counters::Mib2TcpGroup {
            tcp_rto_algorithm: self.read_u32()?,
            tcp_rto_min: self.read_u32()?,
            tcp_rto_max: self.read_u32()?,
            tcp_max_conn: self.read_u32()?,
            tcp_active_opens: self.read_u32()?,
            tcp_passive_opens: self.read_u32()?,
            tcp_attempt_fails: self.read_u32()?,
            tcp_estab_resets: self.read_u32()?,
            tcp_curr_estab: self.read_u32()?,
            tcp_in_segs: self.read_u32()?,
            tcp_out_segs: self.read_u32()?,
            tcp_retrans_segs: self.read_u32()?,
            tcp_in_errs: self.read_u32()?,
            tcp_out_rsts: self.read_u32()?,
            tcp_in_csum_errs: self.read_u32()?,
        })
    }

    /// Parse MIB-2 UDP Group - Format (0,2010)
    pub(super) fn parse_mib2_udp_group(
        &mut self,
    ) -> Result<crate::models::record_counters::Mib2UdpGroup> {
        Ok(crate::models::record_counters::Mib2UdpGroup {
            udp_in_datagrams: self.read_u32()?,
            udp_no_ports: self.read_u32()?,
            udp_in_errors: self.read_u32()?,
            udp_out_datagrams: self.read_u32()?,
            udp_rcvbuf_errors: self.read_u32()?,
            udp_sndbuf_errors: self.read_u32()?,
            udp_in_csum_errors: self.read_u32()?,
        })
    }

    /// Parse Virtual Node - Format (0,2100)
    pub(super) fn parse_virtual_node(
        &mut self,
    ) -> Result<crate::models::record_counters::VirtualNode> {
        Ok(crate::models::record_counters::VirtualNode {
            mhz: self.read_u32()?,
            cpus: self.read_u32()?,
            memory: self.read_u64()?,
            memory_free: self.read_u64()?,
            num_domains: self.read_u32()?,
        })
    }

    /// Parse Virtual CPU - Format (0,2101)
    pub(super) fn parse_virtual_cpu(
        &mut self,
    ) -> Result<crate::models::record_counters::VirtualCpu> {
        Ok(crate::models::record_counters::VirtualCpu {
            state: self.read_u32()?,
            cpu_time: self.read_u32()?,
            nr_virt_cpu: self.read_u32()?,
        })
    }

    /// Parse Virtual Memory - Format (0,2102)
    pub(super) fn parse_virtual_memory(
        &mut self,
    ) -> Result<crate::models::record_counters::VirtualMemory> {
        Ok(crate::models::record_counters::VirtualMemory {
            memory: self.read_u64()?,
            max_memory: self.read_u64()?,
        })
    }

    /// Parse Virtual Disk I/O - Format (0,2103)
    pub(super) fn parse_virtual_disk_io(
        &mut self,
    ) -> Result<crate::models::record_counters::VirtualDiskIo> {
        Ok(crate::models::record_counters::VirtualDiskIo {
            capacity: self.read_u64()?,
            allocation: self.read_u64()?,
            available: self.read_u64()?,
            rd_req: self.read_u32()?,
            rd_bytes: self.read_u64()?,
            wr_req: self.read_u32()?,
            wr_bytes: self.read_u64()?,
            errs: self.read_u32()?,
        })
    }

    /// Parse Virtual Network I/O - Format (0,2104)
    pub(super) fn parse_virtual_net_io(
        &mut self,
    ) -> Result<crate::models::record_counters::VirtualNetIo> {
        Ok(crate::models::record_counters::VirtualNetIo {
            rx_bytes: self.read_u64()?,
            rx_packets: self.read_u32()?,
            rx_errs: self.read_u32()?,
            rx_drop: self.read_u32()?,
            tx_bytes: self.read_u64()?,
            tx_packets: self.read_u32()?,
            tx_errs: self.read_u32()?,
            tx_drop: self.read_u32()?,
        })
    }

    /// Parse JVM Runtime - Format (0,2105)
    pub(super) fn parse_jvm_runtime(
        &mut self,
    ) -> Result<crate::models::record_counters::JvmRuntime> {
        Ok(crate::models::record_counters::JvmRuntime {
            vm_name: self.read_string()?,
            vm_vendor: self.read_string()?,
            vm_version: self.read_string()?,
        })
    }

    /// Parse JVM Statistics - Format (0,2106)
    pub(super) fn parse_jvm_statistics(
        &mut self,
    ) -> Result<crate::models::record_counters::JvmStatistics> {
        Ok(crate::models::record_counters::JvmStatistics {
            heap_initial: self.read_u64()?,
            heap_used: self.read_u64()?,
            heap_committed: self.read_u64()?,
            heap_max: self.read_u64()?,
            non_heap_initial: self.read_u64()?,
            non_heap_used: self.read_u64()?,
            non_heap_committed: self.read_u64()?,
            non_heap_max: self.read_u64()?,
            gc_count: self.read_u32()?,
            gc_time: self.read_u32()?,
            classes_loaded: self.read_u32()?,
            classes_total: self.read_u32()?,
            classes_unloaded: self.read_u32()?,
            compilation_time: self.read_u32()?,
            thread_num_live: self.read_u32()?,
            thread_num_daemon: self.read_u32()?,
            thread_num_started: self.read_u32()?,
            fd_open_count: self.read_u32()?,
            fd_max_count: self.read_u32()?,
        })
    }

    /// Parse HTTP Counters - Format (0,2201)
    pub(super) fn parse_http_counters(
        &mut self,
    ) -> Result<crate::models::record_counters::HttpCounters> {
        Ok(crate::models::record_counters::HttpCounters {
            method_option_count: self.read_u32()?,
            method_get_count: self.read_u32()?,
            method_head_count: self.read_u32()?,
            method_post_count: self.read_u32()?,
            method_put_count: self.read_u32()?,
            method_delete_count: self.read_u32()?,
            method_trace_count: self.read_u32()?,
            method_connect_count: self.read_u32()?,
            method_other_count: self.read_u32()?,
            status_1xx_count: self.read_u32()?,
            status_2xx_count: self.read_u32()?,
            status_3xx_count: self.read_u32()?,
            status_4xx_count: self.read_u32()?,
            status_5xx_count: self.read_u32()?,
            status_other_count: self.read_u32()?,
        })
    }

    /// Parse App Operations - Format (0,2202)
    pub(super) fn parse_app_operations(
        &mut self,
    ) -> Result<crate::models::record_counters::AppOperations> {
        Ok(crate::models::record_counters::AppOperations {
            application: self.read_string()?,
            success: self.read_u32()?,
            other: self.read_u32()?,
            timeout: self.read_u32()?,
            internal_error: self.read_u32()?,
            bad_request: self.read_u32()?,
            forbidden: self.read_u32()?,
            too_large: self.read_u32()?,
            not_implemented: self.read_u32()?,
            not_found: self.read_u32()?,
            unavailable: self.read_u32()?,
            unauthorized: self.read_u32()?,
        })
    }

    /// Parse App Resources - Format (0,2203)
    pub(super) fn parse_app_resources(
        &mut self,
    ) -> Result<crate::models::record_counters::AppResources> {
        Ok(crate::models::record_counters::AppResources {
            user_time: self.read_u32()?,
            system_time: self.read_u32()?,
            mem_used: self.read_u64()?,
            mem_max: self.read_u64()?,
            fd_open: self.read_u32()?,
            fd_max: self.read_u32()?,
            conn_open: self.read_u32()?,
            conn_max: self.read_u32()?,
        })
    }

    /// Parse Memcache Counters - Format (0,2204)
    pub(super) fn parse_memcache_counters(
        &mut self,
    ) -> Result<crate::models::record_counters::MemcacheCounters> {
        Ok(crate::models::record_counters::MemcacheCounters {
            cmd_set: self.read_u32()?,
            cmd_touch: self.read_u32()?,
            cmd_flush: self.read_u32()?,
            get_hits: self.read_u32()?,
            get_misses: self.read_u32()?,
            delete_hits: self.read_u32()?,
            delete_misses: self.read_u32()?,
            incr_hits: self.read_u32()?,
            incr_misses: self.read_u32()?,
            decr_hits: self.read_u32()?,
            decr_misses: self.read_u32()?,
            cas_hits: self.read_u32()?,
            cas_misses: self.read_u32()?,
            cas_badval: self.read_u32()?,
            auth_cmds: self.read_u32()?,
            auth_errors: self.read_u32()?,
            threads: self.read_u32()?,
            conn_yields: self.read_u32()?,
            listen_disabled_num: self.read_u32()?,
            curr_connections: self.read_u32()?,
            rejected_connections: self.read_u32()?,
            total_connections: self.read_u32()?,
            connection_structures: self.read_u32()?,
            evictions: self.read_u32()?,
            reclaimed: self.read_u32()?,
            curr_items: self.read_u32()?,
            total_items: self.read_u32()?,
            bytes_read: self.read_u64()?,
            bytes_written: self.read_u64()?,
            bytes: self.read_u64()?,
            limit_maxbytes: self.read_u64()?,
        })
    }

    /// Parse App Workers - Format (0,2206)
    pub(super) fn parse_app_workers(
        &mut self,
    ) -> Result<crate::models::record_counters::AppWorkers> {
        Ok(crate::models::record_counters::AppWorkers {
            workers_active: self.read_u32()?,
            workers_idle: self.read_u32()?,
            workers_max: self.read_u32()?,
            req_delayed: self.read_u32()?,
            req_dropped: self.read_u32()?,
        })
    }

    /// Parse Broadcom Device Buffer Utilization - Format (4413,1)
    pub(super) fn parse_broadcom_device_buffers(
        &mut self,
    ) -> Result<crate::models::record_counters::BroadcomDeviceBuffers> {
        Ok(crate::models::record_counters::BroadcomDeviceBuffers {
            uc_pc: self.read_i32()?,
            mc_pc: self.read_i32()?,
        })
    }

    /// Parse Broadcom Port Buffer Utilization - Format (4413,2)
    pub(super) fn parse_broadcom_port_buffers(
        &mut self,
    ) -> Result<crate::models::record_counters::BroadcomPortBuffers> {
        let ingress_uc_pc = self.read_i32()?;
        let ingress_mc_pc = self.read_i32()?;
        let egress_uc_pc = self.read_i32()?;
        let egress_mc_pc = self.read_i32()?;

        // Read variable-length arrays for egress queue percentages
        let uc_count = self.read_u32()? as usize;
        let mut egress_queue_uc_pc = Vec::with_capacity(uc_count);
        for _ in 0..uc_count {
            egress_queue_uc_pc.push(self.read_i32()?);
        }

        let mc_count = self.read_u32()? as usize;
        let mut egress_queue_mc_pc = Vec::with_capacity(mc_count);
        for _ in 0..mc_count {
            egress_queue_mc_pc.push(self.read_i32()?);
        }

        Ok(crate::models::record_counters::BroadcomPortBuffers {
            ingress_uc_pc,
            ingress_mc_pc,
            egress_uc_pc,
            egress_mc_pc,
            egress_queue_uc_pc,
            egress_queue_mc_pc,
        })
    }

    /// Parse Broadcom Switch ASIC Table Utilization - Format (4413,3)
    pub(super) fn parse_broadcom_tables(
        &mut self,
    ) -> Result<crate::models::record_counters::BroadcomTables> {
        Ok(crate::models::record_counters::BroadcomTables {
            host_entries: self.read_u32()?,
            host_entries_max: self.read_u32()?,
            ipv4_entries: self.read_u32()?,
            ipv4_entries_max: self.read_u32()?,
            ipv6_entries: self.read_u32()?,
            ipv6_entries_max: self.read_u32()?,
            ipv4_ipv6_entries: self.read_u32()?,
            ipv6_ipv6_entries_max: self.read_u32()?,
            long_ipv6_entries: self.read_u32()?,
            long_ipv6_entries_max: self.read_u32()?,
            total_routes: self.read_u32()?,
            total_routes_max: self.read_u32()?,
            ecmp_nexthops: self.read_u32()?,
            ecmp_nexthops_max: self.read_u32()?,
            mac_entries: self.read_u32()?,
            mac_entries_max: self.read_u32()?,
            ipv4_neighbors: self.read_u32()?,
            ipv6_neighbors: self.read_u32()?,
            ipv4_routes: self.read_u32()?,
            ipv6_routes: self.read_u32()?,
            acl_ingress_entries: self.read_u32()?,
            acl_ingress_entries_max: self.read_u32()?,
            acl_ingress_counters: self.read_u32()?,
            acl_ingress_counters_max: self.read_u32()?,
            acl_ingress_meters: self.read_u32()?,
            acl_ingress_meters_max: self.read_u32()?,
            acl_ingress_slices: self.read_u32()?,
            acl_ingress_slices_max: self.read_u32()?,
            acl_egress_entries: self.read_u32()?,
            acl_egress_entries_max: self.read_u32()?,
            acl_egress_counters: self.read_u32()?,
            acl_egress_counters_max: self.read_u32()?,
            acl_egress_meters: self.read_u32()?,
            acl_egress_meters_max: self.read_u32()?,
            acl_egress_slices: self.read_u32()?,
            acl_egress_slices_max: self.read_u32()?,
        })
    }

    /// Parse NVIDIA GPU Statistics - Format (5703,1)
    pub(super) fn parse_nvidia_gpu(&mut self) -> Result<crate::models::record_counters::NvidiaGpu> {
        Ok(crate::models::record_counters::NvidiaGpu {
            device_count: self.read_u32()?,
            processes: self.read_u32()?,
            gpu_time: self.read_u32()?,
            mem_time: self.read_u32()?,
            mem_total: self.read_u64()?,
            mem_free: self.read_u64()?,
            ecc_errors: self.read_u32()?,
            energy: self.read_u32()?,
            temperature: self.read_u32()?,
            fan_speed: self.read_u32()?,
        })
    }

    /// Parse counter data based on format
    pub(super) fn parse_counter_data(
        &mut self,
        format: DataFormat,
        data: Vec<u8>,
    ) -> Result<CounterData> {
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
                3 => Ok(CounterData::TokenRing(parser.parse_token_ring_counters()?)),
                4 => Ok(CounterData::Vg100Interface(
                    parser.parse_vg100_interface_counters()?,
                )),
                5 => Ok(CounterData::Vlan(parser.parse_vlan_counters()?)),
                6 => Ok(CounterData::Ieee80211(parser.parse_ieee80211_counters()?)),
                7 => Ok(CounterData::LagPortStats(parser.parse_lag_port_stats()?)),
                9 => Ok(CounterData::InfiniBandCounters(
                    parser.parse_infiniband_counters()?,
                )),
                10 => Ok(CounterData::OpticalSfpQsfp(
                    parser.parse_optical_sfp_qsfp()?,
                )),
                1001 => Ok(CounterData::Processor(parser.parse_processor_counters()?)),
                1002 => Ok(CounterData::RadioUtilization(
                    parser.parse_radio_utilization()?,
                )),
                1004 => Ok(CounterData::OpenFlowPort(parser.parse_openflow_port()?)),
                1005 => Ok(CounterData::OpenFlowPortName(
                    parser.parse_openflow_port_name()?,
                )),
                2000 => Ok(CounterData::HostDescription(
                    parser.parse_host_description()?,
                )),
                2001 => Ok(CounterData::HostAdapters(parser.parse_host_adapters()?)),
                2002 => Ok(CounterData::HostParent(parser.parse_host_parent()?)),
                2003 => Ok(CounterData::HostCpu(parser.parse_host_cpu()?)),
                2004 => Ok(CounterData::HostMemory(parser.parse_host_memory()?)),
                2005 => Ok(CounterData::HostDiskIo(parser.parse_host_disk_io()?)),
                2006 => Ok(CounterData::HostNetIo(parser.parse_host_net_io()?)),
                2007 => Ok(CounterData::Mib2IpGroup(parser.parse_mib2_ip_group()?)),
                2008 => Ok(CounterData::Mib2IcmpGroup(parser.parse_mib2_icmp_group()?)),
                2009 => Ok(CounterData::Mib2TcpGroup(parser.parse_mib2_tcp_group()?)),
                2010 => Ok(CounterData::Mib2UdpGroup(parser.parse_mib2_udp_group()?)),
                2100 => Ok(CounterData::VirtualNode(parser.parse_virtual_node()?)),
                2101 => Ok(CounterData::VirtualCpu(parser.parse_virtual_cpu()?)),
                2102 => Ok(CounterData::VirtualMemory(parser.parse_virtual_memory()?)),
                2103 => Ok(CounterData::VirtualDiskIo(parser.parse_virtual_disk_io()?)),
                2104 => Ok(CounterData::VirtualNetIo(parser.parse_virtual_net_io()?)),
                2105 => Ok(CounterData::JvmRuntime(parser.parse_jvm_runtime()?)),
                2106 => Ok(CounterData::JvmStatistics(parser.parse_jvm_statistics()?)),
                2201 => Ok(CounterData::HttpCounters(parser.parse_http_counters()?)),
                2204 => Ok(CounterData::MemcacheCounters(
                    parser.parse_memcache_counters()?,
                )),
                2202 => Ok(CounterData::AppOperations(parser.parse_app_operations()?)),
                2203 => Ok(CounterData::AppResources(parser.parse_app_resources()?)),
                2206 => Ok(CounterData::AppWorkers(parser.parse_app_workers()?)),
                _ => Ok(CounterData::Unknown { format, data }),
            }
        } else if format.enterprise() == 4413 {
            // Broadcom enterprise formats
            match format.format() {
                1 => Ok(CounterData::BroadcomDeviceBuffers(
                    parser.parse_broadcom_device_buffers()?,
                )),
                2 => Ok(CounterData::BroadcomPortBuffers(
                    parser.parse_broadcom_port_buffers()?,
                )),
                3 => Ok(CounterData::BroadcomTables(parser.parse_broadcom_tables()?)),
                _ => Ok(CounterData::Unknown { format, data }),
            }
        } else if format.enterprise() == 5703 {
            // NVIDIA enterprise formats
            match format.format() {
                1 => Ok(CounterData::NvidiaGpu(parser.parse_nvidia_gpu()?)),
                _ => Ok(CounterData::Unknown { format, data }),
            }
        } else {
            // Other vendor-specific formats
            Ok(CounterData::Unknown { format, data })
        }
    }

    /// Parse a counter record
    pub(super) fn parse_counter_record(&mut self) -> Result<CounterRecord> {
        let counter_format = self.parse_data_format()?;
        let counter_data_raw = self.read_opaque()?;
        let counter_data = self.parse_counter_data(counter_format, counter_data_raw)?;

        Ok(CounterRecord {
            counter_format,
            counter_data,
        })
    }
}
