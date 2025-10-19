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
            dot12_in_oversized_frame_errors: self.read_u32()?,
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
        let machine_type = self.read_string()?;
        let os_name = self.read_string()?;
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
                let mut mac = [0u8; 6];
                self.reader.read_exact(&mut mac)?;
                mac_addresses.push(mac);
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
    pub(super) fn parse_host_net_io(
        &mut self,
    ) -> Result<crate::models::record_counters::HostNetIo> {
        Ok(crate::models::record_counters::HostNetIo {
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

    /// Parse Virtual Node - Format (0,2100)
    pub(super) fn parse_virtual_node(
        &mut self,
    ) -> Result<crate::models::record_counters::VirtualNode> {
        Ok(crate::models::record_counters::VirtualNode {
            memory: self.read_u64()?,
            num_cpus: self.read_u32()?,
            cpu_time: self.read_u32()?,
        })
    }

    /// Parse Virtual CPU - Format (0,2101)
    pub(super) fn parse_virtual_cpu(
        &mut self,
    ) -> Result<crate::models::record_counters::VirtualCpu> {
        Ok(crate::models::record_counters::VirtualCpu {
            state: self.read_u32()?,
            cpu_time: self.read_u32()?,
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
            rx_pkts: self.read_u32()?,
            rx_errs: self.read_u32()?,
            rx_drop: self.read_u32()?,
            tx_bytes: self.read_u64()?,
            tx_pkts: self.read_u32()?,
            tx_errs: self.read_u32()?,
            tx_drop: self.read_u32()?,
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
                2100 => Ok(CounterData::VirtualNode(parser.parse_virtual_node()?)),
                2101 => Ok(CounterData::VirtualCpu(parser.parse_virtual_cpu()?)),
                2102 => Ok(CounterData::VirtualMemory(parser.parse_virtual_memory()?)),
                2103 => Ok(CounterData::VirtualDiskIo(parser.parse_virtual_disk_io()?)),
                2104 => Ok(CounterData::VirtualNetIo(parser.parse_virtual_net_io()?)),
                2202 => Ok(CounterData::AppOperations(parser.parse_app_operations()?)),
                2203 => Ok(CounterData::AppResources(parser.parse_app_resources()?)),
                2206 => Ok(CounterData::AppWorkers(parser.parse_app_workers()?)),
                _ => Ok(CounterData::Unknown { format, data }),
            }
        } else {
            // Vendor-specific format
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
