#![no_main]

use libfuzzer_sys::{
    arbitrary::{Arbitrary, Unstructured},
    fuzz_target,
};
use sflow_parser::parsers::parse_datagram;

/// Valid sFlow sample types (enterprise=0)
const SAMPLE_TYPES: &[(u32, u32)] = &[
    (0, 1), // Flow Sample
    (0, 2), // Counters Sample
    (0, 3), // Flow Sample Expanded
    (0, 4), // Counters Sample Expanded
    (0, 5), // Discarded Packet
];

/// Valid flow record format IDs (enterprise=0)
const FLOW_FORMATS: &[(u32, u32)] = &[
    (0, 1),    // Sampled Header
    (0, 2),    // Sampled Ethernet
    (0, 3),    // Sampled IPv4
    (0, 4),    // Sampled IPv6
    (0, 1001), // Extended Switch
    (0, 1002), // Extended Router
    (0, 1003), // Extended Gateway (BGP)
    (0, 1004), // Extended User
    (0, 1005), // Extended URL (deprecated)
    (0, 1006), // Extended MPLS
    (0, 1007), // Extended NAT
    (0, 1008), // Extended MPLS Tunnel
    (0, 1009), // Extended MPLS VC
    (0, 1010), // Extended MPLS FEC
    (0, 1011), // Extended MPLS LVP FEC
    (0, 1012), // Extended VLAN Tunnel
    (0, 1013), // Extended 802.11 Payload
    (0, 1014), // Extended 802.11 RX
    (0, 1015), // Extended 802.11 TX
    (0, 1016), // Extended 802.11 Aggregation
    (0, 1017), // Extended OpenFlow v1 (deprecated)
    (0, 1018), // Extended Fibre Channel
    (0, 1019), // Extended Queue Length
    (0, 1020), // Extended NAT Port
    (0, 1021), // Extended L2 Tunnel Egress
    (0, 1022), // Extended L2 Tunnel Ingress
    (0, 1023), // Extended IPv4 Tunnel Egress
    (0, 1024), // Extended IPv4 Tunnel Ingress
    (0, 1025), // Extended IPv6 Tunnel Egress
    (0, 1026), // Extended IPv6 Tunnel Ingress
    (0, 1027), // Extended Decapsulate Egress
    (0, 1028), // Extended Decapsulate Ingress
    (0, 1029), // Extended VNI Egress
    (0, 1030), // Extended VNI Ingress
    (0, 1031), // Extended InfiniBand LRH
    (0, 1032), // Extended InfiniBand GRH
    (0, 1033), // Extended InfiniBand BRH
    (0, 1034), // Extended VLAN In
    (0, 1035), // Extended VLAN Out
    (0, 1036), // Extended Egress Queue
    (0, 1037), // Extended ACL
    (0, 1038), // Extended Function
    (0, 1039), // Extended Transit Delay
    (0, 1040), // Extended Queue Depth
    (0, 1041), // Extended HW Trap
    (0, 1042), // Extended Linux Drop Reason
    (0, 2000), // Transaction
    (0, 2001), // Extended NFS Storage Transaction
    (0, 2002), // Extended SCSI Storage Transaction
    (0, 2003), // Extended HTTP Transaction
    (0, 2100), // Extended Socket IPv4
    (0, 2101), // Extended Socket IPv6
    (0, 2102), // Extended Proxy Socket IPv4
    (0, 2103), // Extended Proxy Socket IPv6
    (0, 2200), // Memcache Operation
    (0, 2201), // HTTP Request (deprecated)
    (0, 2202), // App Operation
    (0, 2203), // App Parent Context
    (0, 2204), // App Initiator
    (0, 2205), // App Target
    (0, 2206), // HTTP Request
    (0, 2207), // Extended Proxy Request
    (0, 2208), // Extended Nav Timing
    (0, 2209), // Extended TCP Info
    (0, 2210), // Extended Entities
    (4413, 1), // BST Egress Queue
];

/// Valid counter record format IDs (enterprise=0)
const COUNTER_FORMATS: &[(u32, u32)] = &[
    (0, 1),    // Generic Interface
    (0, 2),    // Ethernet Interface
    (0, 3),    // Token Ring
    (0, 4),    // 100BaseVG Interface
    (0, 5),    // VLAN
    (0, 6),    // IEEE 802.11 Counters
    (0, 7),    // LAG Port Stats
    (0, 8),    // Slow Path Counts
    (0, 9),    // InfiniBand Counters
    (0, 10),   // Optical SFP/QSFP
    (0, 1001), // Processor
    (0, 1002), // Radio Utilization
    (0, 1003), // Queue Length
    (0, 1004), // OpenFlow Port
    (0, 1005), // OpenFlow Port Name
    (0, 2000), // Host Description
    (0, 2001), // Host Adapters
    (0, 2002), // Host Parent
    (0, 2003), // Host CPU
    (0, 2004), // Host Memory
    (0, 2005), // Host Disk I/O
    (0, 2006), // Host Network I/O
    (0, 2007), // MIB2 IP Group
    (0, 2008), // MIB2 ICMP Group
    (0, 2009), // MIB2 TCP Group
    (0, 2010), // MIB2 UDP Group
    (0, 2100), // Virtual Node
    (0, 2101), // Virtual CPU
    (0, 2102), // Virtual Memory
    (0, 2103), // Virtual Disk I/O
    (0, 2104), // Virtual Network I/O
    (0, 2105), // JVM Runtime
    (0, 2106), // JVM Statistics
    (0, 2200), // Memcache Counters (deprecated)
    (0, 2201), // HTTP Counters
    (0, 2202), // App Operations
    (0, 2203), // App Resources
    (0, 2204), // Memcache Counters
    (0, 2206), // App Workers
    (0, 2207), // OVS DP Stats
    (0, 3000), // Energy
    (0, 3001), // Temperature
    (0, 3002), // Humidity
    (0, 3003), // Fans
    (4413, 1), // Broadcom Device Buffer
    (4413, 2), // Broadcom Port Buffer
    (4413, 3), // Broadcom ASIC Tables
    (5703, 1), // NVIDIA GPU
];

/// Structured fuzzing input that generates more realistic sFlow data
#[derive(Debug)]
struct SflowFuzzInput {
    version: u32,
    agent_addr_type: u32,
    agent_addr: Vec<u8>,
    sub_agent_id: u32,
    sequence_number: u32,
    uptime: u32,
    samples: Vec<SampleData>,
}

#[derive(Debug)]
struct SampleData {
    sample_type: (u32, u32), // (enterprise, format)
    records: Vec<RecordData>,
}

#[derive(Debug)]
struct RecordData {
    record_format: (u32, u32), // (enterprise, format)
    record_length: u32,
    data: Vec<u8>,
}

impl<'a> Arbitrary<'a> for RecordData {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        // Pick a random flow or counter format
        let is_flow = u.arbitrary::<bool>()?;
        let formats = if is_flow { FLOW_FORMATS } else { COUNTER_FORMATS };
        let format_idx = u.choose_index(formats.len())?;
        let record_format = formats[format_idx];

        // Generate record data (limited size)
        let data_len = u.int_in_range(4..=128)?;
        let data = u.bytes(data_len)?.to_vec();
        let record_length = data.len() as u32;

        Ok(RecordData {
            record_format,
            record_length,
            data,
        })
    }
}

impl<'a> Arbitrary<'a> for SampleData {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        // Pick a valid sample type
        let type_idx = u.choose_index(SAMPLE_TYPES.len())?;
        let sample_type = SAMPLE_TYPES[type_idx];

        // Generate 1-3 records per sample
        let num_records = u.int_in_range(1..=3)?;
        let mut records = Vec::new();
        for _ in 0..num_records {
            records.push(u.arbitrary()?);
        }

        Ok(SampleData {
            sample_type,
            records,
        })
    }
}

impl<'a> Arbitrary<'a> for SflowFuzzInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let version = 5; // Always use version 5
        let agent_addr_type = u.int_in_range(0..=5)?;

        // Generate appropriate address length based on type
        let addr_len = match agent_addr_type {
            1 => 4,  // IPv4
            2 => 16, // IPv6
            _ => u.int_in_range(0..=32)?,
        };
        let agent_addr = u.bytes(addr_len)?.to_vec();

        let sub_agent_id = u.arbitrary()?;
        let sequence_number = u.arbitrary()?;
        let uptime = u.arbitrary()?;

        // Generate 1-3 samples
        let num_samples = u.int_in_range(1..=3)?;
        let mut samples = Vec::new();
        for _ in 0..num_samples {
            samples.push(u.arbitrary()?);
        }

        Ok(SflowFuzzInput {
            version,
            agent_addr_type,
            agent_addr,
            sub_agent_id,
            sequence_number,
            uptime,
            samples,
        })
    }
}

impl RecordData {
    fn to_bytes(&self) -> Vec<u8> {
        let mut data = Vec::new();

        // Record format (enterprise + format as DataFormat)
        let format_value = (self.record_format.0 << 12) | self.record_format.1;
        data.extend_from_slice(&format_value.to_be_bytes());

        // Record length
        data.extend_from_slice(&self.record_length.to_be_bytes());

        // Record data
        data.extend_from_slice(&self.data);

        // Add padding to 4-byte boundary
        let padding = (4 - (self.data.len() % 4)) % 4;
        data.extend_from_slice(&vec![0u8; padding]);

        data
    }
}

impl SampleData {
    fn to_bytes(&self) -> Vec<u8> {
        let mut data = Vec::new();

        // Sample type (enterprise + format as DataFormat)
        let format_value = (self.sample_type.0 << 12) | self.sample_type.1;
        data.extend_from_slice(&format_value.to_be_bytes());

        // Build sample body first to calculate length
        let mut sample_body = Vec::new();

        // Add sample-specific header fields (simplified)
        // Sequence number
        sample_body.extend_from_slice(&0u32.to_be_bytes());
        // Source ID
        sample_body.extend_from_slice(&0u32.to_be_bytes());
        // Sampling rate
        sample_body.extend_from_slice(&1u32.to_be_bytes());
        // Sample pool
        sample_body.extend_from_slice(&0u32.to_be_bytes());
        // Drops
        sample_body.extend_from_slice(&0u32.to_be_bytes());
        // Input interface
        sample_body.extend_from_slice(&0u32.to_be_bytes());
        // Output interface
        sample_body.extend_from_slice(&0u32.to_be_bytes());

        // Number of records
        sample_body.extend_from_slice(&(self.records.len() as u32).to_be_bytes());

        // Records
        for record in &self.records {
            sample_body.extend_from_slice(&record.to_bytes());
        }

        // Sample length
        data.extend_from_slice(&(sample_body.len() as u32).to_be_bytes());

        // Sample body
        data.extend_from_slice(&sample_body);

        data
    }
}

impl SflowFuzzInput {
    fn to_bytes(&self) -> Vec<u8> {
        let mut data = Vec::new();

        // Version
        data.extend_from_slice(&self.version.to_be_bytes());

        // Agent address type
        data.extend_from_slice(&self.agent_addr_type.to_be_bytes());

        // Agent address
        data.extend_from_slice(&self.agent_addr);

        // Sub-agent ID
        data.extend_from_slice(&self.sub_agent_id.to_be_bytes());

        // Sequence number
        data.extend_from_slice(&self.sequence_number.to_be_bytes());

        // Uptime
        data.extend_from_slice(&self.uptime.to_be_bytes());

        // Number of samples
        data.extend_from_slice(&(self.samples.len() as u32).to_be_bytes());

        // Samples
        for sample in &self.samples {
            data.extend_from_slice(&sample.to_bytes());
        }

        data
    }
}

fuzz_target!(|input: SflowFuzzInput| {
    let data = input.to_bytes();
    let _ = parse_datagram(&data);
});
