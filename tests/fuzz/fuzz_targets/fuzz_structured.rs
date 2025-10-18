#![no_main]

use libfuzzer_sys::{fuzz_target, arbitrary::{Arbitrary, Unstructured}};
use sflow_parser::parser::parse_datagram;

/// Structured fuzzing input that generates more realistic sFlow data
#[derive(Debug)]
struct SflowFuzzInput {
    version: u32,
    agent_addr_type: u32,
    agent_addr: Vec<u8>,
    sub_agent_id: u32,
    sequence_number: u32,
    uptime: u32,
    num_samples: u8,
    sample_data: Vec<u8>,
}

impl<'a> Arbitrary<'a> for SflowFuzzInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let version = u.int_in_range(1..=10)?;
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
        let num_samples = u.int_in_range(0..=5)?;  // Reduced from 10 to 5
        
        // Generate sample data - limit to reasonable size
        let sample_len = u.int_in_range(0..=512)?;  // Reduced from 1024 to 512
        let sample_data = u.bytes(sample_len)?.to_vec();
        
        Ok(SflowFuzzInput {
            version,
            agent_addr_type,
            agent_addr,
            sub_agent_id,
            sequence_number,
            uptime,
            num_samples,
            sample_data,
        })
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
        data.extend_from_slice(&(self.num_samples as u32).to_be_bytes());
        
        // Sample data
        data.extend_from_slice(&self.sample_data);
        
        data
    }
}

fuzz_target!(|input: SflowFuzzInput| {
    let data = input.to_bytes();
    let _ = parse_datagram(&data);
});
