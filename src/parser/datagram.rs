//! Datagram and sample parsing
//!
//! This module contains top-level parsing functions for sFlow datagrams and samples.

use super::error::{ParseError, Result};
use super::Parser;
use crate::models::*;
use std::io::{self, Cursor, Read};

impl<R: Read> Parser<R> {
    /// Parse a compact flow sample
    pub(super) fn parse_flow_sample(&mut self) -> Result<FlowSample> {
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
    pub(super) fn parse_counters_sample(&mut self) -> Result<CountersSample> {
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
    pub(super) fn parse_flow_sample_expanded(&mut self) -> Result<FlowSampleExpanded> {
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
    pub(super) fn parse_counters_sample_expanded(&mut self) -> Result<CountersSampleExpanded> {
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
            return Err(ParseError::InvalidData(format!(
                "Invalid version: expected 5, got {}",
                version
            )));
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
            Err(ParseError::Io(e)) if e.kind() == io::ErrorKind::UnexpectedEof => {
                // End of data
                break;
            }
            Err(e) => return Err(e),
        }
    }

    Ok(datagrams)
}
