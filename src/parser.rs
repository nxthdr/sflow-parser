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

    /// Read a u8
    #[allow(dead_code)]
    fn read_u8(&mut self) -> Result<u8> {
        let mut buf = [0u8; 1];
        self.reader.read_exact(&mut buf)?;
        Ok(buf[0])
    }

    /// Read an opaque byte array (length-prefixed)
    fn read_opaque(&mut self) -> Result<Vec<u8>> {
        let length = self.read_u32()? as usize;
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

    /// Parse a flow record
    fn parse_flow_record(&mut self) -> Result<FlowRecord> {
        let flow_format = self.parse_data_format()?;
        let flow_data = self.read_opaque()?;
        Ok(FlowRecord {
            flow_format,
            flow_data,
        })
    }

    /// Parse a counter record
    fn parse_counter_record(&mut self) -> Result<CounterRecord> {
        let counter_format = self.parse_data_format()?;
        let counter_data = self.read_opaque()?;
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
        let mut flow_records = Vec::with_capacity(num_records as usize);
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
        let mut counters = Vec::with_capacity(num_records as usize);
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
        let mut flow_records = Vec::with_capacity(num_records as usize);
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
        let mut counters = Vec::with_capacity(num_records as usize);
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
        let mut samples = Vec::with_capacity(num_samples as usize);
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
            Err(e) if e.downcast_ref::<io::Error>()
                .map(|e| e.kind() == io::ErrorKind::UnexpectedEof)
                .unwrap_or(false) => {
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
