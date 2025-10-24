//! sFlow v5 parser
//!
//! This module provides parsing functionality for sFlow v5 datagrams.
//! All data is in network byte order (big-endian) as per XDR specification.

mod datagram;
mod error;
mod parser_counters;
mod parser_flows;

// Re-export public types
pub use datagram::{parse_datagram, parse_datagrams};
pub use error::{ParseError, Result};

use crate::models::*;
use std::io::Read;
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
    pub(crate) fn read_u32(&mut self) -> Result<u32> {
        let mut buf = [0u8; 4];
        self.reader.read_exact(&mut buf)?;
        Ok(u32::from_be_bytes(buf))
    }

    /// Read a u64 in network byte order (big-endian)
    pub(crate) fn read_u64(&mut self) -> Result<u64> {
        let mut buf = [0u8; 8];
        self.reader.read_exact(&mut buf)?;
        Ok(u64::from_be_bytes(buf))
    }

    /// Read a u8
    #[allow(dead_code)]
    pub(crate) fn read_u8(&mut self) -> Result<u8> {
        let mut buf = [0u8; 1];
        self.reader.read_exact(&mut buf)?;
        Ok(buf[0])
    }

    /// Read a string (length-prefixed opaque data converted to UTF-8)
    pub(crate) fn read_string(&mut self) -> Result<String> {
        let bytes = self.read_opaque()?;
        Ok(String::from_utf8(bytes)?)
    }

    /// Read an opaque byte array (length-prefixed)
    pub(crate) fn read_opaque(&mut self) -> Result<Vec<u8>> {
        let length = self.read_u32()? as usize;

        // Sanity check: reject unreasonably large allocations (> 100MB)
        // Valid sFlow packets are typically much smaller
        const MAX_OPAQUE_SIZE: usize = 100 * 1024 * 1024; // 100MB
        if length > MAX_OPAQUE_SIZE {
            return Err(ParseError::InvalidData(format!(
                "Opaque data length {} exceeds maximum {}",
                length, MAX_OPAQUE_SIZE
            )));
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
    pub(crate) fn read_fixed(&mut self, size: usize) -> Result<Vec<u8>> {
        let mut data = vec![0u8; size];
        self.reader.read_exact(&mut data)?;
        Ok(data)
    }

    /// Parse an address
    pub(crate) fn parse_address(&mut self) -> Result<Address> {
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
            _ => Err(ParseError::InvalidData(format!(
                "Invalid address type: {}",
                addr_type
            ))),
        }
    }

    /// Parse a data format
    pub(crate) fn parse_data_format(&mut self) -> Result<DataFormat> {
        let value = self.read_u32()?;
        Ok(DataFormat(value))
    }

    /// Parse a data source
    pub(crate) fn parse_data_source(&mut self) -> Result<DataSource> {
        let value = self.read_u32()?;
        Ok(DataSource(value))
    }

    /// Parse an expanded data source
    pub(crate) fn parse_data_source_expanded(&mut self) -> Result<DataSourceExpanded> {
        let source_id_type = self.read_u32()?;
        let source_id_index = self.read_u32()?;
        Ok(DataSourceExpanded {
            source_id_type,
            source_id_index,
        })
    }

    /// Parse an interface
    pub(crate) fn parse_interface(&mut self) -> Result<Interface> {
        let value = self.read_u32()?;
        Ok(Interface(value))
    }

    /// Parse an expanded interface
    pub(crate) fn parse_interface_expanded(&mut self) -> Result<InterfaceExpanded> {
        let format = self.read_u32()?;
        let value = self.read_u32()?;
        Ok(InterfaceExpanded { format, value })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

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
