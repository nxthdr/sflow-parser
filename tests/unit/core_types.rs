//! Tests for core sFlow types (DataFormat, DataSource, Interface, Address, etc.)

use sflow_parser::models::*;
use std::net::{Ipv4Addr, Ipv6Addr};

#[test]
fn test_data_format_encoding() {
    // Standard sFlow format (enterprise=0, format=1)
    let format = DataFormat::new(0, 1);
    assert_eq!(format.enterprise(), 0);
    assert_eq!(format.format(), 1);
    assert_eq!(format.0, 1);

    // Extended switch (enterprise=0, format=1001)
    let format = DataFormat::new(0, 1001);
    assert_eq!(format.enterprise(), 0);
    assert_eq!(format.format(), 1001);

    // Vendor specific (enterprise=4413, format=5)
    let format = DataFormat::new(4413, 5);
    assert_eq!(format.enterprise(), 4413);
    assert_eq!(format.format(), 5);
    assert_eq!(format.0, (4413 << 12) | 5);
}

#[test]
fn test_data_format_max_values() {
    // Max enterprise (20 bits = 1,048,575)
    let format = DataFormat::new(0xFFFFF, 0);
    assert_eq!(format.enterprise(), 0xFFFFF);
    assert_eq!(format.format(), 0);

    // Max format (12 bits = 4,095)
    let format = DataFormat::new(0, 0xFFF);
    assert_eq!(format.enterprise(), 0);
    assert_eq!(format.format(), 0xFFF);

    // Both max
    let format = DataFormat::new(0xFFFFF, 0xFFF);
    assert_eq!(format.enterprise(), 0xFFFFF);
    assert_eq!(format.format(), 0xFFF);
}

#[test]
fn test_data_source_encoding() {
    // ifIndex type (0) with index 42
    let source = DataSource::new(0, 42);
    assert_eq!(source.source_type(), 0);
    assert_eq!(source.index(), 42);

    // sFlowDataSource (1) with index 100
    let source = DataSource::new(1, 100);
    assert_eq!(source.source_type(), 1);
    assert_eq!(source.index(), 100);

    // Physical entity (2) with index 5
    let source = DataSource::new(2, 5);
    assert_eq!(source.source_type(), 2);
    assert_eq!(source.index(), 5);
}

#[test]
fn test_data_source_max_index() {
    // Max index for compact format (24 bits = 16,777,215)
    let source = DataSource::new(0, 0xFFFFFF);
    assert_eq!(source.source_type(), 0);
    assert_eq!(source.index(), 0xFFFFFF);
}

#[test]
fn test_interface_single() {
    // Single interface with ifIndex 42
    let iface = Interface(42);
    assert_eq!(iface.format(), 0);
    assert_eq!(iface.value(), 42);

    // Another single interface
    let iface = Interface(1000);
    assert_eq!(iface.format(), 0);
    assert_eq!(iface.value(), 1000);
}

#[test]
fn test_interface_discarded() {
    // Packet discarded due to ACL (reason code 258)
    let iface = Interface(0x40000102); // Format 1, value 258
    assert_eq!(iface.format(), 1);
    assert_eq!(iface.value(), 258);

    // Packet discarded due to congestion (reason code 512)
    let iface = Interface(0x40000200); // Format 1, value 512
    assert_eq!(iface.format(), 1);
    assert_eq!(iface.value(), 512);
}

#[test]
fn test_interface_multiple() {
    // Packet sent to 7 interfaces
    let iface = Interface(0x80000007); // Format 2, value 7
    assert_eq!(iface.format(), 2);
    assert_eq!(iface.value(), 7);

    // Packet sent to 100 interfaces
    let iface = Interface(0x80000064); // Format 2, value 100
    assert_eq!(iface.format(), 2);
    assert_eq!(iface.value(), 100);
}

#[test]
fn test_interface_special_values() {
    // No interface (0x3FFFFFFF)
    let iface = Interface(0x3FFFFFFF);
    assert_eq!(iface.format(), 0);
    assert_eq!(iface.value(), 0x3FFFFFFF);

    // Unknown output interface count (0xFFFFFFFF)
    let iface = Interface(0xFFFFFFFF);
    assert_eq!(iface.format(), 3);
    assert_eq!(iface.value(), 0x3FFFFFFF);
}

#[test]
fn test_address_types() {
    let unknown = Address::Unknown;
    assert_eq!(unknown, Address::Unknown);

    let ipv4 = Address::IPv4(Ipv4Addr::new(192, 168, 1, 1));
    match ipv4 {
        Address::IPv4(addr) => assert_eq!(addr, Ipv4Addr::new(192, 168, 1, 1)),
        _ => panic!("Expected IPv4"),
    }

    let ipv6 = Address::IPv6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
    match ipv6 {
        Address::IPv6(addr) => {
            assert_eq!(addr.segments()[0], 0x2001);
            assert_eq!(addr.segments()[1], 0xdb8);
        }
        _ => panic!("Expected IPv6 address"),
    }
}

#[test]
fn test_datagram_version() {
    assert_eq!(DatagramVersion::Version5 as u32, 5);
}

#[test]
fn test_sflow_datagram_creation() {
    let datagram = SFlowDatagram::new(
        Address::IPv4(Ipv4Addr::new(10, 0, 0, 1)),
        100000,
        12345,
        1000000,
    );

    assert_eq!(datagram.version, DatagramVersion::Version5);
    assert_eq!(
        datagram.agent_address,
        Address::IPv4(Ipv4Addr::new(10, 0, 0, 1))
    );
    assert_eq!(datagram.sub_agent_id, 100000);
    assert_eq!(datagram.sequence_number, 12345);
    assert_eq!(datagram.uptime, 1000000);
    assert_eq!(datagram.samples.len(), 0);
}

#[test]
fn test_expanded_structures() {
    let source = DataSourceExpanded {
        source_id_type: 0,
        source_id_index: 0x1000000, // > 2^24
    };
    assert_eq!(source.source_id_type, 0);
    assert_eq!(source.source_id_index, 0x1000000);

    let iface = InterfaceExpanded {
        format: 0,
        value: 0x1000000,
    };
    assert_eq!(iface.format, 0);
    assert_eq!(iface.value, 0x1000000);
}
