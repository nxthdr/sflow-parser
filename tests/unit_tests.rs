//! Unit tests for sFlow parser models and core functionality

use sflow_parser::models::*;
use std::net::{Ipv4Addr, Ipv6Addr};

mod model_tests {
    use super::*;

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
        assert_eq!(source.0, 42);

        // VLAN type (1) with VLAN 100
        let source = DataSource::new(1, 100);
        assert_eq!(source.source_type(), 1);
        assert_eq!(source.index(), 100);
        assert_eq!(source.0, (1 << 24) | 100);

        // Physical entity type (2) with index 5
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
        assert!(iface.is_single());
        assert!(!iface.is_discarded());
        assert!(!iface.is_multiple());
    }

    #[test]
    fn test_interface_discarded() {
        // Packet discarded due to ACL (reason code 258)
        let iface = Interface(0x40000102); // Format 1, value 258
        assert_eq!(iface.format(), 1);
        assert_eq!(iface.value(), 258);
        assert!(!iface.is_single());
        assert!(iface.is_discarded());
        assert!(!iface.is_multiple());
    }

    #[test]
    fn test_interface_multiple() {
        // Packet sent to 7 interfaces
        let iface = Interface(0x80000007); // Format 2, value 7
        assert_eq!(iface.format(), 2);
        assert_eq!(iface.value(), 7);
        assert!(!iface.is_single());
        assert!(!iface.is_discarded());
        assert!(iface.is_multiple());
    }

    #[test]
    fn test_interface_special_values() {
        // No interface (0x3FFFFFFF)
        let iface = Interface(0x3FFFFFFF);
        assert_eq!(iface.format(), 0);
        assert_eq!(iface.value(), 0x3FFFFFFF);
        assert!(iface.is_single());

        // Unknown number of multiple interfaces
        let iface = Interface(0x80000000);
        assert_eq!(iface.format(), 2);
        assert_eq!(iface.value(), 0);
        assert!(iface.is_multiple());
    }

    #[test]
    fn test_address_types() {
        let unknown = Address::Unknown;
        assert_eq!(unknown, Address::Unknown);

        let ipv4 = Address::IPv4(Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(ipv4, Address::IPv4(Ipv4Addr::new(192, 168, 1, 1)));

        let ipv6 = Address::IPv6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        assert_eq!(
            ipv6,
            Address::IPv6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))
        );
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
        assert_eq!(datagram.agent_address, Address::IPv4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(datagram.sub_agent_id, 100000);
        assert_eq!(datagram.sequence_number, 12345);
        assert_eq!(datagram.uptime, 1000000);
        assert_eq!(datagram.samples.len(), 0);
    }

    #[test]
    fn test_flow_record_structure() {
        let record = FlowRecord {
            flow_format: DataFormat::new(0, 1),
            flow_data: vec![1, 2, 3, 4],
        };

        assert_eq!(record.flow_format.enterprise(), 0);
        assert_eq!(record.flow_format.format(), 1);
        assert_eq!(record.flow_data.len(), 4);
    }

    #[test]
    fn test_counter_record_structure() {
        let record = CounterRecord {
            counter_format: DataFormat::new(0, 1),
            counter_data: vec![5, 6, 7, 8],
        };

        assert_eq!(record.counter_format.enterprise(), 0);
        assert_eq!(record.counter_format.format(), 1);
        assert_eq!(record.counter_data.len(), 4);
    }

    #[test]
    fn test_flow_sample_structure() {
        let sample = FlowSample {
            sequence_number: 100,
            source_id: DataSource::new(0, 5),
            sampling_rate: 400,
            sample_pool: 40000,
            drops: 0,
            input: Interface(1),
            output: Interface(2),
            flow_records: vec![],
        };

        assert_eq!(sample.sequence_number, 100);
        assert_eq!(sample.source_id.source_type(), 0);
        assert_eq!(sample.source_id.index(), 5);
        assert_eq!(sample.sampling_rate, 400);
        assert_eq!(sample.sample_pool, 40000);
        assert_eq!(sample.drops, 0);
        assert_eq!(sample.input.value(), 1);
        assert_eq!(sample.output.value(), 2);
    }

    #[test]
    fn test_counters_sample_structure() {
        let sample = CountersSample {
            sequence_number: 200,
            source_id: DataSource::new(0, 10),
            counters: vec![],
        };

        assert_eq!(sample.sequence_number, 200);
        assert_eq!(sample.source_id.source_type(), 0);
        assert_eq!(sample.source_id.index(), 10);
        assert_eq!(sample.counters.len(), 0);
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

    #[test]
    fn test_sample_data_variants() {
        let flow = FlowSample {
            sequence_number: 1,
            source_id: DataSource::new(0, 1),
            sampling_rate: 100,
            sample_pool: 100,
            drops: 0,
            input: Interface(0),
            output: Interface(0),
            flow_records: vec![],
        };

        let sample_data = SampleData::FlowSample(flow.clone());
        match sample_data {
            SampleData::FlowSample(f) => assert_eq!(f.sequence_number, 1),
            _ => panic!("Wrong variant"),
        }

        let counters = CountersSample {
            sequence_number: 2,
            source_id: DataSource::new(0, 1),
            counters: vec![],
        };

        let sample_data = SampleData::CountersSample(counters.clone());
        match sample_data {
            SampleData::CountersSample(c) => assert_eq!(c.sequence_number, 2),
            _ => panic!("Wrong variant"),
        }
    }
}
