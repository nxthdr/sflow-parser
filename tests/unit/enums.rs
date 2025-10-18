//! Tests for enum variants (FlowData, CounterData, SampleData)

use sflow_parser::models::*;

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
    assert_eq!(sample.source_id.index(), 5);
    assert_eq!(sample.sampling_rate, 400);
    assert_eq!(sample.sample_pool, 40000);
    assert_eq!(sample.drops, 0);
    assert_eq!(sample.input.value(), 1);
    assert_eq!(sample.output.value(), 2);
    assert_eq!(sample.flow_records.len(), 0);
}

#[test]
fn test_counters_sample_structure() {
    let sample = CountersSample {
        sequence_number: 200,
        source_id: DataSource::new(0, 10),
        counters: vec![],
    };

    assert_eq!(sample.sequence_number, 200);
    assert_eq!(sample.source_id.index(), 10);
    assert_eq!(sample.counters.len(), 0);
}

#[test]
fn test_sample_data_variants() {
    let flow = FlowSample {
        sequence_number: 1,
        source_id: DataSource::new(0, 1),
        sampling_rate: 100,
        sample_pool: 1000,
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

#[test]
fn test_flow_data_unknown_variant() {
    let unknown = FlowData::Unknown {
        format: DataFormat::new(999, 999),
        data: vec![1, 2, 3, 4],
    };

    match unknown {
        FlowData::Unknown { format, data } => {
            assert_eq!(format.enterprise(), 999);
            assert_eq!(format.format(), 999);
            assert_eq!(data.len(), 4);
        }
        _ => panic!("Expected Unknown variant"),
    }
}

#[test]
fn test_counter_data_unknown_variant() {
    let unknown = CounterData::Unknown {
        format: DataFormat::new(888, 888),
        data: vec![5, 6, 7, 8],
    };

    match unknown {
        CounterData::Unknown { format, data } => {
            assert_eq!(format.enterprise(), 888);
            assert_eq!(format.format(), 888);
            assert_eq!(data.len(), 4);
        }
        _ => panic!("Expected Unknown variant"),
    }
}

#[test]
fn test_sample_data_unknown_variant() {
    let unknown = SampleData::Unknown {
        format: DataFormat::new(777, 777),
        data: vec![9, 10, 11, 12],
    };

    match unknown {
        SampleData::Unknown { format, data } => {
            assert_eq!(format.enterprise(), 777);
            assert_eq!(format.format(), 777);
            assert_eq!(data.len(), 4);
        }
        _ => panic!("Expected Unknown variant"),
    }
}
