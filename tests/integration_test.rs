use sflow_parser::{models::SampleData, parse_datagrams};

/// Test basic parsing of sflow.bin
#[test]
fn test_parse_sflow_bin() {
    let data = std::fs::read("tests/data/sflow.bin").expect("Failed to read sflow.bin");

    let datagrams = parse_datagrams(&data).expect("Failed to parse sFlow datagrams");

    assert!(!datagrams.is_empty(), "Should parse at least one datagram");

    let total_samples: usize = datagrams.iter().map(|d| d.samples.len()).sum();
    assert!(total_samples > 0, "Should have at least one sample");
}

/// Test datagram structure is valid
#[test]
fn test_datagram_structure() {
    let data = std::fs::read("tests/data/sflow.bin").expect("Failed to read sflow.bin");

    let datagrams = parse_datagrams(&data).expect("Failed to parse");

    for datagram in &datagrams {
        // All datagrams should be version 5
        assert_eq!(
            datagram.version,
            sflow_parser::models::DatagramVersion::Version5
        );

        // Should have at least one sample
        assert!(!datagram.samples.is_empty());
    }
}

/// Test flow samples have valid structure
#[test]
fn test_flow_samples() {
    let data = std::fs::read("tests/data/sflow.bin").expect("Failed to read sflow.bin");

    let datagrams = parse_datagrams(&data).expect("Failed to parse");

    let mut found_flow_sample = false;

    for datagram in &datagrams {
        for sample in &datagram.samples {
            match &sample.sample_data {
                SampleData::FlowSample(flow) => {
                    found_flow_sample = true;

                    // Basic validations
                    assert!(flow.sampling_rate > 0, "Sampling rate should be positive");
                    assert!(
                        !flow.flow_records.is_empty(),
                        "Flow sample should have records"
                    );

                    // Validate each record has valid format
                    for record in &flow.flow_records {
                        assert!(record.flow_format.enterprise() <= 0xFFFFF);
                        assert!(record.flow_format.format() <= 0xFFF);
                    }
                }
                SampleData::FlowSampleExpanded(flow) => {
                    found_flow_sample = true;

                    // Basic validations
                    assert!(flow.sampling_rate > 0, "Sampling rate should be positive");
                    assert!(
                        !flow.flow_records.is_empty(),
                        "Flow sample should have records"
                    );

                    // Validate each record has valid format
                    for record in &flow.flow_records {
                        assert!(record.flow_format.enterprise() <= 0xFFFFF);
                        assert!(record.flow_format.format() <= 0xFFF);
                    }
                }
                _ => {}
            }
        }
    }

    assert!(found_flow_sample, "Should have at least one flow sample");
}

/// Test counter samples have valid structure
#[test]
fn test_counter_samples() {
    let data = std::fs::read("tests/data/sflow.bin").expect("Failed to read sflow.bin");

    let datagrams = parse_datagrams(&data).expect("Failed to parse");

    for datagram in &datagrams {
        for sample in &datagram.samples {
            let counters = match &sample.sample_data {
                SampleData::CountersSample(c) => &c.counters,
                SampleData::CountersSampleExpanded(c) => &c.counters,
                _ => continue,
            };

            // If we have counter samples, validate them
            if !counters.is_empty() {
                for record in counters {
                    assert!(record.counter_format.enterprise() <= 0xFFFFF);
                    assert!(record.counter_format.format() <= 0xFFF);
                }
            }
        }
    }
}
