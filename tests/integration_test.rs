use sflow_parser::{parse_datagrams, models::SampleData};

#[test]
fn test_parse_sflow_bin() {
    // Read the binary file we created from the pcap
    let data = std::fs::read("tests/data/sflow.bin")
        .expect("Failed to read sflow.bin - make sure it exists");

    // Parse all datagrams
    let datagrams = parse_datagrams(&data).expect("Failed to parse sFlow datagrams");

    // We should have parsed some datagrams
    assert!(!datagrams.is_empty(), "No datagrams were parsed");

    println!("Parsed {} sFlow datagrams", datagrams.len());

    // Examine each datagram
    for (i, datagram) in datagrams.iter().enumerate() {
        println!("\nDatagram {}:", i + 1);
        println!("  Agent address: {:?}", datagram.agent_address);
        println!("  Sub-agent ID: {}", datagram.sub_agent_id);
        println!("  Sequence number: {}", datagram.sequence_number);
        println!("  Uptime: {} ms", datagram.uptime);
        println!("  Number of samples: {}", datagram.samples.len());

        // Examine each sample
        for (j, sample) in datagram.samples.iter().enumerate() {
            println!("    Sample {}: type={:?}", j + 1, sample.sample_type);
            
            match &sample.sample_data {
                SampleData::FlowSample(flow) => {
                    println!("      Flow Sample:");
                    println!("        Sequence: {}", flow.sequence_number);
                    println!("        Sampling rate: 1/{}", flow.sampling_rate);
                    println!("        Sample pool: {}", flow.sample_pool);
                    println!("        Drops: {}", flow.drops);
                    println!("        Input interface: {:?}", flow.input);
                    println!("        Output interface: {:?}", flow.output);
                    println!("        Flow records: {}", flow.flow_records.len());
                    
                    for (k, record) in flow.flow_records.iter().enumerate() {
                        println!("          Record {}: format={:?}, data_len={}", 
                            k + 1, record.flow_format, record.flow_data.len());
                    }
                }
                SampleData::CountersSample(counters) => {
                    println!("      Counters Sample:");
                    println!("        Sequence: {}", counters.sequence_number);
                    println!("        Counter records: {}", counters.counters.len());
                }
                SampleData::FlowSampleExpanded(flow) => {
                    println!("      Flow Sample (Expanded):");
                    println!("        Sequence: {}", flow.sequence_number);
                    println!("        Sampling rate: 1/{}", flow.sampling_rate);
                }
                SampleData::CountersSampleExpanded(counters) => {
                    println!("      Counters Sample (Expanded):");
                    println!("        Sequence: {}", counters.sequence_number);
                }
                SampleData::Unknown { format, data } => {
                    println!("      Unknown Sample:");
                    println!("        Format: enterprise={}, format={}", 
                        format.enterprise(), format.format());
                    println!("        Data length: {}", data.len());
                }
            }
        }
    }

    // Basic assertions
    let total_samples: usize = datagrams.iter().map(|d| d.samples.len()).sum();
    assert!(total_samples > 0, "No samples found in any datagram");
}

#[test]
fn test_datagram_structure() {
    let data = std::fs::read("tests/data/sflow.bin")
        .expect("Failed to read sflow.bin");

    let datagrams = parse_datagrams(&data).expect("Failed to parse");

    for datagram in &datagrams {
        // All datagrams should be version 5
        assert_eq!(datagram.version, sflow_parser::models::DatagramVersion::Version5);
        
        // Should have at least one sample
        assert!(!datagram.samples.is_empty());
    }
}
