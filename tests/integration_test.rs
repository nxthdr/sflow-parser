use sflow_parser::{parse_datagrams, models::{SampleData, DataFormat, Address}};
use std::collections::HashMap;

#[test]
fn test_parse_sflow_bin() {
    // Read the binary file we created from the pcap
    let data = std::fs::read("tests/data/sflow.bin")
        .expect("Failed to read sflow.bin - make sure it exists");

    // Parse all datagrams
    let datagrams = parse_datagrams(&data).expect("Failed to parse sFlow datagrams");

    // We should have parsed some datagrams
    assert!(!datagrams.is_empty(), "No datagrams were parsed");

    println!("\n=== sFlow Datagram Parse Summary ===");
    println!("Total datagrams: {}", datagrams.len());

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

#[test]
fn test_datagram_statistics() {
    let data = std::fs::read("tests/data/sflow.bin")
        .expect("Failed to read sflow.bin");

    let datagrams = parse_datagrams(&data).expect("Failed to parse");

    // Collect statistics
    let mut total_flow_samples = 0;
    let mut total_counter_samples = 0;
    let mut total_flow_records = 0;
    let mut total_counter_records = 0;
    let mut unique_agents = std::collections::HashSet::new();
    let mut flow_formats = std::collections::HashMap::new();
    let mut counter_formats = std::collections::HashMap::new();

    for datagram in &datagrams {
        // Track unique agent addresses
        match &datagram.agent_address {
            Address::IPv4(addr) => {
                unique_agents.insert(format!("{}", addr));
            }
            Address::IPv6(addr) => {
                unique_agents.insert(format!("{}", addr));
            }
            Address::Unknown => {
                unique_agents.insert("Unknown".to_string());
            }
        }

        for sample in &datagram.samples {
            match &sample.sample_data {
                SampleData::FlowSample(flow) => {
                    total_flow_samples += 1;
                    total_flow_records += flow.flow_records.len();
                    
                    for record in &flow.flow_records {
                        *flow_formats.entry(record.flow_format.0).or_insert(0) += 1;
                    }
                }
                SampleData::CountersSample(counters) => {
                    total_counter_samples += 1;
                    total_counter_records += counters.counters.len();
                    
                    for record in &counters.counters {
                        *counter_formats.entry(record.counter_format.0).or_insert(0) += 1;
                    }
                }
                SampleData::FlowSampleExpanded(flow) => {
                    total_flow_samples += 1;
                    total_flow_records += flow.flow_records.len();
                }
                SampleData::CountersSampleExpanded(counters) => {
                    total_counter_samples += 1;
                    total_counter_records += counters.counters.len();
                }
                SampleData::Unknown { .. } => {}
            }
        }
    }

    println!("\n=== Statistics ===");
    println!("Total datagrams: {}", datagrams.len());
    println!("Unique agents: {}", unique_agents.len());
    println!("  Agents: {:?}", unique_agents);
    println!("Total flow samples: {}", total_flow_samples);
    println!("Total counter samples: {}", total_counter_samples);
    println!("Total flow records: {}", total_flow_records);
    println!("Total counter records: {}", total_counter_records);
    
    println!("\nFlow record formats:");
    for (format, count) in &flow_formats {
        let df = DataFormat(*format);
        println!("  ({}, {}): {} records", df.enterprise(), df.format(), count);
    }
    
    println!("\nCounter record formats:");
    for (format, count) in &counter_formats {
        let df = DataFormat(*format);
        println!("  ({}, {}): {} records", df.enterprise(), df.format(), count);
    }

    // Assertions
    assert!(datagrams.len() > 0, "Should have parsed datagrams");
    assert!(unique_agents.len() > 0, "Should have at least one agent");
    assert!(total_flow_samples + total_counter_samples > 0, "Should have samples");
}

#[test]
fn test_flow_sample_details() {
    let data = std::fs::read("tests/data/sflow.bin")
        .expect("Failed to read sflow.bin");

    let datagrams = parse_datagrams(&data).expect("Failed to parse");

    let mut found_flow_sample = false;

    for datagram in &datagrams {
        for sample in &datagram.samples {
            if let SampleData::FlowSample(flow) = &sample.sample_data {
                found_flow_sample = true;

                // Validate flow sample fields
                assert!(flow.sampling_rate > 0, "Sampling rate should be positive");
                assert!(flow.sample_pool >= flow.sequence_number, 
                    "Sample pool should be >= sequence number");
                
                // Input/output interfaces should be valid
                assert!(flow.input.format() <= 2, "Invalid input interface format");
                assert!(flow.output.format() <= 2, "Invalid output interface format");

                // Should have at least one flow record
                assert!(!flow.flow_records.is_empty(), "Flow sample should have records");

                for record in &flow.flow_records {
                    // Flow data should not be empty
                    assert!(!record.flow_data.is_empty(), "Flow record data should not be empty");
                    
                    // Validate format
                    assert!(record.flow_format.enterprise() <= 0xFFFFF, "Invalid enterprise");
                    assert!(record.flow_format.format() <= 0xFFF, "Invalid format");
                }

                println!("\nFlow Sample Details:");
                println!("  Sequence: {}", flow.sequence_number);
                println!("  Source: type={}, index={}", 
                    flow.source_id.source_type(), flow.source_id.index());
                println!("  Sampling: 1/{}", flow.sampling_rate);
                println!("  Pool: {}", flow.sample_pool);
                println!("  Drops: {}", flow.drops);
                println!("  Input: format={}, value={}", 
                    flow.input.format(), flow.input.value());
                println!("  Output: format={}, value={}", 
                    flow.output.format(), flow.output.value());
                println!("  Records: {}", flow.flow_records.len());
            }
        }
    }

    assert!(found_flow_sample, "Should have found at least one flow sample");
}

#[test]
fn test_counter_sample_details() {
    let data = std::fs::read("tests/data/sflow.bin")
        .expect("Failed to read sflow.bin");

    let datagrams = parse_datagrams(&data).expect("Failed to parse");

    let mut found_counter_sample = false;

    for datagram in &datagrams {
        for sample in &datagram.samples {
            if let SampleData::CountersSample(counters) = &sample.sample_data {
                found_counter_sample = true;

                // Should have at least one counter record
                assert!(!counters.counters.is_empty(), "Counter sample should have records");

                for record in &counters.counters {
                    // Counter data should not be empty
                    assert!(!record.counter_data.is_empty(), "Counter record data should not be empty");
                    
                    // Validate format
                    assert!(record.counter_format.enterprise() <= 0xFFFFF, "Invalid enterprise");
                    assert!(record.counter_format.format() <= 0xFFF, "Invalid format");
                }

                println!("\nCounter Sample Details:");
                println!("  Sequence: {}", counters.sequence_number);
                println!("  Source: type={}, index={}", 
                    counters.source_id.source_type(), counters.source_id.index());
                println!("  Records: {}", counters.counters.len());
                
                for (i, record) in counters.counters.iter().enumerate() {
                    println!("    Record {}: enterprise={}, format={}, data_len={}", 
                        i + 1,
                        record.counter_format.enterprise(),
                        record.counter_format.format(),
                        record.counter_data.len());
                }
            }
        }
    }

    assert!(found_counter_sample, "Should have found at least one counter sample");
}

#[test]
fn test_agent_addresses() {
    let data = std::fs::read("tests/data/sflow.bin")
        .expect("Failed to read sflow.bin");

    let datagrams = parse_datagrams(&data).expect("Failed to parse");

    for datagram in &datagrams {
        // Agent address should be valid
        match &datagram.agent_address {
            Address::IPv4(addr) => {
                println!("Agent IPv4: {}", addr);
                // Should be a valid IP (not 0.0.0.0)
                assert_ne!(addr.octets(), [0, 0, 0, 0], "Agent IP should not be 0.0.0.0");
            }
            Address::IPv6(addr) => {
                println!("Agent IPv6: {}", addr);
                assert!(!addr.is_unspecified(), "Agent IPv6 should not be unspecified");
            }
            Address::Unknown => {
                println!("Agent: Unknown");
            }
        }

        // Sub-agent ID should be reasonable
        assert!(datagram.sub_agent_id < 0xFFFFFFFF, "Sub-agent ID seems invalid");
        
        // Uptime should be reasonable (not zero for real devices)
        // Note: Could be zero for test data
        println!("Uptime: {} ms ({} seconds)", 
            datagram.uptime, datagram.uptime / 1000);
    }
}

#[test]
fn test_sequence_numbers() {
    let data = std::fs::read("tests/data/sflow.bin")
        .expect("Failed to read sflow.bin");

    let datagrams = parse_datagrams(&data).expect("Failed to parse");

    // Group datagrams by agent
    let mut agent_sequences: HashMap<String, Vec<u32>> = HashMap::new();

    for datagram in &datagrams {
        let agent_key = match &datagram.agent_address {
            Address::IPv4(addr) => format!("{}", addr),
            Address::IPv6(addr) => format!("{}", addr),
            Address::Unknown => "Unknown".to_string(),
        };

        agent_sequences.entry(agent_key)
            .or_insert_with(Vec::new)
            .push(datagram.sequence_number);
    }

    println!("\n=== Sequence Number Analysis ===");
    for (agent, sequences) in &agent_sequences {
        println!("Agent {}: {} datagrams", agent, sequences.len());
        println!("  Sequence range: {} - {}", 
            sequences.iter().min().unwrap(),
            sequences.iter().max().unwrap());
        
        // Check if sequences are mostly increasing (allowing for wraps)
        let mut sorted = sequences.clone();
        sorted.sort();
        println!("  Sequences: {:?}", sequences);
    }
}
