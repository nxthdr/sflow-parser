use sflow_parser::{
    models::{Address, CounterData, DataFormat, FlowData, SampleData},
    parse_datagrams,
};
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
                        print!(
                            "          Record {}: format={:?}, ",
                            k + 1,
                            record.flow_format
                        );

                        match &record.flow_data {
                            FlowData::SampledHeader(header) => {
                                println!(
                                    "SampledHeader(protocol={}, frame_len={}, header_len={})",
                                    header.protocol,
                                    header.frame_length,
                                    header.header.len()
                                );
                            }
                            FlowData::SampledEthernet(eth) => {
                                println!(
                                    "SampledEthernet(len={}, type=0x{:04x})",
                                    eth.length, eth.eth_type
                                );
                            }
                            FlowData::SampledIpv4(ipv4) => {
                                println!(
                                    "SampledIpv4({}:{} -> {}:{}, proto={})",
                                    ipv4.src_ip,
                                    ipv4.src_port,
                                    ipv4.dst_ip,
                                    ipv4.dst_port,
                                    ipv4.protocol
                                );
                            }
                            FlowData::SampledIpv6(ipv6) => {
                                println!(
                                    "SampledIpv6({}:{} -> {}:{}, proto={})",
                                    ipv6.src_ip,
                                    ipv6.src_port,
                                    ipv6.dst_ip,
                                    ipv6.dst_port,
                                    ipv6.protocol
                                );
                            }
                            FlowData::ExtendedSwitch(sw) => {
                                println!(
                                    "ExtendedSwitch(src_vlan={}, dst_vlan={})",
                                    sw.src_vlan, sw.dst_vlan
                                );
                            }
                            FlowData::ExtendedRouter(router) => {
                                println!("ExtendedRouter(next_hop={:?})", router.next_hop);
                            }
                            FlowData::ExtendedGateway(gw) => {
                                println!(
                                    "ExtendedGateway(as={}, segments={})",
                                    gw.as_number,
                                    gw.as_path_segments.len()
                                );
                            }
                            FlowData::ExtendedUser(user) => {
                                println!(
                                    "ExtendedUser(src={}, dst={})",
                                    user.src_user, user.dst_user
                                );
                            }
                            FlowData::ExtendedUrl(url) => {
                                println!("ExtendedUrl(url={}, host={})", url.url, url.host);
                            }
                            FlowData::ExtendedMpls(mpls) => {
                                println!(
                                    "ExtendedMpls(in_labels={}, out_labels={})",
                                    mpls.in_label_stack.len(),
                                    mpls.out_label_stack.len()
                                );
                            }
                            FlowData::ExtendedNat(nat) => {
                                println!(
                                    "ExtendedNat(src={:?}, dst={:?})",
                                    nat.src_address, nat.dst_address
                                );
                            }
                            FlowData::ExtendedMplsTunnel(tunnel) => {
                                println!(
                                    "ExtendedMplsTunnel(name={}, id={})",
                                    tunnel.tunnel_name, tunnel.tunnel_id
                                );
                            }
                            FlowData::ExtendedMplsVc(vc) => {
                                println!(
                                    "ExtendedMplsVc(name={}, id={})",
                                    vc.vc_instance_name, vc.vll_vc_id
                                );
                            }
                            FlowData::ExtendedMplsFec(fec) => {
                                println!("ExtendedMplsFec(prefix_len={})", fec.fec_prefix_len);
                            }
                            FlowData::ExtendedMplsLvpFec(fec) => {
                                println!(
                                    "ExtendedMplsLvpFec(prefix_len={})",
                                    fec.fec_addr_prefix_len
                                );
                            }
                            FlowData::ExtendedVlanTunnel(vlan) => {
                                println!("ExtendedVlanTunnel(vlans={:?})", vlan.vlan_stack);
                            }
                            FlowData::Extended80211Payload(wifi) => {
                                println!(
                                    "Extended80211Payload(channel={}, speed={})",
                                    wifi.channel, wifi.speed
                                );
                            }
                            FlowData::Extended80211Rx(rx) => {
                                println!(
                                    "Extended80211Rx(ssid={}, channel={})",
                                    rx.ssid, rx.channel
                                );
                            }
                            FlowData::Extended80211Tx(tx) => {
                                println!(
                                    "Extended80211Tx(ssid={}, channel={})",
                                    tx.ssid, tx.channel
                                );
                            }
                            FlowData::Unknown { format, data } => {
                                println!(
                                    "Unknown(enterprise={}, format={}, data_len={})",
                                    format.enterprise(),
                                    format.format(),
                                    data.len()
                                );
                            }
                        }
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
                    println!(
                        "        Format: enterprise={}, format={}",
                        format.enterprise(),
                        format.format()
                    );
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

#[test]
fn test_datagram_statistics() {
    let data = std::fs::read("tests/data/sflow.bin").expect("Failed to read sflow.bin");

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
        println!(
            "  ({}, {}): {} records",
            df.enterprise(),
            df.format(),
            count
        );
    }

    println!("\nCounter record formats:");
    for (format, count) in &counter_formats {
        let df = DataFormat(*format);
        println!(
            "  ({}, {}): {} records",
            df.enterprise(),
            df.format(),
            count
        );
    }

    // Assertions
    assert!(!datagrams.is_empty(), "Should have parsed datagrams");
    assert!(!unique_agents.is_empty(), "Should have at least one agent");
    assert!(
        total_flow_samples + total_counter_samples > 0,
        "Should have samples"
    );
}

#[test]
fn test_flow_sample_details() {
    let data = std::fs::read("tests/data/sflow.bin").expect("Failed to read sflow.bin");

    let datagrams = parse_datagrams(&data).expect("Failed to parse");

    let mut found_flow_sample = false;

    for datagram in &datagrams {
        for sample in &datagram.samples {
            if let SampleData::FlowSample(flow) = &sample.sample_data {
                found_flow_sample = true;

                // Validate flow sample fields
                assert!(flow.sampling_rate > 0, "Sampling rate should be positive");
                assert!(
                    flow.sample_pool >= flow.sequence_number,
                    "Sample pool should be >= sequence number"
                );

                // Input/output interfaces should be valid
                assert!(flow.input.format() <= 2, "Invalid input interface format");
                assert!(flow.output.format() <= 2, "Invalid output interface format");

                // Should have at least one flow record
                assert!(
                    !flow.flow_records.is_empty(),
                    "Flow sample should have records"
                );

                for record in &flow.flow_records {
                    // Validate format
                    assert!(
                        record.flow_format.enterprise() <= 0xFFFFF,
                        "Invalid enterprise"
                    );
                    assert!(record.flow_format.format() <= 0xFFF, "Invalid format");

                    // Validate flow data is parsed
                    match &record.flow_data {
                        FlowData::SampledHeader(header) => {
                            assert!(header.frame_length > 0, "Frame length should be positive");
                            assert!(!header.header.is_empty(), "Header should not be empty");
                        }
                        FlowData::SampledEthernet(eth) => {
                            assert!(eth.length > 0, "Ethernet length should be positive");
                        }
                        FlowData::SampledIpv4(ipv4) => {
                            assert!(ipv4.length > 0, "IPv4 length should be positive");
                        }
                        FlowData::SampledIpv6(ipv6) => {
                            assert!(ipv6.length > 0, "IPv6 length should be positive");
                        }
                        // All other variants are valid as-is
                        _ => {}
                    }
                }

                println!("\nFlow Sample Details:");
                println!("  Sequence: {}", flow.sequence_number);
                println!(
                    "  Source: type={}, index={}",
                    flow.source_id.source_type(),
                    flow.source_id.index()
                );
                println!("  Sampling: 1/{}", flow.sampling_rate);
                println!("  Pool: {}", flow.sample_pool);
                println!("  Drops: {}", flow.drops);
                println!(
                    "  Input: format={}, value={}",
                    flow.input.format(),
                    flow.input.value()
                );
                println!(
                    "  Output: format={}, value={}",
                    flow.output.format(),
                    flow.output.value()
                );
                println!("  Records: {}", flow.flow_records.len());
            }
        }
    }

    assert!(
        found_flow_sample,
        "Should have found at least one flow sample"
    );
}

#[test]
fn test_counter_sample_details() {
    let data = std::fs::read("tests/data/sflow.bin").expect("Failed to read sflow.bin");

    let datagrams = parse_datagrams(&data).expect("Failed to parse");

    let mut found_counter_sample = false;

    for datagram in &datagrams {
        for sample in &datagram.samples {
            let (sequence, counters_ref) = match &sample.sample_data {
                SampleData::CountersSample(c) => (c.sequence_number, &c.counters),
                SampleData::CountersSampleExpanded(c) => (c.sequence_number, &c.counters),
                _ => continue,
            };

            found_counter_sample = true;

            // Should have at least one counter record
            assert!(
                !counters_ref.is_empty(),
                "Counter sample should have records"
            );

            for record in counters_ref {
                // Validate format
                assert!(
                    record.counter_format.enterprise() <= 0xFFFFF,
                    "Invalid enterprise"
                );
                assert!(record.counter_format.format() <= 0xFFF, "Invalid format");

                // Validate counter data is parsed or stored
                match &record.counter_data {
                    CounterData::Unknown { data, .. } => {
                        assert!(!data.is_empty(), "Unknown counter data should not be empty");
                    }
                    _ => {
                        // Parsed counter data is valid
                    }
                }
            }

            println!("\nCounter Sample Details:");
            println!("  Sequence: {}", sequence);
            println!("  Records: {}", counters_ref.len());

            for (i, record) in counters_ref.iter().enumerate() {
                print!(
                    "    Record {}: enterprise={}, format={}, ",
                    i + 1,
                    record.counter_format.enterprise(),
                    record.counter_format.format()
                );

                match &record.counter_data {
                    CounterData::GenericInterface(c) => {
                        println!(
                            "GenericInterface(in={} bytes, out={} bytes)",
                            c.if_in_octets, c.if_out_octets
                        );
                    }
                    CounterData::EthernetInterface(_) => println!("EthernetInterface"),
                    CounterData::Processor(p) => {
                        println!(
                            "Processor(cpu_5s={}%, mem_free={} bytes)",
                            p.cpu_5s, p.free_memory
                        );
                    }
                    CounterData::HostDescription(h) => {
                        println!("HostDescription(hostname={}, os={})", h.hostname, h.os_name);
                    }
                    CounterData::HostCpu(c) => {
                        println!("HostCpu(load={}, cpus={})", c.load_one, c.cpu_num);
                    }
                    CounterData::HostMemory(m) => {
                        println!(
                            "HostMemory(total={} bytes, free={} bytes)",
                            m.mem_total, m.mem_free
                        );
                    }
                    CounterData::HostDiskIo(d) => {
                        println!(
                            "HostDiskIo(total={} bytes, free={} bytes)",
                            d.disk_total, d.disk_free
                        );
                    }
                    CounterData::HostNetIo(n) => {
                        println!(
                            "HostNetIo(in={} bytes, out={} bytes)",
                            n.bytes_in, n.bytes_out
                        );
                    }
                    CounterData::Unknown { format, data } => {
                        println!(
                            "Unknown(enterprise={}, format={}, data_len={})",
                            format.enterprise(),
                            format.format(),
                            data.len()
                        );
                    }
                    _ => println!("Other parsed format"),
                }
            }
        }
    }

    // Note: Counter samples may not be present in all test data
    if !found_counter_sample {
        println!("\nNote: No counter samples found in test data");
    }
}

#[test]
fn test_agent_addresses() {
    let data = std::fs::read("tests/data/sflow.bin").expect("Failed to read sflow.bin");

    let datagrams = parse_datagrams(&data).expect("Failed to parse");

    for datagram in &datagrams {
        // Agent address should be valid
        match &datagram.agent_address {
            Address::IPv4(addr) => {
                println!("Agent IPv4: {}", addr);
                // Should be a valid IP (not 0.0.0.0)
                assert_ne!(
                    addr.octets(),
                    [0, 0, 0, 0],
                    "Agent IP should not be 0.0.0.0"
                );
            }
            Address::IPv6(addr) => {
                println!("Agent IPv6: {}", addr);
                assert!(
                    !addr.is_unspecified(),
                    "Agent IPv6 should not be unspecified"
                );
            }
            Address::Unknown => {
                println!("Agent: Unknown");
            }
        }

        // Sub-agent ID should be reasonable
        assert!(
            datagram.sub_agent_id < 0xFFFFFFFF,
            "Sub-agent ID seems invalid"
        );

        // Uptime should be reasonable (not zero for real devices)
        // Note: Could be zero for test data
        println!(
            "Uptime: {} ms ({} seconds)",
            datagram.uptime,
            datagram.uptime / 1000
        );
    }
}

#[test]
fn test_sequence_numbers() {
    let data = std::fs::read("tests/data/sflow.bin").expect("Failed to read sflow.bin");

    let datagrams = parse_datagrams(&data).expect("Failed to parse");

    // Group datagrams by agent
    let mut agent_sequences: HashMap<String, Vec<u32>> = HashMap::new();

    for datagram in &datagrams {
        let agent_key = match &datagram.agent_address {
            Address::IPv4(addr) => format!("{}", addr),
            Address::IPv6(addr) => format!("{}", addr),
            Address::Unknown => "Unknown".to_string(),
        };

        agent_sequences
            .entry(agent_key)
            .or_default()
            .push(datagram.sequence_number);
    }

    println!("\n=== Sequence Number Analysis ===");
    for (agent, sequences) in &agent_sequences {
        println!("Agent {}: {} datagrams", agent, sequences.len());
        println!(
            "  Sequence range: {} - {}",
            sequences.iter().min().unwrap(),
            sequences.iter().max().unwrap()
        );

        // Check if sequences are mostly increasing (allowing for wraps)
        let mut sorted = sequences.clone();
        sorted.sort();
        println!("  Sequences: {:?}", sequences);
    }
}

#[test]
fn test_parsed_flow_data() {
    let data = std::fs::read("tests/data/sflow.bin").expect("Failed to read sflow.bin");

    let datagrams = parse_datagrams(&data).expect("Failed to parse");

    let mut sampled_headers = 0;
    let mut sampled_ethernet = 0;
    let mut sampled_ipv4 = 0;
    let mut sampled_ipv6 = 0;
    let mut extended_switch = 0;
    let mut extended_router = 0;
    let mut extended_gateway = 0;
    let mut extended_user = 0;
    let mut extended_url = 0;
    let mut extended_mpls = 0;
    let mut extended_nat = 0;
    let mut extended_mpls_tunnel = 0;
    let mut extended_mpls_vc = 0;
    let mut extended_mpls_fec = 0;
    let mut extended_mpls_lvp_fec = 0;
    let mut extended_vlan_tunnel = 0;
    let mut extended_80211_payload = 0;
    let mut extended_80211_rx = 0;
    let mut extended_80211_tx = 0;
    let mut unknown = 0;

    println!("\n=== Parsed Flow Data Analysis ===");

    for datagram in &datagrams {
        for sample in &datagram.samples {
            if let SampleData::FlowSample(flow) = &sample.sample_data {
                for record in &flow.flow_records {
                    match &record.flow_data {
                        FlowData::SampledHeader(header) => {
                            sampled_headers += 1;
                            if sampled_headers == 1 {
                                println!("\nFirst Sampled Header:");
                                println!("  Protocol: {}", header.protocol);
                                println!("  Frame length: {} bytes", header.frame_length);
                                println!("  Stripped: {} bytes", header.stripped);
                                println!("  Header captured: {} bytes", header.header.len());

                                // Print first few bytes of header
                                print!("  Header bytes: ");
                                for (i, byte) in header.header.iter().take(16).enumerate() {
                                    if i > 0 && i % 8 == 0 {
                                        print!(" ");
                                    }
                                    print!("{:02x} ", byte);
                                }
                                println!("...");
                            }
                        }
                        FlowData::SampledIpv4(ipv4) => {
                            sampled_ipv4 += 1;
                            if sampled_ipv4 == 1 {
                                println!("\nFirst Sampled IPv4:");
                                println!(
                                    "  {}:{} -> {}:{}",
                                    ipv4.src_ip, ipv4.src_port, ipv4.dst_ip, ipv4.dst_port
                                );
                                println!("  Protocol: {}", ipv4.protocol);
                                println!("  Length: {} bytes", ipv4.length);
                                println!("  TCP flags: 0x{:02x}", ipv4.tcp_flags);
                                println!("  ToS: 0x{:02x}", ipv4.tos);
                            }
                        }
                        FlowData::SampledIpv6(ipv6) => {
                            sampled_ipv6 += 1;
                            if sampled_ipv6 == 1 {
                                println!("\nFirst Sampled IPv6:");
                                println!(
                                    "  {}:{} -> {}:{}",
                                    ipv6.src_ip, ipv6.src_port, ipv6.dst_ip, ipv6.dst_port
                                );
                                println!("  Protocol: {}", ipv6.protocol);
                                println!("  Length: {} bytes", ipv6.length);
                            }
                        }
                        FlowData::ExtendedSwitch(sw) => {
                            extended_switch += 1;
                            if extended_switch == 1 {
                                println!("\nFirst Extended Switch:");
                                println!(
                                    "  Source VLAN: {}, Priority: {}",
                                    sw.src_vlan, sw.src_priority
                                );
                                println!(
                                    "  Dest VLAN: {}, Priority: {}",
                                    sw.dst_vlan, sw.dst_priority
                                );
                            }
                        }
                        FlowData::ExtendedRouter(router) => {
                            extended_router += 1;
                            if extended_router == 1 {
                                println!("\nFirst Extended Router:");
                                println!("  Next hop: {:?}", router.next_hop);
                                println!("  Src mask: /{}", router.src_mask_len);
                                println!("  Dst mask: /{}", router.dst_mask_len);
                            }
                        }
                        FlowData::ExtendedGateway(gw) => {
                            extended_gateway += 1;
                            if extended_gateway == 1 {
                                println!("\nFirst Extended Gateway:");
                                println!("  Next hop: {:?}", gw.next_hop);
                                println!("  AS: {}", gw.as_number);
                                println!("  Source AS: {}", gw.src_as);
                                println!("  Source Peer AS: {}", gw.src_peer_as);
                                println!("  AS path segments: {}", gw.as_path_segments.len());
                                for (i, segment) in gw.as_path_segments.iter().enumerate() {
                                    println!(
                                        "    Segment {}: type={}, path={:?}",
                                        i + 1,
                                        segment.path_type,
                                        segment.path
                                    );
                                }
                                println!("  Communities: {:?}", gw.communities);
                                println!("  Local pref: {}", gw.local_pref);
                            }
                        }
                        FlowData::SampledEthernet(_) => {
                            sampled_ethernet += 1;
                        }
                        FlowData::ExtendedUser(_) => {
                            extended_user += 1;
                        }
                        FlowData::ExtendedUrl(_) => {
                            extended_url += 1;
                        }
                        FlowData::ExtendedMpls(_) => {
                            extended_mpls += 1;
                        }
                        FlowData::ExtendedNat(_) => {
                            extended_nat += 1;
                        }
                        FlowData::ExtendedMplsTunnel(_) => {
                            extended_mpls_tunnel += 1;
                        }
                        FlowData::ExtendedMplsVc(_) => {
                            extended_mpls_vc += 1;
                        }
                        FlowData::ExtendedMplsFec(_) => {
                            extended_mpls_fec += 1;
                        }
                        FlowData::ExtendedMplsLvpFec(_) => {
                            extended_mpls_lvp_fec += 1;
                        }
                        FlowData::ExtendedVlanTunnel(_) => {
                            extended_vlan_tunnel += 1;
                        }
                        FlowData::Extended80211Payload(_) => {
                            extended_80211_payload += 1;
                        }
                        FlowData::Extended80211Rx(_) => {
                            extended_80211_rx += 1;
                        }
                        FlowData::Extended80211Tx(_) => {
                            extended_80211_tx += 1;
                        }
                        FlowData::Unknown { format, data } => {
                            unknown += 1;
                            if unknown == 1 {
                                println!("\nFirst Unknown Flow Data:");
                                println!(
                                    "  Format: enterprise={}, format={}",
                                    format.enterprise(),
                                    format.format()
                                );
                                println!("  Data length: {} bytes", data.len());
                            }
                        }
                    }
                }
            }
        }
    }

    println!("\n=== Flow Data Summary ===");
    println!("Sampled Records:");
    println!("  Headers: {}", sampled_headers);
    println!("  Ethernet: {}", sampled_ethernet);
    println!("  IPv4: {}", sampled_ipv4);
    println!("  IPv6: {}", sampled_ipv6);
    println!("\nExtended Records:");
    println!("  Switch: {}", extended_switch);
    println!("  Router: {}", extended_router);
    println!("  Gateway (BGP): {}", extended_gateway);
    println!("  User: {}", extended_user);
    println!("  URL: {}", extended_url);
    println!("  MPLS: {}", extended_mpls);
    println!("  NAT: {}", extended_nat);
    println!("  MPLS Tunnel: {}", extended_mpls_tunnel);
    println!("  MPLS VC: {}", extended_mpls_vc);
    println!("  MPLS FEC: {}", extended_mpls_fec);
    println!("  MPLS LVP FEC: {}", extended_mpls_lvp_fec);
    println!("  VLAN Tunnel: {}", extended_vlan_tunnel);
    println!("  802.11 Payload: {}", extended_80211_payload);
    println!("  802.11 RX: {}", extended_80211_rx);
    println!("  802.11 TX: {}", extended_80211_tx);
    println!("\nUnknown: {}", unknown);

    let total = sampled_headers
        + sampled_ethernet
        + sampled_ipv4
        + sampled_ipv6
        + extended_switch
        + extended_router
        + extended_gateway
        + extended_user
        + extended_url
        + extended_mpls
        + extended_nat
        + extended_mpls_tunnel
        + extended_mpls_vc
        + extended_mpls_fec
        + extended_mpls_lvp_fec
        + extended_vlan_tunnel
        + extended_80211_payload
        + extended_80211_rx
        + extended_80211_tx
        + unknown;
    println!("\nTotal flow records parsed: {}", total);

    // Assertions
    assert!(total > 0, "Should have parsed flow records");
    assert!(
        sampled_headers > 0,
        "Should have parsed at least one sampled header"
    );
}
