//! Comprehensive parser test helpers
//!
//! Helper functions for building test data for comprehensive parser tests.
//! These helpers create binary sFlow v5 datagrams for testing.
//!
//! Reference: https://sflow.org/sflow_version_5.txt

#[allow(unused_imports)]
pub(super) use sflow_parser::models::core::*;

/// Encode a u32 as big-endian bytes
pub(crate) fn u32_bytes(value: u32) -> [u8; 4] {
    [
        (value >> 24) as u8,
        (value >> 16) as u8,
        (value >> 8) as u8,
        value as u8,
    ]
}

/// Calculate the total sample length for a flow sample
/// Sample length = flow_sample_header + sum(flow_record_header + flow_record_data)
/// Flow sample header = 32 bytes (8 fields × 4 bytes)
/// Flow record header = 8 bytes (type + length)
/// Flow record data = varies (must be 4-byte aligned)
pub(crate) fn calculate_flow_sample_length(flow_records_data: &[usize]) -> u32 {
    const FLOW_SAMPLE_HEADER: usize = 32; // 8 fields × 4 bytes
    const RECORD_HEADER: usize = 8; // type(4) + length(4)

    let records_total: usize = flow_records_data
        .iter()
        .map(|&data_len| RECORD_HEADER + data_len)
        .sum();

    (FLOW_SAMPLE_HEADER + records_total) as u32
}

/// Build a flow sample test with a single flow record
/// This reduces code duplication across tests
pub(crate) fn build_flow_sample_test(record_type: u32, record_data: &[u8]) -> Vec<u8> {
    let mut data = create_datagram_header(1);

    let record_length = record_data.len();
    let sample_length = calculate_flow_sample_length(&[record_length]);

    // Flow sample header
    data.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // sample type = flow sample
    data.extend_from_slice(&u32_bytes(sample_length));
    data.extend_from_slice(&[
        0x00, 0x00, 0x00, 0x01, // sequence number
        0x00, 0x00, 0x00, 0x01, // source ID
        0x00, 0x00, 0x04, 0x00, // sampling rate = 1024
        0x00, 0x00, 0x00, 0x64, // sample pool = 100
        0x00, 0x00, 0x00, 0x00, // drops = 0
        0x00, 0x00, 0x00, 0x01, // input interface = 1
        0x00, 0x00, 0x00, 0x02, // output interface = 2
        0x00, 0x00, 0x00, 0x01, // number of flow records = 1
    ]);

    // Flow record header
    data.extend_from_slice(&u32_bytes(record_type)); // flow record type
    data.extend_from_slice(&u32_bytes(record_length as u32)); // flow record length

    // Flow record data
    data.extend_from_slice(record_data);

    data
}

/// Build a counter sample test with a single counter record
pub(crate) fn build_counter_sample_test(record_type: u32, record_data: &[u8]) -> Vec<u8> {
    let mut data = create_datagram_header(1);

    let record_length = record_data.len();
    // Counter sample header = 12 bytes (3 fields × 4 bytes)
    // Record header = 8 bytes (type + length)
    let sample_length = 12 + 8 + record_length;

    // Counter sample header
    data.extend_from_slice(&[0x00, 0x00, 0x00, 0x02]); // sample type = counter sample
    data.extend_from_slice(&u32_bytes(sample_length as u32));
    data.extend_from_slice(&[
        0x00, 0x00, 0x00, 0x01, // sequence number
        0x00, 0x00, 0x00, 0x01, // source ID
        0x00, 0x00, 0x00, 0x01, // number of counter records = 1
    ]);

    // Counter record header
    data.extend_from_slice(&u32_bytes(record_type)); // counter record type
    data.extend_from_slice(&u32_bytes(record_length as u32)); // counter record length

    // Counter record data
    data.extend_from_slice(record_data);

    data
}

/// Create a minimal sFlow v5 datagram header
pub(crate) fn create_datagram_header(num_samples: u32) -> Vec<u8> {
    let mut header = Vec::new();

    // Version = 5
    header.extend_from_slice(&[0x00, 0x00, 0x00, 0x05]);

    // Agent address (IPv4: 192.168.1.1)
    header.extend_from_slice(&[
        0x00, 0x00, 0x00, 0x01, // address type = IPv4
        0xC0, 0xA8, 0x01, 0x01, // 192.168.1.1
    ]);

    // Sub-agent ID = 0
    header.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

    // Sequence number = 1
    header.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);

    // Uptime = 100ms
    header.extend_from_slice(&[0x00, 0x00, 0x00, 0x64]);

    // Number of samples
    header.extend_from_slice(&u32_bytes(num_samples));

    header
}
