#![no_main]

use libfuzzer_sys::fuzz_target;
use sflow_parser::parsers::parse_datagram;

fuzz_target!(|data: &[u8]| {
    // Try to parse arbitrary data as an sFlow datagram
    // The parser should never panic, only return errors

    // Limit input size to prevent fuzzer OOM (not a parser bug)
    // Real sFlow packets are typically much smaller (usually 1-10KB)
    const MAX_INPUT_SIZE: usize = 16 * 1024; // 16KB
    if data.len() > MAX_INPUT_SIZE {
        return;
    }

    let _ = parse_datagram(data);
});
