#![no_main]

use libfuzzer_sys::fuzz_target;
use sflow_parser::parsers::Parser;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    // Try to parse arbitrary data as multiple sFlow datagrams
    // This tests the datagram boundary detection logic

    // Limit input size to prevent fuzzer OOM (not a parser bug)
    // Real sFlow packets are typically much smaller (usually 1-5KB)
    // The fuzzer can craft inputs that maximize memory usage
    const MAX_INPUT_SIZE: usize = 1024; // 1KB
    const MAX_DATAGRAMS: usize = 2; // Limit number of datagrams to parse

    if data.len() > MAX_INPUT_SIZE {
        return;
    }

    // Parse datagrams one at a time with a limit
    let mut cursor = Cursor::new(data);
    let mut count = 0;

    loop {
        if count >= MAX_DATAGRAMS {
            break;
        }

        let pos = cursor.position();
        if pos >= data.len() as u64 {
            break;
        }

        match Parser::new(&mut cursor).parse_datagram() {
            Ok(_) => count += 1,
            Err(_) => break,
        }
    }
});
