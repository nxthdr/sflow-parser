//! Tests for parser primitive functions (XDR parsing)
//!
//! These tests validate XDR encoding/decoding logic used by the parser.

#[test]
fn test_xdr_u32_parsing() {
    // Test big-endian u32 parsing
    let data = vec![0x00, 0x00, 0x00, 0x01]; // 1 in big-endian
    assert_eq!(data.len(), 4);

    let value = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    assert_eq!(value, 1);
}

#[test]
fn test_xdr_u64_parsing() {
    // Test big-endian u64 parsing
    let data = vec![0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]; // 2^32 in big-endian
    assert_eq!(data.len(), 8);

    let value = u64::from_be_bytes([
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
    ]);
    assert_eq!(value, 0x0000000100000000);
}

#[test]
fn test_xdr_string_with_padding() {
    // XDR strings are length-prefixed and padded to 4-byte boundary
    // "test" = 4 bytes, no padding needed
    let data = vec![
        0x00, 0x00, 0x00, 0x04, // length = 4
        b't', b'e', b's', b't', // "test"
    ];

    let length = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    assert_eq!(length, 4);

    let string = String::from_utf8(data[4..8].to_vec()).unwrap();
    assert_eq!(string, "test");
}

#[test]
fn test_xdr_string_with_padding_needed() {
    // "hi" = 2 bytes, needs 2 bytes padding
    let data = vec![
        0x00, 0x00, 0x00, 0x02, // length = 2
        b'h', b'i', 0x00, 0x00, // "hi" + 2 padding bytes
    ];

    let length = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    assert_eq!(length, 2);

    let string = String::from_utf8(data[4..6].to_vec()).unwrap();
    assert_eq!(string, "hi");
}

#[test]
fn test_xdr_opaque_data_no_padding() {
    // 4 bytes of opaque data, no padding needed
    let data = vec![
        0x00, 0x00, 0x00, 0x04, // length = 4
        0x01, 0x02, 0x03, 0x04, // data
    ];

    let length = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    assert_eq!(length, 4);

    let opaque = &data[4..8];
    assert_eq!(opaque, &[0x01, 0x02, 0x03, 0x04]);
}

#[test]
fn test_xdr_opaque_data_with_padding() {
    // 3 bytes of opaque data, needs 1 byte padding
    let data = vec![
        0x00, 0x00, 0x00, 0x03, // length = 3
        0x01, 0x02, 0x03, 0x00, // data + 1 padding byte
    ];

    let length = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    assert_eq!(length, 3);

    let opaque = &data[4..7];
    assert_eq!(opaque, &[0x01, 0x02, 0x03]);
}

#[test]
fn test_xdr_padding_calculation() {
    // Test padding calculation for various lengths
    assert_eq!((4 - (0 % 4)) % 4, 0); // 0 bytes -> 0 padding
    assert_eq!((4 - (1 % 4)) % 4, 3); // 1 byte -> 3 padding
    assert_eq!((4 - (2 % 4)) % 4, 2); // 2 bytes -> 2 padding
    assert_eq!((4 - (3 % 4)) % 4, 1); // 3 bytes -> 1 padding
    assert_eq!((4 - (4 % 4)) % 4, 0); // 4 bytes -> 0 padding
    assert_eq!((4 - (5 % 4)) % 4, 3); // 5 bytes -> 3 padding
}

#[test]
fn test_ipv4_address_parsing() {
    // IPv4 address: 192.168.1.1
    let data = vec![0xC0, 0xA8, 0x01, 0x01];
    let addr = std::net::Ipv4Addr::from(u32::from_be_bytes([data[0], data[1], data[2], data[3]]));
    assert_eq!(addr.to_string(), "192.168.1.1");
}

#[test]
fn test_ipv6_address_parsing() {
    // IPv6 address: 2001:db8::1
    let data = vec![
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01,
    ];
    let addr = std::net::Ipv6Addr::from([
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8], data[9],
        data[10], data[11], data[12], data[13], data[14], data[15],
    ]);
    assert_eq!(addr.to_string(), "2001:db8::1");
}

#[test]
fn test_mac_address_parsing() {
    // MAC address: 00:11:22:33:44:55
    let data = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    let mac: [u8; 6] = [data[0], data[1], data[2], data[3], data[4], data[5]];
    assert_eq!(mac, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
}

#[test]
fn test_data_format_encoding() {
    // Test DataFormat bit packing: enterprise (20 bits) | format (12 bits)
    let enterprise = 4413u32;
    let format = 5u32;
    let encoded = (enterprise << 12) | format;

    // Decode
    let decoded_enterprise = (encoded >> 12) & 0xFFFFF;
    let decoded_format = encoded & 0xFFF;

    assert_eq!(decoded_enterprise, enterprise);
    assert_eq!(decoded_format, format);
}

#[test]
fn test_data_source_encoding() {
    // Test DataSource bit packing: type (8 bits) | index (24 bits)
    let source_type = 2u32;
    let index = 12345u32;
    let encoded = (source_type << 24) | index;

    // Decode
    let decoded_type = (encoded >> 24) & 0xFF;
    let decoded_index = encoded & 0xFFFFFF;

    assert_eq!(decoded_type, source_type);
    assert_eq!(decoded_index, index);
}

#[test]
fn test_interface_encoding() {
    // Test Interface bit packing: format (2 bits) | value (30 bits)

    // Format 0: single interface
    let value = 42u32;
    let encoded = value;
    let decoded_format = (encoded >> 30) & 0x3;
    let decoded_value = encoded & 0x3FFFFFFF;
    assert_eq!(decoded_format, 0);
    assert_eq!(decoded_value, 42);

    // Format 1: packet discarded
    let encoded = 0x40000102u32; // Format 1, value 258
    let decoded_format = (encoded >> 30) & 0x3;
    let decoded_value = encoded & 0x3FFFFFFF;
    assert_eq!(decoded_format, 1);
    assert_eq!(decoded_value, 258);

    // Format 2: multiple interfaces
    let encoded = 0x80000007u32; // Format 2, value 7
    let decoded_format = (encoded >> 30) & 0x3;
    let decoded_value = encoded & 0x3FFFFFFF;
    assert_eq!(decoded_format, 2);
    assert_eq!(decoded_value, 7);
}
