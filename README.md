# InMon sFlow v5 Parser

[![CI Status](https://img.shields.io/github/actions/workflow/status/nxthdr/sflow-parser/ci.yml?logo=github&label=build)](https://github.com/nxthdr/sflow-parser/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/sflow-parser?color=blue&logo=rust)](https://crates.io/crates/sflow-parser)
[![Docs](https://img.shields.io/docsrs/sflow-parser?logo=rust)](https://docs.rs/sflow-parser)
[![Codecov](https://img.shields.io/codecov/c/github/nxthdr/sflow-parser?logo=codecov)](https://codecov.io/gh/nxthdr/sflow-parser)
[![License](https://img.shields.io/crates/l/sflow-parser)](LICENSE)

A dependency-free Rust library for parsing InMon sFlow version 5 datagrams as specified in [https://sflow.org/sflow_version_5.txt](https://sflow.org/sflow_version_5.txt).

## Implementation Status

The implementation is fully complete. Each flow and counter record type of the RFC is implemented and has a corresponding unit test.
Fuzz testing does not show any issues.

**Core Features:** ✅ Complete
- Datagram structure (version, agent, sequence, uptime)
- All 4 sample envelope types (FlowSample, CountersSample, Expanded variants)
- XDR encoding (big-endian, 4-byte alignment, opaque data)
- Address types (IPv4, IPv6, Unknown)
- Data structures (DataFormat, DataSource, Interface)

### Flow Records

| Format | Enterprise | Name | Status |
|--------|-----------|------|--------|
| 1 | 0 | Sampled Header | ✅ Implemented |
| 2 | 0 | Sampled Ethernet | ✅ Implemented |
| 3 | 0 | Sampled IPv4 | ✅ Implemented |
| 4 | 0 | Sampled IPv6 | ✅ Implemented |
| 1001 | 0 | Extended Switch | ✅ Implemented |
| 1002 | 0 | Extended Router | ✅ Implemented |
| 1003 | 0 | Extended Gateway (BGP) | ✅ Implemented |
| 1004 | 0 | Extended User | ✅ Implemented |
| 1005 | 0 | Extended URL | ✅ Implemented |
| 1006 | 0 | Extended MPLS | ✅ Implemented |
| 1007 | 0 | Extended NAT | ✅ Implemented |
| 1008 | 0 | Extended MPLS Tunnel | ✅ Implemented |
| 1009 | 0 | Extended MPLS VC | ✅ Implemented |
| 1010 | 0 | Extended MPLS FEC | ✅ Implemented |
| 1011 | 0 | Extended MPLS LVP FEC | ✅ Implemented |
| 1012 | 0 | Extended VLAN Tunnel | ✅ Implemented |
| 1014 | 0 | Extended 802.11 Payload | ✅ Implemented |
| 1015 | 0 | Extended 802.11 RX | ✅ Implemented |
| 1016 | 0 | Extended 802.11 TX | ✅ Implemented |

### Counter Records

| Format | Enterprise | Name | Status |
|--------|-----------|------|--------|
| 1 | 0 | Generic Interface | ✅ Implemented |
| 2 | 0 | Ethernet Interface | ✅ Implemented |
| 3 | 0 | Token Ring | ✅ Implemented |
| 4 | 0 | 100BaseVG Interface | ✅ Implemented |
| 5 | 0 | VLAN | ✅ Implemented |
| 1001 | 0 | Processor | ✅ Implemented |
| 1002 | 0 | Radio Utilization | ✅ Implemented |
| 1004 | 0 | OpenFlow Port | ✅ Implemented |
| 1005 | 0 | OpenFlow Port Name | ✅ Implemented |
| 2000 | 0 | Host Description | ✅ Implemented |
| 2001 | 0 | Host Adapters | ✅ Implemented |
| 2002 | 0 | Host Parent | ✅ Implemented |
| 2003 | 0 | Host CPU | ✅ Implemented |
| 2004 | 0 | Host Memory | ✅ Implemented |
| 2005 | 0 | Host Disk I/O | ✅ Implemented |
| 2006 | 0 | Host Network I/O | ✅ Implemented |
| 2100 | 0 | Virtual Node | ✅ Implemented |
| 2101 | 0 | Virtual CPU | ✅ Implemented |
| 2102 | 0 | Virtual Memory | ✅ Implemented |
| 2103 | 0 | Virtual Disk I/O | ✅ Implemented |
| 2104 | 0 | Virtual Network I/O | ✅ Implemented |
| 2206 | 0 | App Resources | ✅ Implemented |

## Testing

### Unit & Integration Tests

Run the comprehensive test suite:
```bash
make test              # Run all tests
make test-unit         # Run unit tests only
make test-integration  # Run integration tests only
```

### Fuzz Testing

The project includes comprehensive fuzz testing using `cargo-fuzz`:

```bash
make fuzz-install    # Install fuzzing tools (requires nightly Rust)
make fuzz-single     # Fuzz single datagram parsing (60s)
make fuzz-multiple   # Fuzz multiple datagrams parsing (60s)
make fuzz-structured # Fuzz with structured inputs (60s)
make fuzz-all        # Run all fuzzers (5 minutes each)
```

## License

This project is licensed under the [MIT License](LICENSE).

sFlow® is a registered trademark of InMon Corp. This implementation is based on the
sFlow version 5 specification available at [https://sflow.org/sflow_version_5.txt](https://sflow.org/sflow_version_5.txt) and
is licensed under the terms provided at [https://inmon.com/technology/sflowlicense.txt](https://inmon.com/technology/sflowlicense.txt).
