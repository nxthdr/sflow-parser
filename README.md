# InMon sFlow v5 Parser

[![CI Status](https://img.shields.io/github/actions/workflow/status/nxthdr/sflow-parser/ci.yml?logo=github&label=build)](https://github.com/nxthdr/sflow-parser/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/sflow-parser?color=blue&logo=rust)](https://crates.io/crates/sflow-parser)
[![Docs](https://img.shields.io/docsrs/sflow-parser?logo=rust)](https://docs.rs/sflow-parser)
[![Codecov](https://img.shields.io/codecov/c/github/nxthdr/sflow-parser?logo=codecov)](https://codecov.io/gh/nxthdr/sflow-parser)
[![License](https://img.shields.io/crates/l/sflow-parser)](LICENSE)

> [!WARNING]
> Currently in early-stage development.

A Rust library for parsing InMon sFlow version 5 datagrams as specified in [https://sflow.org/sflow_version_5.txt](https://sflow.org/sflow_version_5.txt).

## Core Parsing

- ✅ **Datagram structure** - Version, agent, sequence, uptime
- ✅ **Sample envelopes** - All 4 types (FlowSample, CountersSample, Expanded variants)
- ✅ **XDR encoding** - Big-endian, 4-byte alignment, opaque data
- ✅ **Address types** - IPv4, IPv6, Unknown
- ✅ **Data structures** - DataFormat, DataSource, Interface

## Flow Record Parsing

### ✅ Implemented (17 formats - 100% of standard formats)

| Format | Enterprise | Name | Status |
|--------|-----------|------|--------|
| 1 | 0 | Sampled Header | ✅ Fully parsed |
| 2 | 0 | Sampled Ethernet | ✅ Fully parsed |
| 3 | 0 | Sampled IPv4 | ✅ Fully parsed |
| 4 | 0 | Sampled IPv6 | ✅ Fully parsed |
| 1001 | 0 | Extended Switch | ✅ Fully parsed |
| 1002 | 0 | Extended Router | ✅ Fully parsed |
| 1004 | 0 | Extended Gateway (BGP) | ✅ Fully parsed |
| 1005 | 0 | Extended User | ✅ Fully parsed |
| 1006 | 0 | Extended URL | ✅ Fully parsed |
| 1007 | 0 | Extended MPLS | ✅ Fully parsed |
| 1008 | 0 | Extended NAT | ✅ Fully parsed |
| 1009 | 0 | Extended MPLS Tunnel | ✅ Fully parsed |
| 1010 | 0 | Extended MPLS VC | ✅ Fully parsed |
| 1011 | 0 | Extended MPLS FEC | ✅ Fully parsed |
| 1012 | 0 | Extended MPLS LVP FEC | ✅ Fully parsed |
| 1013 | 0 | Extended VLAN Tunnel | ✅ Fully parsed |
| 1014 | 0 | Extended 802.11 Payload | ✅ Fully parsed |
| 1015 | 0 | Extended 802.11 RX | ✅ Fully parsed |
| 1016 | 0 | Extended 802.11 TX | ✅ Fully parsed |

## Counter Record Parsing

### ✅ Implemented (9 formats - Most Common Formats)

| Format | Enterprise | Name | Status |
|--------|-----------|------|--------|
| 1 | 0 | Generic Interface Counters | ✅ Fully parsed |
| 2 | 0 | Ethernet Interface Counters | ✅ Fully parsed |
| 1001 | 0 | Processor Counters | ✅ Fully parsed |
| 2000 | 0 | Host Description | ✅ Fully parsed |
| 2001 | 0 | Host Adapters | ✅ Fully parsed |
| 2003 | 0 | Host CPU | ✅ Fully parsed |
| 2004 | 0 | Host Memory | ✅ Fully parsed |
| 2005 | 0 | Host Disk I/O | ✅ Fully parsed |
| 2006 | 0 | Host Network I/O | ✅ Fully parsed |

### 📦 Models Defined, Parsers TODO (19 formats)

Less common formats with models defined but parsers not yet implemented:
- Token Ring, 100BaseVG, VLAN counters
- Radio Utilization
- Host Parent
- Virtual machine counters (5 formats)
- OpenFlow counters (2 formats)
- App Resources
- And others...

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
