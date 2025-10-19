# InMon sFlow v5 Parser

[![CI Status](https://img.shields.io/github/actions/workflow/status/nxthdr/sflow-parser/ci.yml?logo=github&label=build)](https://github.com/nxthdr/sflow-parser/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/sflow-parser?color=blue&logo=rust)](https://crates.io/crates/sflow-parser)
[![Docs](https://img.shields.io/docsrs/sflow-parser?logo=rust)](https://docs.rs/sflow-parser)
[![Codecov](https://img.shields.io/codecov/c/github/nxthdr/sflow-parser?logo=codecov)](https://codecov.io/gh/nxthdr/sflow-parser)
[![License](https://img.shields.io/crates/l/sflow-parser)](LICENSE)

A dependency-free Rust library for parsing InMon sFlow version 5 datagrams as specified in [https://sflow.org/sflow_version_5.txt](https://sflow.org/sflow_version_5.txt).

## Implementation Status

All core sFlow v5 specifications and common extensions are implemented.
Each implemented flow and counter record type has a corresponding unit test.

The flows and counters types tables below list all sFlow structure numbers as defined in the [official sFlow structure registry](https://sflow.org/developers/structures.php).

**Status Legend:**
- ✅ Implemented
- ⬜ Not implemented
- ⚠️ Deprecated

### Specifications

| Year | Specification | Description | Status |
|------|--------------|-------------|--------|
| 2004 | [sFlow Version 5](https://sflow.org/sflow_version_5.txt) | Core protocol, base flow and counter records | ✅ |
| 2007 | [sFlow 802.11 Structures](https://sflow.org/sflow_80211.txt) | Wireless/802.11 monitoring extensions | ✅ |
| 2010 | [sFlow Host Structures](https://sflow.org/sflow_host.txt) | Host and virtual machine performance metrics | ✅ |
| 2011 | [sFlow HTTP Structures](https://sflow.org/sflow_http.txt) | HTTP performance metrics | ⬜ |
| 2011 | [sFlow Java Virtual Machine Structures](https://sflow.org/sflow_jvm.txt) | JVM performance metrics | ⬜ |
| 2011 | [sFlow Memcache Structures](https://sflow.org/sflow_memcache.txt) | Memcache performance metrics | ⬜ |
| 2012 | [sFlow NVML GPU Structures](https://sflow.org/sflow_nvml.txt) | NVIDIA GPU performance, status, and health | ⬜ |
| 2012 | [sFlow Application Structures](https://sflow.org/sflow_application.txt) | Application resource monitoring | ✅ |
| 2012 | [sFlow LAG Counters Structure](https://sflow.org/sflow_lag.txt) | IEEE 802.1AX Link Aggregation (LACP) | ⬜ |
| 2012 | [sFlow Tunnel Structures](https://sflow.org/sflow_tunnels.txt) | Encapsulation/decapsulation (VXLAN, GRE, etc.) | ⬜ |
| 2012 | [sFlow Port NAT Structures](https://sflow.org/sflow_pnat.txt) | Port-based NAT mapping | ⬜ |
| 2013 | [sFlow InfiniBand Structures](https://sflow.org/draft_sflow_infiniband_2.txt) | InfiniBand network monitoring | ⬜ |
| 2014 | [sFlow OpenFlow Structures](https://sflow.org/sflow_openflow.txt) | OpenFlow port monitoring | ✅ |
| 2015 | [sFlow Host TCP/IP Counters](https://sflow.org/sflow_host_ip.txt) | Host IP, ICMP, TCP, and UDP counters | ⬜ |
| 2015 | [sFlow Broadcom ASIC Table Utilization](https://sflow.org/sflow_broadcom_tables.txt) | Hardware table utilization for Broadcom ASICs | ⬜ |
| 2015 | [sFlow Broadcom Buffer Utilization](https://sflow.org/bv-sflow.txt) | Buffer utilization for Broadcom switches | ⬜ |
| 2016 | [sFlow Optical Interface Structures](https://sflow.org/sflow_optics.txt) | Pluggable optical modules (SFP, QSFP, etc.) | ⬜ |
| 2020 | [sFlow Dropped Packet Notification](https://sflow.org/sflow_drops.txt) | Reports on dropped packets with reason codes | ⬜ |
| 2021 | [sFlow Transit Delay Structures](https://sflow.org/sflow_transit.txt) | Delay and queue depth for sampled packets | ⬜ |

**Note:** See [sFlow Errata](https://sflow.org/developers/errata.php) for corrections to published specifications.

### Core Features

**Datagram Structure:**
- Version 5 protocol support
- Agent address (IPv4/IPv6)
- Sub-agent ID for distributed architectures
- Sequence number tracking
- System uptime
- Multiple samples per datagram

**Sample Types:**

sFlow datagrams contain sample records. Each sample record has a format type that determines its structure:

| Enterprise | Format | Name | Description | Status |
|-----------|--------|------|-------------|--------|
| 0 | 1 | Flow Sample | Compact format for ifIndex < 2^24 | ✅ |
| 0 | 2 | Counters Sample | Compact format for ifIndex < 2^24 | ✅ |
| 0 | 3 | Flow Sample Expanded | Extended format for ifIndex >= 2^24 | ✅ |
| 0 | 4 | Counters Sample Expanded | Extended format for ifIndex >= 2^24 | ✅ |
| 0 | 5 | Discarded Packet | Dropped packet with reason code | ⬜ |

Each sample contains one or more flow records (for flow samples) or counter records (for counter samples).

**Data Encoding:**
- XDR (External Data Representation)
- Big-endian byte order
- 4-byte alignment
- Opaque data handling
- Variable-length arrays

**Core Data Types:**
- Address types: IPv4, IPv6, Unknown
- DataFormat: enterprise (20 bits) + format (12 bits)
- DataSource: source type (8 bits) + index (24 bits)
- Interface: format (2 bits) + value (30 bits)
- Expanded variants for large ifIndex values

### Flow Records

| Enterprise | Format | Name | Specification | Status |
|-----------|--------|------|---------------|--------|
| 0 | 1 | Sampled Header | [sFlow v5](https://sflow.org/sflow_version_5.txt) | ✅ |
| 0 | 2 | Sampled Ethernet | [sFlow v5](https://sflow.org/sflow_version_5.txt) | ✅ |
| 0 | 3 | Sampled IPv4 | [sFlow v5](https://sflow.org/sflow_version_5.txt) | ✅ |
| 0 | 4 | Sampled IPv6 | [sFlow v5](https://sflow.org/sflow_version_5.txt) | ✅ |
| 0 | 1001 | Extended Switch | [sFlow v5](https://sflow.org/sflow_version_5.txt) | ✅ |
| 0 | 1002 | Extended Router | [sFlow v5](https://sflow.org/sflow_version_5.txt) | ✅ |
| 0 | 1003 | Extended Gateway (BGP) | [sFlow v5](https://sflow.org/sflow_version_5.txt) | ✅ |
| 0 | 1004 | Extended User | [sFlow v5](https://sflow.org/sflow_version_5.txt) | ✅ |
| 0 | 1005 | Extended URL (deprecated) | [sFlow v5](https://sflow.org/sflow_version_5.txt) | ✅ ⚠️ |
| 0 | 1006 | Extended MPLS | [sFlow v5](https://sflow.org/sflow_version_5.txt) | ✅ |
| 0 | 1007 | Extended NAT | [sFlow v5](https://sflow.org/sflow_version_5.txt) | ✅ |
| 0 | 1008 | Extended MPLS Tunnel | [sFlow v5](https://sflow.org/sflow_version_5.txt) | ✅ |
| 0 | 1009 | Extended MPLS VC | [sFlow v5](https://sflow.org/sflow_version_5.txt) | ✅ |
| 0 | 1010 | Extended MPLS FEC | [sFlow v5](https://sflow.org/sflow_version_5.txt) | ✅ |
| 0 | 1011 | Extended MPLS LVP FEC | [sFlow v5](https://sflow.org/sflow_version_5.txt) | ✅ |
| 0 | 1012 | Extended VLAN Tunnel | [sFlow v5](https://sflow.org/sflow_version_5.txt) | ✅ |
| 0 | 1013 | Extended 802.11 Payload | [sFlow 802.11](https://sflow.org/sflow_80211.txt) | ✅ |
| 0 | 1014 | Extended 802.11 RX | [sFlow 802.11](https://sflow.org/sflow_80211.txt) | ✅ |
| 0 | 1015 | Extended 802.11 TX | [sFlow 802.11](https://sflow.org/sflow_80211.txt) | ✅ |
| 0 | 1016 | Extended 802.11 Aggregation | [sFlow 802.11](https://sflow.org/sflow_80211.txt) | ✅ |
| 0 | 1017 | Extended OpenFlow v1 (deprecated) | [sFlow OpenFlow Draft](https://sflow.org/draft-sflow-openflow.txt) | ✅ ⚠️ |
| 0 | 1018 | Extended Fibre Channel | [sFlow Discussion](https://sflow.org/discussion/sflow-discussion/0244.html) | ⬜ |
| 0 | 1019 | Extended Queue Length | [sFlow Discussion](http://groups.google.com/group/sflow/browse_thread/thread/773d27b17a81600c) | ⬜ |
| 0 | 1020 | Extended NAT Port | [sFlow Port NAT](https://sflow.org/sflow_pnat.txt) | ⬜ |
| 0 | 1021 | Extended L2 Tunnel Egress | [sFlow Tunnel](https://sflow.org/sflow_tunnels.txt) | ⬜ |
| 0 | 1022 | Extended L2 Tunnel Ingress | [sFlow Tunnel](https://sflow.org/sflow_tunnels.txt) | ⬜ |
| 0 | 1023 | Extended IPv4 Tunnel Egress | [sFlow Tunnel](https://sflow.org/sflow_tunnels.txt) | ⬜ |
| 0 | 1024 | Extended IPv4 Tunnel Ingress | [sFlow Tunnel](https://sflow.org/sflow_tunnels.txt) | ⬜ |
| 0 | 1025 | Extended IPv6 Tunnel Egress | [sFlow Tunnel](https://sflow.org/sflow_tunnels.txt) | ⬜ |
| 0 | 1026 | Extended IPv6 Tunnel Ingress | [sFlow Tunnel](https://sflow.org/sflow_tunnels.txt) | ⬜ |
| 0 | 1027 | Extended Decapsulate Egress | [sFlow Tunnel](https://sflow.org/sflow_tunnels.txt) | ⬜ |
| 0 | 1028 | Extended Decapsulate Ingress | [sFlow Tunnel](https://sflow.org/sflow_tunnels.txt) | ⬜ |
| 0 | 1029 | Extended VNI Egress | [sFlow Tunnel](https://sflow.org/sflow_tunnels.txt) | ⬜ |
| 0 | 1030 | Extended VNI Ingress | [sFlow Tunnel](https://sflow.org/sflow_tunnels.txt) | ⬜ |
| 0 | 1031 | Extended InfiniBand LRH | [sFlow InfiniBand](https://sflow.org/draft_sflow_infiniband_2.txt) | ⬜ |
| 0 | 1032 | Extended InfiniBand GRH | [sFlow InfiniBand](https://sflow.org/draft_sflow_infiniband_2.txt) | ⬜ |
| 0 | 1033 | Extended InfiniBand BRH | [sFlow InfiniBand](https://sflow.org/draft_sflow_infiniband_2.txt) | ⬜ |
| 0 | 1034 | Extended VLAN In | [sFlow Discussion](https://groups.google.com/forum/) | ⬜ |
| 0 | 1035 | Extended VLAN Out | [sFlow Discussion](https://groups.google.com/forum/) | ⬜ |
| 0 | 1036 | Extended Egress Queue | [sFlow Drops](https://sflow.org/sflow_drops.txt) | ⬜ |
| 0 | 1037 | Extended ACL | [sFlow Drops](https://sflow.org/sflow_drops.txt) | ⬜ |
| 0 | 1038 | Extended Function | [sFlow Drops](https://sflow.org/sflow_drops.txt) | ⬜ |
| 0 | 1039 | Extended Transit Delay | [sFlow Transit](https://sflow.org/sflow_transit.txt) | ⬜ |
| 0 | 1040 | Extended Queue Depth | [sFlow Transit](https://sflow.org/sflow_transit.txt) | ⬜ |
| 0 | 1041 | Extended HW Trap | [sFlow Host](https://github.com/sflow/host-sflow/blob/v2.0.50-3/src/sflow/sflow.h) | ⬜ |
| 0 | 1042 | Extended Linux Drop Reason | [sFlow Host](https://github.com/sflow/host-sflow/blob/v2.0.50-3/src/sflow/sflow.h) | ⬜ |
| 0 | 2000 | Transaction | [sFlow Discussion](https://sflow.org/discussion/sflow-discussion/0282.html) | ⬜ |
| 0 | 2001 | Extended NFS Storage Transaction | [sFlow Discussion](https://sflow.org/discussion/sflow-discussion/0282.html) | ⬜ |
| 0 | 2002 | Extended SCSI Storage Transaction | [sFlow Discussion](https://sflow.org/discussion/sflow-discussion/0282.html) | ⬜ |
| 0 | 2003 | Extended HTTP Transaction | [sFlow Discussion](https://sflow.org/discussion/sflow-discussion/0282.html) | ⬜ |
| 0 | 2100 | Extended Socket IPv4 | [sFlow Host](https://sflow.org/sflow_host.txt) | ✅ |
| 0 | 2101 | Extended Socket IPv6 | [sFlow Host](https://sflow.org/sflow_host.txt) | ✅ |
| 0 | 2102 | Extended Proxy Socket IPv4 | [sFlow HTTP](https://sflow.org/sflow_http.txt) | ⬜ |
| 0 | 2103 | Extended Proxy Socket IPv6 | [sFlow HTTP](https://sflow.org/sflow_http.txt) | ⬜ |
| 0 | 2200 | Memcache Operation | [sFlow Memcache](https://sflow.org/sflow_memcache.txt) | ⬜ |
| 0 | 2201 | HTTP Request (deprecated) | [sFlow Discussion](http://groups.google.com/group/sflow/browse_thread/thread/88accb2bad594d1d) | ⬜ ⚠️ |
| 0 | 2202 | App Operation | [sFlow Application](https://sflow.org/sflow_application.txt) | ✅ |
| 0 | 2203 | App Parent Context | [sFlow Application](https://sflow.org/sflow_application.txt) | ✅ |
| 0 | 2204 | App Initiator | [sFlow Application](https://sflow.org/sflow_application.txt) | ⬜ |
| 0 | 2205 | App Target | [sFlow Application](https://sflow.org/sflow_application.txt) | ⬜ |
| 0 | 2206 | HTTP Request | [sFlow HTTP](https://sflow.org/sflow_http.txt) | ⬜ |
| 0 | 2207 | Extended Proxy Request | [sFlow HTTP](https://sflow.org/sflow_http.txt) | ⬜ |
| 0 | 2208 | Extended Nav Timing | [sFlow Discussion](https://groups.google.com/forum/) | ⬜ |
| 0 | 2209 | Extended TCP Info | [sFlow Discussion](https://groups.google.com/forum/) | ⬜ |
| 0 | 2210 | Extended Entities | [sFlow Discussion](https://blog.sflow.com/2018/10/systemd-traffic-marking.html) | ⬜ |
| 4413 | 1 | BST Egress Queue | [sFlow Broadcom](https://sflow.org/bv-sflow.txt) | ⬜ |

### Counter Records

| Enterprise | Format | Name | Specification | Status |
|-----------|--------|------|---------------|--------|
| 0 | 1 | Generic Interface | [sFlow v5](https://sflow.org/sflow_version_5.txt) | ✅ |
| 0 | 2 | Ethernet Interface | [sFlow v5](https://sflow.org/sflow_version_5.txt) | ✅ |
| 0 | 3 | Token Ring | [sFlow v5](https://sflow.org/sflow_version_5.txt) | ✅ |
| 0 | 4 | 100BaseVG Interface | [sFlow v5](https://sflow.org/sflow_version_5.txt) | ✅ |
| 0 | 5 | VLAN | [sFlow v5](https://sflow.org/sflow_version_5.txt) | ✅ |
| 0 | 6 | IEEE 802.11 Counters | [sFlow 802.11](https://sflow.org/sflow_80211.txt) | ✅ |
| 0 | 7 | LAG Port Stats | [sFlow LAG](https://sflow.org/sflow_lag.txt) | ⬜ |
| 0 | 8 | Slow Path Counts | [sFlow Discussion](https://groups.google.com/g/sflow/c/4JM1_Mmoz7w) | ⬜ |
| 0 | 9 | InfiniBand Counters | [sFlow InfiniBand](https://sflow.org/draft_sflow_infiniband_2.txt) | ⬜ |
| 0 | 10 | Optical SFP/QSFP | [sFlow Optics](https://sflow.org/sflow_optics.txt) | ⬜ |
| 0 | 1001 | Processor | [sFlow v5](https://sflow.org/sflow_version_5.txt) | ✅ |
| 0 | 1002 | Radio Utilization | [sFlow 802.11](https://sflow.org/sflow_80211.txt) | ✅ |
| 0 | 1003 | Queue Length | [sFlow Discussion](http://groups.google.com/group/sflow/browse_thread/thread/773d27b17a81600c) | ⬜ |
| 0 | 1004 | OpenFlow Port | [sFlow OpenFlow](https://sflow.org/sflow_openflow.txt) | ✅ |
| 0 | 1005 | OpenFlow Port Name | [sFlow OpenFlow](https://sflow.org/sflow_openflow.txt) | ✅ |
| 0 | 2000 | Host Description | [sFlow Host](https://sflow.org/sflow_host.txt) | ✅ |
| 0 | 2001 | Host Adapters | [sFlow Host](https://sflow.org/sflow_host.txt) | ✅ |
| 0 | 2002 | Host Parent | [sFlow Host](https://sflow.org/sflow_host.txt) | ✅ |
| 0 | 2003 | Host CPU | [sFlow Host](https://sflow.org/sflow_host.txt) | ✅ |
| 0 | 2004 | Host Memory | [sFlow Host](https://sflow.org/sflow_host.txt) | ✅ |
| 0 | 2005 | Host Disk I/O | [sFlow Host](https://sflow.org/sflow_host.txt) | ✅ |
| 0 | 2006 | Host Network I/O | [sFlow Host](https://sflow.org/sflow_host.txt) | ✅ |
| 0 | 2007 | MIB2 IP Group | [sFlow Host TCP/IP](https://sflow.org/sflow_host_ip.txt) | ⬜ |
| 0 | 2008 | MIB2 ICMP Group | [sFlow Host TCP/IP](https://sflow.org/sflow_host_ip.txt) | ⬜ |
| 0 | 2009 | MIB2 TCP Group | [sFlow Host TCP/IP](https://sflow.org/sflow_host_ip.txt) | ⬜ |
| 0 | 2010 | MIB2 UDP Group | [sFlow Host TCP/IP](https://sflow.org/sflow_host_ip.txt) | ⬜ |
| 0 | 2100 | Virtual Node | [sFlow Host](https://sflow.org/sflow_host.txt) | ✅ |
| 0 | 2101 | Virtual CPU | [sFlow Host](https://sflow.org/sflow_host.txt) | ✅ |
| 0 | 2102 | Virtual Memory | [sFlow Host](https://sflow.org/sflow_host.txt) | ✅ |
| 0 | 2103 | Virtual Disk I/O | [sFlow Host](https://sflow.org/sflow_host.txt) | ✅ |
| 0 | 2104 | Virtual Network I/O | [sFlow Host](https://sflow.org/sflow_host.txt) | ✅ |
| 0 | 2105 | JVM Runtime | [sFlow JVM](https://sflow.org/sflow_jvm.txt) | ⬜ |
| 0 | 2106 | JVM Statistics | [sFlow JVM](https://sflow.org/sflow_jvm.txt) | ⬜ |
| 0 | 2200 | Memcache Counters (deprecated) | [sFlow Discussion](https://groups.google.com/g/sflow/c/KDk_QrxCSJI) | ⬜ ⚠️ |
| 0 | 2201 | HTTP Counters | [sFlow HTTP](https://sflow.org/sflow_http.txt) | ⬜ |
| 0 | 2202 | App Operations | [sFlow Application](https://sflow.org/sflow_application.txt) | ✅ |
| 0 | 2203 | App Resources | [sFlow Application](https://sflow.org/sflow_application.txt) | ✅ |
| 0 | 2204 | Memcache Counters | [sFlow Memcache](https://sflow.org/sflow_memcache.txt) | ⬜ |
| 0 | 2206 | App Workers | [sFlow Application](https://sflow.org/sflow_application.txt) | ✅ |
| 0 | 2207 | OVS DP Stats | [sFlow Discussion](http://blog.sflow.com/2015/01/open-vswitch-performance-monitoring.html) | ⬜ |
| 0 | 3000 | Energy | [sFlow Discussion](https://groups.google.com/g/sflow/c/gN3nxSi2SBs) | ⬜ |
| 0 | 3001 | Temperature | [sFlow Discussion](https://groups.google.com/g/sflow/c/gN3nxSi2SBs) | ⬜ |
| 0 | 3002 | Humidity | [sFlow Discussion](https://groups.google.com/g/sflow/c/gN3nxSi2SBs) | ⬜ |
| 0 | 3003 | Fans | [sFlow Discussion](https://groups.google.com/g/sflow/c/gN3nxSi2SBs) | ⬜ |
| 4413 | 1 | Broadcom Device Buffer | [sFlow Broadcom](https://sflow.org/bv-sflow.txt) | ⬜ |
| 4413 | 2 | Broadcom Port Buffer | [sFlow Broadcom](https://sflow.org/bv-sflow.txt) | ⬜ |
| 4413 | 3 | Broadcom ASIC Tables | [sFlow Broadcom](https://sflow.org/sflow_broadcom_tables.txt) | ⬜ |
| 5703 | 1 | NVIDIA GPU | [sFlow NVML](https://sflow.org/sflow_nvml.txt) | ⬜ |

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

## Specifications Validation

The project includes comprehensive validation against official sFlow specification documents using `syn` crate to parse Rust source files and extract sFlow struct metadata:

```bash
make test-validate
```

### Benchmarks

Performance benchmarks using Criterion:

```bash
make bench  # Run performance benchmarks
```

**Results:** ~330ns per datagram (~3M datagrams/sec) on typical hardware. The parser is not zero-copy (at least for now) and does not use any unsafe code, but it is fast enough for most use cases.

## License

This project is licensed under the [MIT License](LICENSE).

sFlow® is a registered trademark of InMon Corp. This implementation is based on the
sFlow version 5 specification available at [https://sflow.org/sflow_version_5.txt](https://sflow.org/sflow_version_5.txt) and
is licensed under the terms provided at [https://inmon.com/technology/sflowlicense.txt](https://inmon.com/technology/sflowlicense.txt).
