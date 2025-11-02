# sFlow Specification Validation Tests

Automated validation tests that verify our Rust implementation against the official sFlow specifications from [sflow.org](https://sflow.org).

**Status: ✅ 94/94 structures implemented (100% coverage)**

## Components

- **`specs_validation.rs`** - Downloads specs, parses XDR definitions, validates against implementation
- **`specs_parser_lib_ast.rs`** - Parses Rust source files using `syn` to extract struct metadata
- **`cache/`** - Cached specification documents (not commited)

## Validated Specifications

| Year | Specification | Structures | Status |
|------|--------------|------------|--------|
| 2004 | sflow_version_5 | 26 | ✅ Complete |
| 2007 | sflow_80211 | 6 | ✅ Complete |
| 2010 | sflow_host | 14 | ✅ Complete |
| 2011 | sflow_http | 5 | ✅ Complete |
| 2011 | sflow_jvm | 2 | ✅ Complete |
| 2011 | sflow_memcache | 2 | ✅ Complete |
| 2012 | sflow_nvml | 1 | ✅ Complete |
| 2012 | sflow_application | 7 | ✅ Complete |
| 2012 | sflow_lag | 1 | ✅ Complete |
| 2012 | sflow_tunnels | 8 | ✅ Complete |
| 2012 | sflow_pnat | 1 | ✅ Complete |
| 2013 | sflow_infiniband | 4 | ✅ Complete |
| 2014 | sflow_openflow | 2 | ✅ Complete |
| 2015 | sflow_host_ip | 4 | ✅ Complete |
| 2015 | sflow_broadcom_tables | 1 | ✅ Complete |
| 2015 | sflow_broadcom_buffers | 3 | ✅ Complete |
| 2016 | sflow_optics | 1 | ✅ Complete |
| 2020 | sflow_drops | 4 | ✅ Complete |
| 2021 | sflow_transit | 2 | ✅ Complete |

## Running Tests

```bash
make specs-validate
```

## Specification Errata

See the [official sFlow errata](https://sflow.org/developers/errata.php) for documented corrections to published specifications.

We've also identified [additional specification issues](SPEC_ISSUES.md) that are not yet part of the official errata, including:
- Missing semicolons (RFC 4506 violations)
- Non-standard data type names
- Missing `struct` keywords
- Formatting inconsistencies

## References

- [sFlow.org Specifications](https://sflow.org)
- [RFC 3176 - InMon Corporation's sFlow](https://www.rfc-editor.org/rfc/rfc3176)
- [XDR: External Data Representation Standard](https://www.rfc-editor.org/rfc/rfc4506)
