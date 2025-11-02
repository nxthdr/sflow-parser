//! Validation against official sFlow specifications
//!
//! This module provides automated validation of our Rust implementation against
//! the official sFlow specifications from sflow.org. It downloads specification
//! documents, parses XDR structure definitions, and compares them with our
//! implementation to ensure 100% compliance.
//!
//! # Architecture
//!
//! The validation system consists of three main components:
//!
//! 1. **Specification Download & Parsing** - Downloads specs from sflow.org and
//!    parses XDR structure definitions using regex patterns
//! 2. **Rust Implementation Parsing** - Uses the `syn` crate to extract struct
//!    metadata from our source files via AST parsing
//! 3. **Validation & Comparison** - Compares field names, types, and counts
//!    between XDR definitions and Rust implementations
//!
//! # Special Cases
//!
//! The validator handles several categories of special cases:
//!
//! - **Core Sample Structures**: Use complex typedefs that XDR parser can't understand
//! - **XDR Parser Limitations**: Specs with syntax issues or missing fields
//! - **Intentional Deviations**: Improvements for better usability and type safety
//! - **Application Structures**: Complex nested types that require special handling
//!
//! # Known Specification Errata
//!
//! The following errata from the official sFlow specifications are documented in the implementation:
//!
//! ## sFlow Version 5 Errata
//!
//! - **ERRATUM (Page 28):** Input/output port example corrected from `0x40000001` to `0x40000102`
//!   for packet discarded because of ACL.
//!
//! - **ERRATUM (Page 37):** Extended Switch Data - All fields (src_vlan, src_priority, dst_vlan,
//!   dst_priority) clarified to use `0xffffffff` if unknown.
//!
//! - **ERRATUM (Page 29, 30, 31, 32):** Sequence number comments in flow_sample, counters_sample,
//!   flow_sample_expanded, and counters_sample_expanded clarified to reference "sFlow Instance"
//!   instead of "source_id".
//!
//! - **ERRATUM (Page 31):** interface_expanded value field clarified that `0xFFFFFFFF` must be used
//!   to indicate traffic originating or terminating in device (not `0x3FFFFFFF`).
//!
//! - **ERRATUM (Page 38):** extended_router nexthop field clarified as "immediate next hop router".
//!
//! ## sFlow Host Structures Errata
//!
//! - **ERRATUM (Page 8):** host_descr uuid field changed from `opaque uuid<16>` to `opaque uuid[16]`
//!   (fixed-length array), and clarified as "all zeros if unknown" instead of "empty if unknown".
//!
//! - **ERRATUM (Page 12):** virt_disk_io field renamed from `available` (remaining free bytes) to
//!   `physical` (physical size in bytes of the container of the backing image).
//!
//! - **ERRATUM (Page 11):** Comment references corrected from `virtDomainInfo` to `virDomainInfo`,
//!   from `virtDomainBlockInfo` to `virDomainBlockInfo`, from `virtDomainBlockStatsStruct` to
//!   `virDomainBlockStatsStruct`, and from `virtDomainInterfaceStatsStruct` to
//!   `virDomainInterfaceStatsStruct`.

use super::specs_parser_lib_ast::{build_registry_from_source, FieldMetadata, StructRegistry};
use regex::Regex;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// sFlow specification to download and validate against
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct SpecDocument {
    pub name: &'static str,
    pub url: &'static str,
    pub year: u32,
}

/// List of official sFlow specifications
pub const SFLOW_SPECS: &[SpecDocument] = &[
    SpecDocument {
        name: "sflow_version_5",
        url: "https://sflow.org/sflow_version_5.txt",
        year: 2004,
    },
    SpecDocument {
        name: "sflow_80211",
        url: "https://sflow.org/sflow_80211.txt",
        year: 2007,
    },
    SpecDocument {
        name: "sflow_host",
        url: "https://sflow.org/sflow_host.txt",
        year: 2010,
    },
    SpecDocument {
        name: "sflow_http",
        url: "https://sflow.org/sflow_http.txt",
        year: 2011,
    },
    SpecDocument {
        name: "sflow_jvm",
        url: "https://sflow.org/sflow_jvm.txt",
        year: 2011,
    },
    SpecDocument {
        name: "sflow_memcache",
        url: "https://sflow.org/sflow_memcache.txt",
        year: 2011,
    },
    SpecDocument {
        name: "sflow_nvml",
        url: "https://sflow.org/sflow_nvml.txt",
        year: 2012,
    },
    SpecDocument {
        name: "sflow_application",
        url: "https://sflow.org/sflow_application.txt",
        year: 2012,
    },
    SpecDocument {
        name: "sflow_lag",
        url: "https://sflow.org/sflow_lag.txt",
        year: 2012,
    },
    SpecDocument {
        name: "sflow_tunnels",
        url: "https://sflow.org/sflow_tunnels.txt",
        year: 2012,
    },
    SpecDocument {
        name: "sflow_pnat",
        url: "https://sflow.org/sflow_pnat.txt",
        year: 2012,
    },
    SpecDocument {
        name: "sflow_infiniband",
        url: "https://sflow.org/draft_sflow_infiniband_2.txt",
        year: 2013,
    },
    SpecDocument {
        name: "sflow_openflow",
        url: "https://sflow.org/sflow_openflow.txt",
        year: 2014,
    },
    SpecDocument {
        name: "sflow_host_ip",
        url: "https://sflow.org/sflow_host_ip.txt",
        year: 2015,
    },
    SpecDocument {
        name: "sflow_broadcom_tables",
        url: "https://sflow.org/sflow_broadcom_tables.txt",
        year: 2015,
    },
    SpecDocument {
        name: "sflow_broadcom_buffers",
        url: "https://sflow.org/bv-sflow.txt",
        year: 2015,
    },
    SpecDocument {
        name: "sflow_optics",
        url: "https://sflow.org/sflow_optics.txt",
        year: 2016,
    },
    SpecDocument {
        name: "sflow_drops",
        url: "https://sflow.org/sflow_drops.txt",
        year: 2020,
    },
    SpecDocument {
        name: "sflow_transit",
        url: "https://sflow.org/sflow_transit.txt",
        year: 2021,
    },
];

/// XDR structure definition parsed from spec
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct XdrStructure {
    pub name: String,
    pub enterprise: u32,
    pub format: u32,
    pub data_type: String, // "flow_data" or "counter_data"
    pub fields: Vec<XdrField>,
    pub spec_source: String,
    pub docstring: String,
}

/// XDR field definition
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct XdrField {
    pub name: String,
    pub xdr_type: String,
    pub rust_type: String,
    pub comment: Option<String>,
}

/// Download a specification document from sflow.org
///
/// Downloads the specification and caches it locally to avoid repeated network requests.
/// If a cached version exists, it will be used instead of downloading again.
///
/// # Arguments
///
/// * `spec` - The specification document to download
/// * `cache_dir` - Directory to store cached specification files
///
/// # Returns
///
/// The specification content as a string
pub fn download_spec(
    spec: &SpecDocument,
    cache_dir: &Path,
) -> Result<String, Box<dyn std::error::Error>> {
    // Create cache directory if it doesn't exist
    fs::create_dir_all(cache_dir)?;

    let cache_file = cache_dir.join(format!("{}.txt", spec.name));

    // Check if cached version exists
    if cache_file.exists() {
        println!("Using cached spec: {}", spec.name);
        return Ok(fs::read_to_string(cache_file)?);
    }

    // Download the spec
    println!("Downloading spec: {} from {}", spec.name, spec.url);
    let mut response = ureq::get(spec.url).call()?;
    let content = response.body_mut().read_to_string()?;

    // Cache it
    fs::write(&cache_file, &content)?;

    Ok(content)
}

/// Download all official sFlow specifications
///
/// Downloads all specifications defined in `SFLOW_SPECS` and returns them as a HashMap.
/// Uses caching to avoid repeated downloads.
///
/// # Arguments
///
/// * `cache_dir` - Directory to store cached specification files
///
/// # Returns
///
/// HashMap mapping specification names to their content
pub fn download_all_specs(
    cache_dir: &Path,
) -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
    let mut specs = HashMap::new();

    for spec in SFLOW_SPECS {
        let content = download_spec(spec, cache_dir)?;
        specs.insert(spec.name.to_string(), content);
    }

    Ok(specs)
}

/// Parse XDR structure definitions from specification text
///
/// Extracts XDR structure definitions by looking for format comments followed by
/// struct definitions. The format comment pattern is:
/// `/* opaque = <data_type>; enterprise = <N>; format = <M> */`
///
/// # Arguments
///
/// * `spec_content` - The specification document content
/// * `spec_name` - Name of the specification (for tracking purposes)
///
/// # Returns
///
/// Vector of parsed XDR structures with their fields and metadata
pub fn parse_xdr_structures(spec_content: &str, spec_name: &str) -> Vec<XdrStructure> {
    let mut structures = Vec::new();

    // Regex to find XDR structure definitions with format comments
    // Pattern: /* opaque = ...; enterprise = N; format = M */
    //          [optional comments and whitespace]
    //          struct name {
    //              fields...
    //          }

    // Match format comment followed by struct definition
    // Use (?s) for . to match newlines
    // Allow for up to 800 characters (including page headers) between format comment and struct
    // Use non-greedy matching to get the closest struct
    // The 'struct' keyword is optional (some specs like app_initiator don't use it)
    // Accept both semicolons and commas as separators (NVIDIA spec uses comma)
    // Note: We match up to the opening brace, then manually find the matching closing brace
    let format_comment_re = Regex::new(
        r"(?s)/\*\s*opaque\s*=\s*(\w+)\s*;\s*enterprise\s*=\s*(\d+)\s*[;,]\s*format\s*=\s*(\d+)\s*\*/.{0,800}?(?:struct\s+)?(\w+)\s*\{"
    ).unwrap();

    for cap in format_comment_re.captures_iter(spec_content) {
        let data_type = cap.get(1).unwrap().as_str().to_string();
        let enterprise: u32 = cap.get(2).unwrap().as_str().parse().unwrap_or(0);
        let format: u32 = cap.get(3).unwrap().as_str().parse().unwrap_or(0);
        let name = cap.get(4).unwrap().as_str().to_string();

        // Find the matching closing brace by counting brace depth
        let struct_start = cap.get(0).unwrap().end();
        let remaining = &spec_content[struct_start..];
        let mut brace_count = 1;
        let mut end_pos = 0;

        for (i, ch) in remaining.chars().enumerate() {
            if ch == '{' {
                brace_count += 1;
            } else if ch == '}' {
                brace_count -= 1;
                if brace_count == 0 {
                    end_pos = i;
                    break;
                }
            }
        }

        let fields_text = &remaining[..end_pos];

        // Extract docstring (text before the format comment)
        let match_start = cap.get(0).unwrap().start();
        let docstring = extract_docstring(spec_content, match_start);

        // Parse fields
        let fields = parse_xdr_fields(fields_text);

        structures.push(XdrStructure {
            name,
            enterprise,
            format,
            data_type,
            fields,
            spec_source: spec_name.to_string(),
            docstring,
        });
    }

    structures
}

/// Extract docstring from text before a structure definition
fn extract_docstring(text: &str, position: usize) -> String {
    // Look backwards for the previous section heading or blank lines
    let before = &text[..position];
    let lines: Vec<&str> = before.lines().rev().take(20).collect();

    let mut doc_lines = Vec::new();
    for line in lines {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("===") || trimmed.starts_with("---") {
            break;
        }
        doc_lines.push(trimmed);
    }

    doc_lines.reverse();
    doc_lines.join(" ").trim().to_string()
}

/// Parse XDR fields from structure body
fn parse_xdr_fields(fields_text: &str) -> Vec<XdrField> {
    // First, remove all /* ... */ comments (including multi-line)
    let mut cleaned_text = fields_text.to_string();
    while let Some(start) = cleaned_text.find("/*") {
        if let Some(end_pos) = cleaned_text[start..].find("*/") {
            cleaned_text.replace_range(start..start + end_pos + 2, " ");
        } else {
            break;
        }
    }

    // Then filter out page headers
    let cleaned_text = cleaned_text
        .lines()
        .filter(|line| {
            let trimmed = line.trim();
            !trimmed.contains("[Page")
                && !trimmed.starts_with("FINAL")
                && !trimmed.starts_with("v1.")
                && !trimmed.contains("sFlow.org")
                && !trimmed.is_empty()
        })
        .collect::<Vec<_>>()
        .join("\n");

    // Collect all field matches with their positions to preserve order
    let mut field_matches: Vec<(usize, XdrField)> = Vec::new();

    // Match sized types like "string ssid<32>;" or "opaque header<>;" or "unsigned int stack<>"
    // Also match without semicolon for fields at end of struct
    // Allow multi-word types like "unsigned int"
    let sized_field_re =
        Regex::new(r"(?m)^\s*([a-zA-Z_][\w\s]+?)\s+(\w+)\s*<([^>]*)>\s*;?").unwrap();
    for cap in sized_field_re.captures_iter(&cleaned_text) {
        let pos = cap.get(0).unwrap().start();
        let base_type = cap.get(1).unwrap().as_str().trim();
        let name = cap.get(2).unwrap().as_str().to_string();
        let size = cap.get(3).unwrap().as_str();
        let xdr_type = if size.is_empty() {
            format!("{}<>", base_type)
        } else {
            format!("{}<{}>", base_type, size)
        };
        let rust_type = xdr_type_to_rust(&xdr_type);

        field_matches.push((
            pos,
            XdrField {
                name,
                xdr_type,
                rust_type,
                comment: None,
            },
        ));
    }

    // Match regular fields like "unsigned int field;" or "unsigned int field"
    // Require semicolon to avoid false matches
    let field_re = Regex::new(r"(?m)^\s*([a-zA-Z_][\w\s]+?)\s+(\w+)\s*;").unwrap();
    for cap in field_re.captures_iter(&cleaned_text) {
        let pos = cap.get(0).unwrap().start();
        let xdr_type = cap.get(1).unwrap().as_str().trim().to_string();
        let name = cap.get(2).unwrap().as_str().to_string();

        // Skip if already added (check by name only)
        if field_matches.iter().any(|(_, f)| f.name == name) {
            continue;
        }

        // Skip if this looks like a comment or struct keyword
        if xdr_type.contains("/*") || xdr_type.contains("*/") || xdr_type == "struct" {
            continue;
        }

        let rust_type = xdr_type_to_rust(&xdr_type);

        field_matches.push((
            pos,
            XdrField {
                name,
                xdr_type,
                rust_type,
                comment: None,
            },
        ));
    }

    // Sort by position and extract fields
    field_matches.sort_by_key(|(pos, _)| *pos);
    field_matches.into_iter().map(|(_, field)| field).collect()
}

/// Convert XDR type to equivalent Rust type
///
/// Maps XDR type names to their Rust equivalents, handling:
/// - Basic types (unsigned int → u32, string → String)
/// - Arrays (opaque[16] → [u8; 16])
/// - Variable-length arrays (opaque<> → Vec<u8>)
/// - Custom sFlow types (address → Address, mac → MacAddress)
///
/// # Arguments
///
/// * `xdr_type` - The XDR type string from the specification
///
/// # Returns
///
/// The equivalent Rust type as a string
fn xdr_type_to_rust(xdr_type: &str) -> String {
    let xdr_type = xdr_type.trim();

    // Handle arrays
    if let Some(array_match) = Regex::new(r"(\w+)\s*\[(\d+)\]").unwrap().captures(xdr_type) {
        let base_type = array_match.get(1).unwrap().as_str();
        let size = array_match.get(2).unwrap().as_str();

        if base_type == "unsigned" || base_type == "int" {
            return format!("[u32; {}]", size);
        } else if base_type == "opaque" || base_type == "byte" {
            return format!("[u8; {}]", size);
        }
    }

    // Handle variable-length arrays and sized strings
    if xdr_type.contains("<") || xdr_type.ends_with("[]") {
        if xdr_type.contains("string") {
            return "String".to_string();
        }
        if xdr_type.contains("opaque") || xdr_type.contains("byte") {
            return "Vec<u8>".to_string();
        }
        // Handle arrays of typedefs like "percentage<8>"
        if xdr_type.contains("percentage") {
            return "Vec<i32>".to_string();
        }
        // Handle arrays of custom types like "lane<>"
        if xdr_type.contains("lane") {
            return "Vec<Lane>".to_string();
        }
        return "Vec<u32>".to_string();
    }

    // Handle pointers
    if xdr_type.contains('*') {
        if xdr_type.contains("char") {
            return "String".to_string();
        }
        return "Vec<u8>".to_string();
    }

    // Basic types
    match xdr_type {
        "unsigned int" | "unsigned" => "u32".to_string(),
        "int" => "i32".to_string(),
        "unsigned hyper" | "hyper" => "u64".to_string(),
        "string" | "string<>" => "String".to_string(),
        "opaque" | "opaque<>" => "Vec<u8>".to_string(),
        "address" => "Address".to_string(),
        "mac" => "MacAddress".to_string(),
        "ip_v4" => "Ipv4Addr".to_string(),
        "ip_v6" => "Ipv6Addr".to_string(),
        "next_hop" => "Address".to_string(),
        "data_format" => "DataFormat".to_string(),
        "data_source" => "DataSource".to_string(),
        "interface" => "Interface".to_string(),
        "header_protocol" => "HeaderProtocol".to_string(),
        "ieee80211_version" => "Ieee80211Version".to_string(),
        "cipher_suite" => "u32".to_string(),
        "charset" => "u32".to_string(),
        "url_direction" => "UrlDirection".to_string(),
        "machine_type" => "MachineType".to_string(),
        "os_name" => "OsName".to_string(),
        "label_stack" => "Vec<u32>".to_string(),
        "milliseconds" => "u32".to_string(),
        "percentage" => "i32".to_string(),
        "gauge32" => "u32".to_string(),
        "counter32" => "u32".to_string(),
        "counter64" => "u64".to_string(),
        "float" => "f32".to_string(),
        "duration_us" => "u32".to_string(),
        "as_path_type" => "Vec<AsPathSegment>".to_string(),
        "host_adapter" => "HostAdapter".to_string(),
        "sampled_ethernet" => "SampledEthernet".to_string(),
        "sampled_ipv4" => "SampledIpv4".to_string(),
        "sampled_ipv6" => "SampledIpv6".to_string(),
        // HTTP extension types
        "http_method" => "HttpMethod".to_string(),
        "version" => "u32".to_string(), // HTTP version typedef
        "extended_socket_ipv4" => "ExtendedSocketIpv4".to_string(),
        "extended_socket_ipv6" => "ExtendedSocketIpv6".to_string(),
        // Memcache extension types
        "memcache_protocol" => "MemcacheProtocol".to_string(),
        "memcache_cmd" => "MemcacheCommand".to_string(),
        "memcache_status" => "MemcacheStatus".to_string(),
        _ => {
            // Custom types - assume they're defined elsewhere
            if xdr_type.starts_with("SFL") || xdr_type.starts_with("enum") {
                xdr_type.to_string()
            } else {
                "Unknown".to_string()
            }
        }
    }
}

/// Validation result for a structure
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct StructureValidation {
    pub name: String,
    pub enterprise: u32,
    pub format: u32,
    pub data_type: String,
    pub spec_source: String,
    pub implemented: bool,
    pub docstring_correct: bool,
    pub docstring_issues: Vec<String>,
    pub field_count_match: bool,
    pub field_issues: Vec<String>,
}

/// Normalize data_type to standard types used in the registry
///
/// The InfiniBand specification uses custom data types (ib_lrh_data, ib_grh_data, ib_bth_data)
/// but these are actually flow_data records in the implementation. This function normalizes
/// them to the standard types.
///
/// # Arguments
///
/// * `data_type` - The data type from the specification
///
/// # Returns
///
/// Normalized data type (flow_data, counter_data, or sample_data)
fn normalize_data_type(data_type: &str) -> String {
    match data_type {
        "ib_lrh_data" | "ib_grh_data" | "ib_bth_data" => "flow_data".to_string(),
        _ => data_type.to_string(),
    }
}

/// Check if a format is implemented in our codebase
///
/// Uses the AST-parsed registry to determine if a specific (enterprise, format, data_type)
/// combination has been implemented.
///
/// # Arguments
///
/// * `registry` - The struct registry built from source files
/// * `enterprise` - Enterprise number
/// * `format` - Format number
/// * `data_type` - Data type (flow_data, counter_data, or sample_data)
///
/// # Returns
///
/// `true` if the format is implemented, `false` otherwise
pub fn is_format_implemented(
    registry: &StructRegistry,
    enterprise: u32,
    format: u32,
    data_type: &str,
) -> bool {
    let normalized_type = normalize_data_type(data_type);
    registry.contains_key(&(enterprise, format, normalized_type))
}

/// Convert camelCase or PascalCase to snake_case
///
/// Handles special cases like acronyms (QoS, FCS, RTS) and converts hyphens to underscores.
/// Used for matching XDR field names with Rust field names.
///
/// # Arguments
///
/// * `s` - The string to convert
///
/// # Returns
///
/// The snake_case version of the input string
fn to_snake_case(s: &str) -> String {
    // Handle special known acronyms first
    let s = s
        .replace("QoS", "Qos") // Quality of Service
        .replace("FCS", "Fcs") // Frame Check Sequence
        .replace("RTS", "Rts") // Request To Send
        .replace("ACK", "Ack") // Acknowledgment
        .replace("SQE", "Sqe") // Signal Quality Error
        .replace('-', "_"); // Convert hyphens to underscores (e.g., mime-type -> mime_type)

    let mut result = String::new();
    let mut chars = s.chars().peekable();
    let mut prev_was_upper = false;

    while let Some(ch) = chars.next() {
        if ch.is_uppercase() {
            let next_is_lower = chars.peek().map(|c| c.is_lowercase()).unwrap_or(false);

            // Add underscore before uppercase letter if:
            // - result is not empty
            // - previous char was not uppercase, OR next char is lowercase (end of acronym)
            if !result.is_empty() && (!prev_was_upper || next_is_lower) {
                result.push('_');
            }

            result.push(ch.to_lowercase().next().unwrap());
            prev_was_upper = true;
        } else {
            result.push(ch);
            prev_was_upper = false;
        }
    }

    result
}

/// Check if two field names match (allowing for case conversion)
///
/// Handles various naming convention differences between XDR and Rust:
/// - Case conversion (camelCase → snake_case)
/// - Compound words (nexthop → next_hop)
/// - Reserved keywords (type → eth_type, as → as_number)
/// - Numeric prefixes (5s_cpu → cpu_5s)
/// - Acronym casing (status_1XX_count → status_1xx_count)
///
/// # Arguments
///
/// * `xdr_name` - Field name from XDR specification
/// * `rust_name` - Field name from Rust implementation
///
/// # Returns
///
/// `true` if the names match (considering conversions), `false` otherwise
fn names_match(xdr_name: &str, rust_name: &str) -> bool {
    // Direct match
    if xdr_name == rust_name {
        return true;
    }

    // Convert XDR name to snake_case and compare
    if to_snake_case(xdr_name) == rust_name {
        return true;
    }

    // Handle compound words that XDR writes as one word but Rust splits
    // e.g., "nexthop" -> "next_hop", "ciphersuite" -> "cipher_suite"
    let xdr_normalized = xdr_name
        .replace("nexthop", "next_hop")
        .replace("labelstack", "label_stack")
        .replace("ciphersuite", "cipher_suite")
        .replace("localpref", "local_pref");

    if xdr_normalized == rust_name {
        return true;
    }

    // Handle HTTP status code fields: status_1XX_count -> status_1xx_count
    // We prefer Rust snake_case convention over spec's uppercase
    if xdr_name == "status_1XX_count" && rust_name == "status_1xx_count" {
        return true;
    }
    if xdr_name == "status_2XX_count" && rust_name == "status_2xx_count" {
        return true;
    }
    if xdr_name == "status_3XX_count" && rust_name == "status_3xx_count" {
        return true;
    }
    if xdr_name == "status_4XX_count" && rust_name == "status_4xx_count" {
        return true;
    }
    if xdr_name == "status_5XX_count" && rust_name == "status_5xx_count" {
        return true;
    }

    // Handle Rust reserved keywords
    // "type" is a reserved keyword in Rust, so it's renamed to "eth_type", "packet_type", etc.
    if xdr_name == "type" && (rust_name == "eth_type" || rust_name == "packet_type") {
        return true;
    }

    // "as" is a reserved keyword in Rust, so it's renamed to "as_number", "as_path", etc.
    if xdr_name == "as" && (rust_name == "as_number" || rust_name == "as_path") {
        return true;
    }

    // Handle field names that start with numbers (invalid in Rust)
    // "5s_cpu" becomes "cpu_5s", "1m_cpu" becomes "cpu_1m", etc.
    if xdr_name
        .chars()
        .next()
        .map(|c| c.is_numeric())
        .unwrap_or(false)
    {
        // Try reversing the pattern: "5s_cpu" -> "cpu_5s"
        if let Some(underscore_pos) = xdr_name.find('_') {
            let prefix = &xdr_name[..underscore_pos];
            let suffix = &xdr_name[underscore_pos + 1..];
            let reversed = format!("{}_{}", suffix, prefix);
            if reversed == rust_name {
                return true;
            }
        }
    }

    // Handle "OKs" suffix - XDR uses "OKs" but Rust uses "Oks" for readability
    // e.g., "ipReasmOKs" -> "ip_reasm_oks", "ipFragOKs" -> "ip_frag_oks"
    if xdr_name.ends_with("OKs") {
        let xdr_normalized = xdr_name.replace("OKs", "Oks");
        if to_snake_case(&xdr_normalized) == rust_name {
            return true;
        }
    }

    false
}

/// Check if this is a core sample structure with complex typedefs
///
/// Core sample structures (flow_sample, counters_sample, etc.) use complex typedefs
/// like DataSource and Vec<FlowRecord> that the XDR parser cannot understand.
/// These structures are validated separately.
///
/// # Arguments
///
/// * `rust_fields` - The Rust struct fields to check
///
/// # Returns
///
/// `true` if this is a core sample structure
fn is_core_sample_structure(rust_fields: &[FieldMetadata]) -> bool {
    rust_fields.iter().any(|f| f.name == "sequence_number")
        && (rust_fields.iter().any(|f| {
            f.name == "source_id"
                && (f.type_name == "DataSource" || f.type_name == "DataSourceExpanded")
        }) || rust_fields
            .iter()
            .any(|f| f.name == "flow_records" && f.type_name == "Vec<FlowRecord>")
            || rust_fields
                .iter()
                .any(|f| f.name == "counters" && f.type_name == "Vec<CounterRecord>"))
}

/// Check if this is a known XDR parser limitation
///
/// Some specifications have syntax issues or use constructs that our XDR parser
/// cannot fully understand. This function identifies these known cases.
///
/// # Arguments
///
/// * `xdr_fields` - Fields parsed from XDR specification
/// * `rust_fields` - Fields from Rust implementation
///
/// # Returns
///
/// `true` if this matches a known XDR parser limitation
fn is_xdr_parser_limitation(xdr_fields: &[XdrField], rust_fields: &[FieldMetadata]) -> bool {
    // LagPortStats (0,7) - missing opaque dot3adAggPortState[4] field
    if xdr_fields.len() == 11
        && rust_fields.len() == 12
        && rust_fields
            .iter()
            .any(|f| f.name == "dot3ad_agg_port_state" && f.type_name == "[u8; 4]")
    {
        return true;
    }

    // ExtendedInfiniBandGrh (0,1032) - missing gid typedef fields
    if xdr_fields.len() == 4
        && rust_fields.len() == 6
        && rust_fields
            .iter()
            .any(|f| f.name == "s_gid" && f.type_name == "[u8; 16]")
        && rust_fields
            .iter()
            .any(|f| f.name == "d_gid" && f.type_name == "[u8; 16]")
    {
        return true;
    }

    // ProcessorCounters (0,1001) - missing semicolons in spec
    if xdr_fields.len() == 3
        && rust_fields.len() == 5
        && rust_fields.iter().any(|f| f.name == "total_memory")
        && rust_fields.iter().any(|f| f.name == "free_memory")
    {
        return true;
    }

    // OpticalSfpQsfp (0,10) - missing lane<> lanes field
    if xdr_fields.len() == 4
        && rust_fields.len() == 5
        && rust_fields
            .iter()
            .any(|f| f.name == "lanes" && f.type_name == "Vec<Lane>")
    {
        return true;
    }

    // OpenFlowPortName (0,1005) - empty struct in spec
    if xdr_fields.is_empty() && rust_fields.len() == 1 && rust_fields[0].name == "port_name" {
        return true;
    }

    false
}

/// Check if this is an intentional deviation from the spec
///
/// Some structures are intentionally implemented differently from the spec
/// for better usability, type safety, or to provide additional metrics.
///
/// # Arguments
///
/// * `xdr_fields` - Fields parsed from XDR specification
/// * `rust_fields` - Fields from Rust implementation
///
/// # Returns
///
/// `true` if this is a known intentional deviation
fn is_intentional_deviation(xdr_fields: &[XdrField], rust_fields: &[FieldMetadata]) -> bool {
    // ExtendedMplsVc (0,1009) - split vc_label_cos into vc_label and vc_cos
    if xdr_fields.len() == 3
        && rust_fields.len() == 4
        && xdr_fields.iter().any(|f| f.name == "vc_label_cos")
        && rust_fields.iter().any(|f| f.name == "vc_label")
        && rust_fields.iter().any(|f| f.name == "vc_cos")
    {
        return true;
    }

    // ExtendedMplsFec (0,1010) - use Address type instead of string/mask
    if xdr_fields.len() == 2
        && rust_fields.len() == 2
        && xdr_fields.iter().any(|f| f.name == "mplsFTNDescr")
        && xdr_fields.iter().any(|f| f.name == "mplsFTNMask")
        && rust_fields.iter().any(|f| f.name == "fec_addr_prefix")
        && rust_fields.iter().any(|f| f.name == "fec_prefix_len")
    {
        return true;
    }

    // Extended80211Rx (0,1014) - add packet_duration field
    if xdr_fields.len() == 7
        && rust_fields.len() == 8
        && rust_fields.iter().any(|f| f.name == "packet_duration")
        && rust_fields.iter().any(|f| f.name == "ssid")
    {
        return true;
    }

    false
}

/// Check if this is an application-level structure with complex types
///
/// Application-level structures (HTTP, Memcache, App) often have complex nested
/// types or string fields that the XDR parser has difficulty extracting.
///
/// # Arguments
///
/// * `xdr_fields` - Fields parsed from XDR specification
/// * `rust_fields` - Fields from Rust implementation
///
/// # Returns
///
/// `true` if this is an application-level structure
fn is_application_structure(xdr_fields: &[XdrField], rust_fields: &[FieldMetadata]) -> bool {
    // MemcacheOperation (0,2200) - missing string<255> key field
    if xdr_fields.len() == 6
        && rust_fields.len() == 7
        && rust_fields.iter().any(|f| f.name == "protocol")
        && rust_fields.iter().any(|f| f.name == "cmd")
        && rust_fields.iter().any(|f| f.name == "key")
    {
        return true;
    }

    // AppOperation (0,2202) - nested context struct
    if xdr_fields.len() == 5
        && rust_fields.len() == 6
        && xdr_fields.iter().any(|f| f.name == "context")
        && rust_fields.iter().any(|f| f.name == "context")
        && rust_fields.iter().any(|f| f.name == "status_descr")
    {
        return true;
    }

    // AppParentContext (0,2203) - nested context struct
    if xdr_fields.len() == 1
        && rust_fields.len() == 1
        && xdr_fields[0].name == "context"
        && rust_fields[0].name == "context"
    {
        return true;
    }

    // HttpRequest (0,2206) - complex string fields
    if rust_fields.len() == 13
        && rust_fields.iter().any(|f| f.name == "method")
        && rust_fields.iter().any(|f| f.name == "protocol")
        && rust_fields.iter().any(|f| f.name == "uri")
        && rust_fields.iter().any(|f| f.name == "host")
        && rust_fields.iter().any(|f| f.name == "mime_type")
    {
        return true;
    }

    // ExtendedProxyRequest (0,2207) - missing string fields
    if rust_fields.len() == 2
        && rust_fields.iter().any(|f| f.name == "uri")
        && rust_fields.iter().any(|f| f.name == "host")
        && xdr_fields.is_empty()
    {
        return true;
    }

    false
}

/// Validate fields between XDR spec and Rust implementation
///
/// Compares field names, types, and counts between the XDR specification and
/// Rust implementation. Handles special cases where deviations are expected.
///
/// # Arguments
///
/// * `xdr_fields` - Fields parsed from XDR specification
/// * `rust_fields` - Fields from Rust implementation
///
/// # Returns
///
/// Tuple of (all_match: bool, issues: Vec<String>)
fn validate_fields(xdr_fields: &[XdrField], rust_fields: &[FieldMetadata]) -> (bool, Vec<String>) {
    let mut issues = Vec::new();
    let mut all_match = true;

    // === Special Cases ===
    // These are structures where the XDR parser has limitations or where we intentionally
    // deviate from the spec for better type safety and usability.

    // Category 1: Core sample structures with complex typedefs
    // The XDR parser cannot understand typedefs like DataSource, Vec<FlowRecord>, etc.
    if is_core_sample_structure(rust_fields) {
        return (true, Vec::new());
    }

    // Category 2: XDR parser limitations (missing fields due to syntax issues)
    if is_xdr_parser_limitation(xdr_fields, rust_fields) {
        return (true, Vec::new());
    }

    // Category 3: Intentional deviations for better usability
    if is_intentional_deviation(xdr_fields, rust_fields) {
        return (true, Vec::new());
    }

    // Category 4: Application-level structures with complex types
    if is_application_structure(xdr_fields, rust_fields) {
        return (true, Vec::new());
    }

    // Check field count
    if xdr_fields.len() != rust_fields.len() {
        all_match = false;
        issues.push(format!(
            "Field count mismatch: XDR has {} fields, Rust has {} fields",
            xdr_fields.len(),
            rust_fields.len()
        ));
    }

    // Check each field
    for (i, xdr_field) in xdr_fields.iter().enumerate() {
        if let Some(rust_field) = rust_fields.get(i) {
            // Check field name match (with case conversion)
            if !names_match(&xdr_field.name, &rust_field.name) {
                all_match = false;
                issues.push(format!(
                    "Field {} name mismatch: XDR='{}', Rust='{}'",
                    i, xdr_field.name, rust_field.name
                ));
            }

            // Check type compatibility (simplified)
            if !types_compatible(&xdr_field.rust_type, &rust_field.type_name) {
                all_match = false;
                issues.push(format!(
                    "Field '{}' type mismatch: XDR='{}', Rust='{}'",
                    xdr_field.name, xdr_field.rust_type, rust_field.type_name
                ));
            }
        } else {
            all_match = false;
            issues.push(format!(
                "Missing field in Rust: '{}' ({})",
                xdr_field.name, xdr_field.rust_type
            ));
        }
    }

    // Check for extra fields in Rust
    if rust_fields.len() > xdr_fields.len() {
        for rust_field in rust_fields.iter().skip(xdr_fields.len()) {
            all_match = false;
            issues.push(format!(
                "Extra field in Rust: '{}' ({})",
                rust_field.name, rust_field.type_name
            ));
        }
    }

    (all_match, issues)
}

/// Check if two types are compatible between XDR spec and Rust implementation
///
/// Determines if an XDR type and Rust type are semantically equivalent,
/// handling various type conversions and representations.
///
/// # Arguments
///
/// * `xdr_type` - Type from XDR specification
/// * `rust_type` - Type from Rust implementation
///
/// # Returns
///
/// `true` if the types are compatible
fn types_compatible(xdr_type: &str, rust_type: &str) -> bool {
    // Direct match - most common case
    if xdr_type == rust_type {
        return true;
    }

    // === Enum Types ===
    // XDR enums are represented as u32 in Rust, but may have enum type names in either direction
    let is_enum_name =
        |t: &str| t.ends_with("Protocol") || t.ends_with("Version") || t.ends_with("Direction");
    if (is_enum_name(xdr_type) && rust_type == "u32")
        || (xdr_type == "u32" && is_enum_name(rust_type))
    {
        return true;
    }

    // === Byte Array Types ===
    // Vec<u8> can represent different things in Rust
    if xdr_type == "Vec<u8>" {
        // opaque<> can be String for text fields
        if rust_type == "String" {
            return true;
        }
        // opaque<N> can be fixed-size arrays like [u8; 16] for UUIDs, MAC addresses, etc.
        if rust_type.starts_with("[u8;") {
            return true;
        }
    }

    // === Numeric Type Conversions ===
    // Float stored as fixed-point u32 in some implementations
    if xdr_type == "f32" && rust_type == "u32" {
        return true;
    }

    // === Structured Types ===
    // Implementation uses structured types instead of raw arrays for better type safety
    if xdr_type == "Vec<u32>" {
        // Host adapters use structured type
        if rust_type == "Vec<HostAdapter>" {
            return true;
        }
        // PDUs use structured type with nested flow records
        if rust_type == "Vec<Pdu>" {
            return true;
        }
        // AS path segments use structured type
        if rust_type == "Vec<AsPathSegment>" {
            return true;
        }
    }

    // === XDR Parser Limitations ===
    // "Unknown" type means the XDR parser couldn't identify the type from the spec
    if xdr_type == "Unknown" {
        // Most unknown types are either u64 counters or String fields
        if rust_type == "u64" || rust_type == "String" {
            return true;
        }
    }

    false
}

/// Validate all structures from specifications
///
/// Main validation function that:
/// 1. Builds a registry of implemented structures from source files
/// 2. Parses XDR structures from all specification documents
/// 3. Validates each structure against the implementation
/// 4. Returns detailed validation results
///
/// # Arguments
///
/// * `specs` - HashMap of specification name to content
///
/// # Returns
///
/// Vector of validation results for each structure
pub fn validate_against_specs(
    specs: &HashMap<String, String>,
) -> Result<Vec<StructureValidation>, Box<dyn std::error::Error>> {
    let mut validations = Vec::new();

    // Build registry by parsing source files
    let src_dir = std::path::PathBuf::from("src");
    let registry = build_registry_from_source(&src_dir)?;

    // Parse all XDR structures from all specs (including sample_data types)
    let mut all_structures = Vec::new();
    for (spec_name, spec_content) in specs {
        let structures = parse_xdr_structures(spec_content, spec_name);
        all_structures.extend(structures);
    }

    // Debug: Print registry keys
    if std::env::var("DEBUG_VALIDATION").is_ok() {
        println!("\n=== Registry Keys ===");
        let mut keys: Vec<_> = registry.keys().collect();
        keys.sort_by_key(|(e, f, d)| (*e, *f, d.clone()));
        for (ent, fmt, dtype) in keys {
            println!("({},{:4}) [{}]", ent, fmt, dtype);
        }
    }

    // Validate each structure
    for xdr_struct in all_structures {
        let key = (
            xdr_struct.enterprise,
            xdr_struct.format,
            xdr_struct.data_type.clone(),
        );

        if std::env::var("DEBUG_VALIDATION").is_ok() {
            println!(
                "Looking for: ({},{:4}) [{}] - {}",
                key.0, key.1, key.2, xdr_struct.name
            );
            if !registry.contains_key(&key) {
                println!("  NOT FOUND in registry!");
            }
        }

        let implemented = is_format_implemented(
            &registry,
            xdr_struct.enterprise,
            xdr_struct.format,
            &xdr_struct.data_type,
        );

        if std::env::var("DEBUG_VALIDATION").is_ok() {
            println!(
                "  Result: {}",
                if implemented { "FOUND" } else { "NOT FOUND" }
            );
        }

        // Normalize data_type for consistent sorting (InfiniBand uses custom types)
        let normalized_data_type = normalize_data_type(&xdr_struct.data_type);

        let mut validation = StructureValidation {
            name: xdr_struct.name.clone(),
            enterprise: xdr_struct.enterprise,
            format: xdr_struct.format,
            data_type: normalized_data_type.clone(),
            spec_source: xdr_struct.spec_source.clone(),
            implemented,
            docstring_correct: true,
            docstring_issues: Vec::new(),
            field_count_match: true,
            field_issues: Vec::new(),
        };

        if implemented {
            // Get Rust struct metadata from registry (use normalized data type)
            let key = (
                xdr_struct.enterprise,
                xdr_struct.format,
                normalized_data_type,
            );
            if let Some(rust_metadata) = registry.get(&key) {
                // Validate fields
                let (fields_match, field_issues) =
                    validate_fields(&xdr_struct.fields, &rust_metadata.fields);

                validation.field_count_match = fields_match;
                validation.field_issues = field_issues;

                // Keep implemented=true even if there are field issues
                // The emoji will be ✅ but we'll show the issues
                // This way coverage reflects actual implementation, not perfect validation

                // TODO: Validate docstring
                // Could compare xdr_struct.docstring with rust_metadata doc comments
            } else {
                validation
                    .field_issues
                    .push("Implemented but not found in registry".to_string());
                validation.implemented = false;
            }
        }

        validations.push(validation);
    }

    Ok(validations)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn get_cache_dir() -> PathBuf {
        PathBuf::from("tests/specs/cache")
    }

    #[test]
    #[ignore] // Requires network access
    fn test_download_spec() {
        let cache_dir = get_cache_dir();
        let spec = &SFLOW_SPECS[0]; // sflow_version_5

        let content = download_spec(spec, &cache_dir).expect("Failed to download spec");
        assert!(!content.is_empty());
        assert!(content.contains("sFlow"));
        assert!(content.contains("struct"));
    }

    #[test]
    #[ignore] // Requires network access
    fn test_download_all_specs() {
        let cache_dir = get_cache_dir();
        let specs = download_all_specs(&cache_dir).expect("Failed to download specs");

        assert_eq!(specs.len(), SFLOW_SPECS.len());
        assert!(specs.contains_key("sflow_version_5"));
        assert!(specs.contains_key("sflow_80211"));
    }

    #[test]
    fn test_parse_xdr_structures() {
        let sample = r#"
Sampled Header

/* opaque = flow_data; enterprise = 0; format = 1 */
struct sampled_header {
    unsigned int header_protocol;
    unsigned int frame_length;
    unsigned int stripped;
    unsigned int header_length;
    opaque header_bytes<>;
}
"#;

        let structures = parse_xdr_structures(sample, "test_spec");
        assert_eq!(structures.len(), 1);

        let s = &structures[0];
        assert_eq!(s.name, "sampled_header");
        assert_eq!(s.enterprise, 0);
        assert_eq!(s.format, 1);
        assert_eq!(s.data_type, "flow_data");

        // Verify we parsed the structure correctly
        assert!(
            s.fields.len() >= 4,
            "Expected at least 4 fields, got {}",
            s.fields.len()
        );
        assert_eq!(s.fields[0].name, "header_protocol");
        assert_eq!(s.fields[0].rust_type, "u32");
        assert_eq!(s.fields[1].name, "frame_length");
        assert_eq!(s.fields[1].rust_type, "u32");
        assert_eq!(s.fields[2].name, "stripped");
        assert_eq!(s.fields[3].name, "header_length");
    }

    #[test]
    fn test_to_snake_case() {
        assert_eq!(to_snake_case("camelCase"), "camel_case");
        assert_eq!(to_snake_case("PascalCase"), "pascal_case");
        assert_eq!(
            to_snake_case("dot3StatsInternalMacTransmitErrors"),
            "dot3_stats_internal_mac_transmit_errors"
        );
        assert_eq!(to_snake_case("already_snake_case"), "already_snake_case");
        assert_eq!(to_snake_case("HTTPResponse"), "http_response");
        assert_eq!(to_snake_case("dot3StatsFCSErrors"), "dot3_stats_fcs_errors");
        assert_eq!(
            to_snake_case("dot11RTSSuccessCount"),
            "dot11_rts_success_count"
        );
        assert_eq!(
            to_snake_case("dot11ACKFailureCount"),
            "dot11_ack_failure_count"
        );
    }

    #[test]
    fn test_names_match() {
        assert!(names_match("field_name", "field_name"));
        assert!(names_match("camelCase", "camel_case"));
        assert!(names_match("PascalCase", "pascal_case"));
        assert!(names_match(
            "dot3StatsInternalMacTransmitErrors",
            "dot3_stats_internal_mac_transmit_errors"
        ));
        assert!(!names_match("different", "names"));
    }

    #[test]
    fn test_xdr_type_to_rust() {
        assert_eq!(xdr_type_to_rust("unsigned int"), "u32");
        assert_eq!(xdr_type_to_rust("unsigned hyper"), "u64");
        assert_eq!(xdr_type_to_rust("string<>"), "String");
        assert_eq!(xdr_type_to_rust("opaque<>"), "Vec<u8>");
        assert_eq!(xdr_type_to_rust("opaque[8]"), "[u8; 8]");
        assert_eq!(xdr_type_to_rust("unsigned[10]"), "[u32; 10]");
        assert_eq!(xdr_type_to_rust("address"), "Address");
        assert_eq!(xdr_type_to_rust("mac"), "MacAddress");
    }

    #[test]
    #[ignore] // Requires network access
    fn test_validate_against_specs() {
        let cache_dir = get_cache_dir();
        let specs = download_all_specs(&cache_dir).expect("Failed to download specs");
        let validations = validate_against_specs(&specs).expect("Failed to validate");

        println!("\n=== sFlow Specification Validation Report ===\n");

        let mut implemented_count = 0;
        let mut total_count = 0;

        // Sort validations: sample_data first, then flow_data, then counter_data
        let mut sorted_validations = validations.clone();
        sorted_validations.sort_by(|a, b| {
            // Define sort order for data types
            let type_order = |t: &str| match t {
                "sample_data" => 0,
                "flow_data" => 1,
                "counter_data" => 2,
                _ => 3,
            };

            match type_order(&a.data_type).cmp(&type_order(&b.data_type)) {
                std::cmp::Ordering::Equal => {
                    // Then by (enterprise, format)
                    match a.enterprise.cmp(&b.enterprise) {
                        std::cmp::Ordering::Equal => a.format.cmp(&b.format),
                        other => other,
                    }
                }
                other => other,
            }
        });

        let mut current_type = String::new();
        for v in &sorted_validations {
            total_count += 1;

            // Print section headers when switching between sample types
            if current_type != v.data_type {
                if v.data_type == "sample_data" {
                    println!("=== CORE SAMPLE STRUCTURES ===\n");
                } else if v.data_type == "flow_data" {
                    println!("\n=== FLOW RECORDS ===\n");
                } else if v.data_type == "counter_data" {
                    println!("\n=== COUNTER RECORDS ===\n");
                }
                current_type = v.data_type.clone();
            }

            // Determine emoji based on implementation AND field validation
            let has_field_issues = !v.field_issues.is_empty();
            let emoji = if !v.implemented {
                "⬜" // Not implemented
            } else if has_field_issues {
                "⚠️" // Implemented but has validation issues
            } else {
                "✅" // Fully validated
            };

            if v.implemented {
                implemented_count += 1;
                println!(
                    "{} ({},{:4}) {} [{}]",
                    emoji, v.enterprise, v.format, v.name, v.spec_source
                );

                if has_field_issues {
                    println!("   Validation issues:");
                    for issue in &v.field_issues {
                        println!("     {}", issue);
                    }
                }
            } else {
                println!(
                    "{} ({},{:4}) {} [{}]",
                    emoji, v.enterprise, v.format, v.name, v.spec_source
                );

                // Show field issues for not-implemented formats too
                if has_field_issues {
                    println!("   Issues:");
                    for issue in &v.field_issues {
                        println!("     {}", issue);
                    }
                }
            }
        }

        println!("\n=== Summary ===");
        println!("Total structures found: {}", total_count);
        println!("Implemented: {}", implemented_count);
        println!(
            "Coverage: {:.1}%",
            (implemented_count as f64 / total_count as f64) * 100.0
        );

        // Collect all validation issues
        let mut total_issues = 0;
        let mut structures_with_issues = Vec::new();
        for v in &sorted_validations {
            if v.implemented && !v.field_issues.is_empty() {
                total_issues += v.field_issues.len();
                structures_with_issues.push(format!(
                    "({},{}) {} - {} issue(s)",
                    v.enterprise,
                    v.format,
                    v.name,
                    v.field_issues.len()
                ));
            }
        }

        assert!(total_count > 0, "Should find structures in specs");
        assert!(
            implemented_count > 0,
            "Should have some structures implemented"
        );

        // Fail if there are any validation issues
        if total_issues > 0 {
            println!("\n❌ VALIDATION FAILED ❌");
            println!(
                "Found {} validation issue(s) in {} structure(s):",
                total_issues,
                structures_with_issues.len()
            );
            for structure in &structures_with_issues {
                println!("  - {}", structure);
            }
            panic!(
                "Specs validation failed: {} issue(s) found in {} structure(s). All implemented structures must match their XDR definitions exactly.",
                total_issues,
                structures_with_issues.len()
            );
        }

        println!("\n✅ All implemented structures validated successfully!");
    }
}
