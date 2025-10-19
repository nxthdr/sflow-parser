//! Parser for C header files (sflow.h)
//!
//! This module parses the official sflow.h header file and extracts
//! struct definitions, format numbers, and field information.

use regex::Regex;
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq)]
pub struct CField {
    pub name: String,
    pub c_type: String,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct CStruct {
    pub name: String,
    pub fields: Vec<CField>,
    pub comment: Option<String>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct FormatDefinition {
    pub enterprise: u32,
    pub format: u32,
    pub name: String,
    pub description: String,
}

/// Parse sflow.h content and extract struct definitions
pub fn parse_sflow_header(content: &str) -> HashMap<String, CStruct> {
    let mut structs = HashMap::new();

    // Regex to match typedef struct definitions
    // Matches: typedef struct _Name { ... } Name;
    let struct_re = Regex::new(r"(?s)typedef\s+struct\s+_(\w+)\s*\{([^}]+)\}\s*(\w+);").unwrap();

    for cap in struct_re.captures_iter(content) {
        let _internal_name = cap.get(1).unwrap().as_str();
        let body = cap.get(2).unwrap().as_str();
        let typedef_name = cap.get(3).unwrap().as_str();

        let fields = parse_struct_fields(body);

        structs.insert(
            typedef_name.to_string(),
            CStruct {
                name: typedef_name.to_string(),
                fields,
                comment: None,
            },
        );
    }

    structs
}

/// Parse fields from a struct body
fn parse_struct_fields(body: &str) -> Vec<CField> {
    let mut fields = Vec::new();

    // Remove comments
    let body = remove_c_comments(body);

    // Split by semicolons to get individual field declarations
    for line in body.split(';') {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Try to parse field declaration
        if let Some(field) = parse_field_declaration(line) {
            fields.push(field);
        }
    }

    fields
}

/// Parse a single field declaration
fn parse_field_declaration(decl: &str) -> Option<CField> {
    let decl = decl.trim();

    // Handle pointer types: "type *name" or "type* name"
    if let Some(pos) = decl.rfind('*') {
        let type_part = decl[..=pos].trim();
        let name_part = decl[pos + 1..].trim();

        // Extract just the field name (remove array brackets if present)
        let name = if let Some(bracket_pos) = name_part.find('[') {
            name_part[..bracket_pos].trim().to_string()
        } else {
            name_part.to_string()
        };

        return Some(CField {
            name,
            c_type: type_part.to_string(),
        });
    }

    // Handle array types: "type name[size]"
    if let Some(bracket_pos) = decl.find('[') {
        let before_bracket = &decl[..bracket_pos];
        let parts: Vec<&str> = before_bracket.split_whitespace().collect();

        if parts.len() >= 2 {
            let name = parts.last().unwrap().to_string();
            let c_type = parts[..parts.len() - 1].join(" ");

            // Include array size in type
            let array_part = &decl[bracket_pos..];

            return Some(CField {
                name,
                c_type: format!("{}{}", c_type, array_part),
            });
        }
    }

    // Handle regular types: "type name"
    let parts: Vec<&str> = decl.split_whitespace().collect();
    if parts.len() >= 2 {
        let name = parts.last().unwrap().to_string();
        let c_type = parts[..parts.len() - 1].join(" ");

        return Some(CField { name, c_type });
    }

    None
}

/// Remove C-style comments from text
#[allow(clippy::while_let_on_iterator)]
fn remove_c_comments(text: &str) -> String {
    let mut result = String::new();
    let mut chars = text.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '/' {
            if let Some(&next) = chars.peek() {
                if next == '/' {
                    // Single-line comment - skip until newline
                    chars.next(); // consume the second '/'
                    while let Some(c) = chars.next() {
                        if c == '\n' {
                            result.push('\n');
                            break;
                        }
                    }
                    continue;
                } else if next == '*' {
                    // Multi-line comment - skip until */
                    chars.next(); // consume the '*'
                    let mut prev = ' ';
                    while let Some(c) = chars.next() {
                        if prev == '*' && c == '/' {
                            break;
                        }
                        prev = c;
                    }
                    continue;
                }
            }
        }
        result.push(c);
    }

    result
}

/// Parse format definitions from comments
/// Looks for patterns like: "opaque = flow_data; enterprise = 0; format = 1001"
pub fn parse_format_definitions(content: &str) -> Vec<FormatDefinition> {
    let mut formats = Vec::new();

    // Regex to match format definitions in comments
    let format_re =
        Regex::new(r"opaque\s*=\s*(\w+);\s*enterprise\s*=\s*(\d+);\s*format\s*=\s*(\d+)").unwrap();

    for cap in format_re.captures_iter(content) {
        let data_type = cap.get(1).unwrap().as_str();
        let enterprise: u32 = cap.get(2).unwrap().as_str().parse().unwrap();
        let format: u32 = cap.get(3).unwrap().as_str().parse().unwrap();

        formats.push(FormatDefinition {
            enterprise,
            format,
            name: String::new(), // Will be filled from struct name
            description: data_type.to_string(),
        });
    }

    formats
}

/// Map C types to Rust types
pub fn c_type_to_rust(c_type: &str) -> String {
    let c_type = c_type.trim();

    match c_type {
        "uint32_t" => "u32".to_string(),
        "uint64_t" => "u64".to_string(),
        "uint16_t" => "u16".to_string(),
        "uint8_t" => "u8".to_string(),
        "int32_t" => "i32".to_string(),
        "int64_t" => "i64".to_string(),
        "int16_t" => "i16".to_string(),
        "int8_t" => "i8".to_string(),
        "unsigned int" => "u32".to_string(),
        "unsigned long" => "u64".to_string(),
        "unsigned short" => "u16".to_string(),
        "unsigned char" => "u8".to_string(),
        "int" => "i32".to_string(),
        "long" => "i64".to_string(),
        "short" => "i16".to_string(),
        "char" => "i8".to_string(),
        "SFLIPv4" => "Ipv4Addr".to_string(),
        "SFLIPv6" => "Ipv6Addr".to_string(),
        "SFLAddress" => "Address".to_string(),
        "SFLCipherSuite" => "u32".to_string(),
        "SFL_IEEE80211_version" => "u32".to_string(),
        "EnumPktDirection" => "u32".to_string(),
        _ if c_type.starts_with("char*") || c_type.starts_with("char *") => "String".to_string(),
        _ if c_type.starts_with("uint8_t*") || c_type.starts_with("uint8_t *") => {
            "Vec<u8>".to_string()
        }
        _ if c_type.contains("char[6]") || c_type.contains("uint8_t[6]") => {
            "MacAddress".to_string()
        }
        _ if c_type.contains("char[8]") || c_type.contains("uint8_t[8]") => {
            "MacAddress".to_string()
        } // 6 bytes + 2 padding
        _ if c_type.starts_with("SFLString") => "String".to_string(),
        _ if c_type.starts_with("SFLLabelStack") => "Vec<u32>".to_string(),
        _ if c_type.starts_with("SFLVlanStack") => "Vec<u32>".to_string(),
        _ => c_type.to_string(), // Keep as-is for custom types
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_struct() {
        let content = r#"
typedef struct _SFLExtended_switch {
  uint32_t src_vlan;
  uint32_t src_priority;
  uint32_t dst_vlan;
  uint32_t dst_priority;
} SFLExtended_switch;
"#;

        let structs = parse_sflow_header(content);
        assert_eq!(structs.len(), 1);

        let switch_struct = structs.get("SFLExtended_switch").unwrap();
        assert_eq!(switch_struct.fields.len(), 4);
        assert_eq!(switch_struct.fields[0].name, "src_vlan");
        assert_eq!(switch_struct.fields[0].c_type, "uint32_t");
    }

    #[test]
    fn test_parse_struct_with_pointers() {
        let content = r#"
typedef struct _SFLSampled_header {
  uint32_t header_protocol;
  uint32_t frame_length;
  uint8_t *header_bytes;
} SFLSampled_header;
"#;

        let structs = parse_sflow_header(content);
        let header = structs.get("SFLSampled_header").unwrap();

        assert_eq!(header.fields.len(), 3);
        assert_eq!(header.fields[2].name, "header_bytes");
        assert_eq!(header.fields[2].c_type, "uint8_t *");
    }

    #[test]
    fn test_parse_struct_with_arrays() {
        let content = r#"
typedef struct _SFLSampled_ethernet {
  uint32_t eth_len;
  uint8_t src_mac[8];
  uint8_t dst_mac[8];
  uint32_t eth_type;
} SFLSampled_ethernet;
"#;

        let structs = parse_sflow_header(content);
        let eth = structs.get("SFLSampled_ethernet").unwrap();

        assert_eq!(eth.fields.len(), 4);
        assert_eq!(eth.fields[1].name, "src_mac");
        assert_eq!(eth.fields[1].c_type, "uint8_t[8]");
    }

    #[test]
    fn test_parse_struct_with_comments() {
        let content = r#"
typedef struct _SFLExtended_router {
  SFLAddress nexthop;  /* IP address of next hop router */
  uint32_t src_mask;   /* Source address prefix mask bits */
  uint32_t dst_mask;   /* Destination address prefix mask bits */
} SFLExtended_router;
"#;

        let structs = parse_sflow_header(content);
        let router = structs.get("SFLExtended_router").unwrap();

        assert_eq!(router.fields.len(), 3);
        assert_eq!(router.fields[0].name, "nexthop");
        assert_eq!(router.fields[0].c_type, "SFLAddress");
    }

    #[test]
    fn test_c_type_to_rust() {
        assert_eq!(c_type_to_rust("uint32_t"), "u32");
        assert_eq!(c_type_to_rust("uint64_t"), "u64");
        assert_eq!(c_type_to_rust("SFLIPv4"), "Ipv4Addr");
        assert_eq!(c_type_to_rust("SFLIPv6"), "Ipv6Addr");
        assert_eq!(c_type_to_rust("char*"), "String");
        assert_eq!(c_type_to_rust("uint8_t *"), "Vec<u8>");
        assert_eq!(c_type_to_rust("uint8_t[6]"), "MacAddress");
        assert_eq!(c_type_to_rust("uint8_t[8]"), "MacAddress");
    }

    #[test]
    fn test_parse_format_definitions() {
        let content = r#"
/* opaque = flow_data; enterprise = 0; format = 1001 */
typedef struct _SFLExtended_switch {
  uint32_t src_vlan;
} SFLExtended_switch;

/* opaque = counter_data; enterprise = 0; format = 1 */
typedef struct _SFLIf_counters {
  uint32_t ifIndex;
} SFLIf_counters;
"#;

        let formats = parse_format_definitions(content);
        assert_eq!(formats.len(), 2);

        assert_eq!(formats[0].enterprise, 0);
        assert_eq!(formats[0].format, 1001);
        assert_eq!(formats[0].description, "flow_data");

        assert_eq!(formats[1].enterprise, 0);
        assert_eq!(formats[1].format, 1);
        assert_eq!(formats[1].description, "counter_data");
    }

    #[test]
    fn test_remove_c_comments() {
        let text = "uint32_t field1; /* comment */ uint32_t field2;";
        let cleaned = remove_c_comments(text);
        assert!(!cleaned.contains("comment"));
        assert!(cleaned.contains("field1"));
        assert!(cleaned.contains("field2"));
    }
}
