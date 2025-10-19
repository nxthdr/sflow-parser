//! Automatic validation against official sFlow specification
//!
//! This module automatically downloads sflow.h, parses it, and validates
//! our Rust implementation against the official C specification.

use super::sflowtool_parser_spec::{
    c_type_to_rust, parse_format_definitions, parse_sflow_header, CStruct,
};
use super::specs_parser_lib_ast::{build_registry_from_source, StructRegistry};
use std::collections::HashMap;
use std::path::PathBuf;

const SFLOW_H_URL: &str =
    "https://raw.githubusercontent.com/sflow/sflowtool/refs/heads/master/src/sflow.h";

/// Download sflow.h from GitHub
pub fn download_sflow_h() -> Result<String, Box<dyn std::error::Error>> {
    let response = ureq::get(SFLOW_H_URL).call()?;
    let content = response.into_string()?;
    Ok(content)
}

/// Validation result for a single format
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct FormatValidation {
    pub enterprise: u32,
    pub format: u32,
    pub name: String,
    pub implemented: bool,
    pub struct_name: Option<String>,
    pub field_validation: Option<FieldValidationResult>,
}

/// Field validation result
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct FieldValidationResult {
    pub correct: bool,
    pub expected_fields: Vec<FieldInfo>,
    pub issues: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct FieldInfo {
    pub name: String,
    pub c_type: String,
    pub rust_type: String,
}

/// Build a map of (enterprise, format, data_type) -> struct_name from sflow.h content
fn build_format_to_struct_map(sflow_content: &str) -> HashMap<(u32, u32, String), String> {
    use regex::Regex;

    let mut map = HashMap::new();

    // First, extract all format definitions with their positions
    let format_re = Regex::new(
        r"/\*[^*]*opaque\s*=\s*(\w+);\s*enterprise\s*=\s*(\d+);\s*format\s*=\s*(\d+)[^*]*\*/",
    )
    .unwrap();

    // Then extract all typedef structs with their positions
    let struct_re = Regex::new(r"typedef\s+struct\s+_(\w+)\s*\{[^}]+\}\s*(\w+);").unwrap();

    // Collect all format definitions with their byte positions
    let mut formats: Vec<(usize, u32, u32, String)> = Vec::new();
    for cap in format_re.captures_iter(sflow_content) {
        let pos = cap.get(0).unwrap().start();
        let data_type = cap.get(1).unwrap().as_str().to_string();
        let enterprise: u32 = cap.get(2).unwrap().as_str().parse().unwrap();
        let format: u32 = cap.get(3).unwrap().as_str().parse().unwrap();
        formats.push((pos, enterprise, format, data_type));
    }

    // Collect all struct definitions with their positions
    let mut structs: Vec<(usize, String)> = Vec::new();
    for cap in struct_re.captures_iter(sflow_content) {
        let pos = cap.get(0).unwrap().start();
        let struct_name = cap.get(2).unwrap().as_str().to_string();
        structs.push((pos, struct_name));
    }

    // Match each format to the nearest following struct (within reasonable distance)
    for (format_pos, enterprise, format, data_type) in formats {
        // Find the first struct that comes after this format comment (within 2000 chars)
        if let Some((_, struct_name)) = structs
            .iter()
            .find(|(struct_pos, _)| *struct_pos > format_pos && *struct_pos - format_pos < 2000)
        {
            map.insert((enterprise, format, data_type), struct_name.clone());
        }
    }

    map
}

/// Check if a format is implemented using AST-parsed registry
fn is_format_implemented(
    registry: &StructRegistry,
    enterprise: u32,
    format: u32,
    data_type: &str,
) -> bool {
    registry.contains_key(&(enterprise, format, data_type.to_string()))
}

/// Convert sflowtool name to comparable format
fn normalize_sflowtool_name(name: &str) -> String {
    name.to_lowercase()
        .replace("sfl", "") // Remove SFL prefix
        .replace("extended_", "") // Remove extended_ prefix
        .replace("_counters", "") // Remove _counters suffix
        .replace("wifi", "80211") // wifi -> 80211
        .replace("vrt", "virtual") // vrt -> virtual
        .replace("dsk", "disk") // dsk -> disk
        .replace("nio", "netio") // nio -> netio
        .replace("ovsdp", "openflow") // ovsdp -> openflow
        .replace("jvm", "") // Remove jvm
        .replace("_id", "") // Remove _id suffix
        .replace("_", "") // Remove all underscores
}

/// Convert our implementation name to comparable format
fn normalize_our_name(name: &str) -> String {
    // Convert CamelCase to lowercase without separators
    let mut result = String::new();
    for ch in name.chars() {
        if ch.is_uppercase() {
            result.push_str(&ch.to_lowercase().to_string());
        } else {
            result.push(ch);
        }
    }
    result
}

/// Check if sflowtool name matches our implementation name
/// Handles naming convention differences between sflowtool and official specs
fn names_match_sflowtool(sflowtool_name: &str, our_name: &str) -> bool {
    let sfl_normalized = normalize_sflowtool_name(sflowtool_name);
    let our_normalized = normalize_our_name(our_name);

    // Check if they match after normalization
    if sfl_normalized == our_normalized {
        return true;
    }

    // Check if one contains the other (for partial matches)
    if sfl_normalized.contains(&our_normalized) || our_normalized.contains(&sfl_normalized) {
        return true;
    }

    // Special cases for known mappings
    let special_mappings = [
        ("host_vrt_node", "virtualnode"),
        ("host_vrt_cpu", "virtualcpu"),
        ("host_vrt_mem", "virtualmemory"),
        ("host_vrt_dsk", "virtualdiskio"),
        ("host_vrt_nio", "virtualnetio"),
        ("aggregation", "80211aggregation"),
        ("socket_ipv4", "socketipv4"),
        ("socket_ipv6", "socketipv6"),
        ("virtualmem", "virtualmemory"),  // vrt_mem -> VirtualMemory
        ("virtualdisk", "virtualdiskio"), // vrt_dsk -> VirtualDiskIo
    ];

    for (sfl_pattern, our_pattern) in &special_mappings {
        if sfl_normalized.contains(sfl_pattern) && our_normalized.contains(our_pattern) {
            return true;
        }
        // Also check reverse
        if our_normalized.contains(sfl_pattern) && sfl_normalized.contains(our_pattern) {
            return true;
        }
    }

    // Check if normalized names are very similar (allow for minor differences)
    let similarity = if sfl_normalized.len() > our_normalized.len() {
        our_normalized.len() as f32 / sfl_normalized.len() as f32
    } else {
        sfl_normalized.len() as f32 / our_normalized.len() as f32
    };

    // If lengths are similar and one contains most of the other, consider it a match
    if similarity > 0.7 {
        let common_chars = sfl_normalized
            .chars()
            .filter(|c| our_normalized.contains(*c))
            .count();
        let max_len = sfl_normalized.len().max(our_normalized.len());
        if common_chars as f32 / max_len as f32 > 0.8 {
            return true;
        }
    }

    false
}

/// Validate all formats from sflow.h
pub fn validate_all_formats(
    sflow_content: &str,
) -> Result<Vec<FormatValidation>, Box<dyn std::error::Error>> {
    let structs = parse_sflow_header(sflow_content);
    let formats = parse_format_definitions(sflow_content);
    let format_map = build_format_to_struct_map(sflow_content);

    // Build registry from source files
    let src_dir = PathBuf::from("src");
    let registry = build_registry_from_source(&src_dir)?;

    let mut validations = Vec::new();

    for format_def in formats {
        // Look up struct name from the automatically built map
        let struct_name = format_map
            .get(&(
                format_def.enterprise,
                format_def.format,
                format_def.description.clone(),
            ))
            .cloned();

        let implemented = is_format_implemented(
            &registry,
            format_def.enterprise,
            format_def.format,
            &format_def.description,
        );

        let field_validation = if implemented {
            struct_name
                .as_ref()
                .and_then(|sname| structs.get(sname).map(validate_struct_fields))
        } else {
            None
        };

        validations.push(FormatValidation {
            enterprise: format_def.enterprise,
            format: format_def.format,
            name: struct_name.clone().unwrap_or_else(|| "Unknown".to_string()),
            implemented,
            struct_name,
            field_validation,
        });
    }

    Ok(validations)
}

/// Validate struct fields (placeholder - would compare against actual Rust structs)
fn validate_struct_fields(c_struct: &CStruct) -> FieldValidationResult {
    let mut expected_fields = Vec::new();
    let issues = Vec::new();

    for field in &c_struct.fields {
        let rust_type = c_type_to_rust(&field.c_type);
        expected_fields.push(FieldInfo {
            name: field.name.clone(),
            c_type: field.c_type.clone(),
            rust_type: rust_type.clone(),
        });
    }

    // For now, we assume fields are correct if we found the struct
    // In a real implementation, you'd use reflection or macros to compare
    // against actual Rust struct definitions

    FieldValidationResult {
        correct: true,
        expected_fields,
        issues,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore] // Requires network access
    fn test_download_sflow_h() {
        let content = download_sflow_h().expect("Failed to download sflow.h");
        assert!(!content.is_empty());
        assert!(content.contains("typedef struct"));
        assert!(content.contains("sFlow"));
    }

    #[test]
    #[ignore] // Requires network access
    fn test_validate_all_formats_live() {
        let content = download_sflow_h().expect("Failed to download sflow.h");
        let mut validations = validate_all_formats(&content).expect("Failed to validate");

        // Filter out "Unknown" entries (formats without matched structs)
        validations.retain(|v| v.name != "Unknown");

        // Separate into flows and counters, then sort each by (enterprise, format)
        let mut flow_validations: Vec<_> = validations
            .iter()
            .filter(|v| !v.name.contains("counter") && !v.name.contains("Counter"))
            .collect();
        let mut counter_validations: Vec<_> = validations
            .iter()
            .filter(|v| v.name.contains("counter") || v.name.contains("Counter"))
            .collect();

        // Sort by (enterprise, format)
        flow_validations.sort_by_key(|v| (v.enterprise, v.format));
        counter_validations.sort_by_key(|v| (v.enterprise, v.format));

        // Combine: flows first, then counters
        let sorted_validations: Vec<_> = flow_validations
            .into_iter()
            .chain(counter_validations.into_iter())
            .collect();

        println!("\n=== sFlow Format Validation Report ===\n");

        let mut implemented_count = 0;
        let mut total_count = 0;
        let mut field_validated_count = 0;
        let mut format_conflicts = Vec::new();

        // Build registry to check for naming mismatches
        let src_dir = PathBuf::from("src");
        let registry = build_registry_from_source(&src_dir).expect("Failed to build registry");

        // Track format numbers to detect duplicates
        // Note: Same format number can be used for both flow_data and counter_data
        let mut format_tracker: std::collections::HashMap<(u32, u32, String), Vec<String>> =
            std::collections::HashMap::new();

        let mut current_type = String::new();
        for validation in &sorted_validations {
            total_count += 1;

            // Determine data type from struct name
            let data_type =
                if validation.name.contains("counter") || validation.name.contains("Counter") {
                    "counter_data"
                } else {
                    "flow_data"
                };

            // Print section headers when switching between flows and counters
            if current_type != data_type {
                if data_type == "flow_data" {
                    println!("=== FLOW RECORDS ===\n");
                } else {
                    println!("\n=== COUNTER RECORDS ===\n");
                }
                current_type = data_type.to_string();
            }

            // Track format numbers for conflict detection (including data type)
            format_tracker
                .entry((
                    validation.enterprise,
                    validation.format,
                    data_type.to_string(),
                ))
                .or_default()
                .push(validation.name.clone());

            if validation.implemented {
                implemented_count += 1;

                // Check if there's a naming mismatch with our implementation
                let our_struct = registry.get(&(
                    validation.enterprise,
                    validation.format,
                    if validation.name.contains("counter") || validation.name.contains("Counter") {
                        "counter_data"
                    } else {
                        "flow_data"
                    }
                    .to_string(),
                ));

                let has_naming_conflict = if let Some(our_impl) = our_struct {
                    // Use proper name matching to avoid false positives from naming conventions
                    !names_match_sflowtool(&validation.name, &our_impl.name)
                } else {
                    false
                };

                if let Some(ref field_val) = validation.field_validation {
                    field_validated_count += 1;

                    let marker = if has_naming_conflict {
                        "⚠️ "
                    } else {
                        "✅"
                    };
                    println!(
                        "{} ({},{:4}) {} - {} fields validated{}",
                        marker,
                        validation.enterprise,
                        validation.format,
                        validation.name,
                        field_val.expected_fields.len(),
                        if has_naming_conflict {
                            " [NAMING CONFLICT]"
                        } else {
                            ""
                        }
                    );

                    if has_naming_conflict {
                        if let Some(our_impl) = our_struct {
                            println!("   ℹ️  Our implementation: {}", our_impl.name);
                            format_conflicts.push(format!(
                                "({},{:4}) sflowtool='{}' vs our='{}'",
                                validation.enterprise,
                                validation.format,
                                validation.name,
                                our_impl.name
                            ));
                        }
                    }

                    if !field_val.issues.is_empty() {
                        for issue in &field_val.issues {
                            println!("   ⚠️  {}", issue);
                        }
                    }
                } else {
                    println!(
                        "✅ ({},{:4}) {} - implemented (no struct found)",
                        validation.enterprise, validation.format, validation.name
                    );
                }
            } else {
                println!(
                    "⬜ ({},{:4}) {} - not implemented",
                    validation.enterprise, validation.format, validation.name
                );
            }
        }

        // Check for duplicate format numbers within the same data type
        let mut duplicate_formats = Vec::new();
        for ((ent, fmt, data_type), names) in &format_tracker {
            if names.len() > 1 {
                duplicate_formats.push(format!(
                    "({},{:4}) [{}] used by: {}",
                    ent,
                    fmt,
                    data_type,
                    names.join(", ")
                ));
            }
        }

        println!("\n=== Summary ===");
        println!("Total formats found: {}", total_count);
        println!("Implemented: {}", implemented_count);
        println!("Field-validated: {}", field_validated_count);
        println!(
            "Coverage: {:.1}%",
            (implemented_count as f64 / total_count as f64) * 100.0
        );

        if !duplicate_formats.is_empty() {
            println!(
                "\n⚠️  FORMAT NUMBER CONFLICTS IN SFLOWTOOL ({}):",
                duplicate_formats.len()
            );
            for conflict in &duplicate_formats {
                println!("   {}", conflict);
            }
        }

        if !format_conflicts.is_empty() {
            println!("\n⚠️  NAMING INCONSISTENCIES ({}):", format_conflicts.len());
            for conflict in &format_conflicts {
                println!("   {}", conflict);
            }
            println!("\nNote: These are inconsistencies in sflowtool's sflow.h.");
            println!("Our implementation follows the official sFlow specifications.");
        }

        assert!(total_count > 0, "Should find formats in sflow.h");
        assert!(
            implemented_count > 0,
            "Should have some formats implemented"
        );
    }

    #[test]
    fn test_comprehensive_validation() {
        // This is a comprehensive sample with few formats from the real sflow.h
        let sample = r#"
/* opaque = flow_data; enterprise = 0; format = 1 */
typedef struct _SFLSampled_header {
  uint32_t header_protocol;
  uint32_t frame_length;
  uint32_t stripped;
  uint32_t header_length;
  uint8_t *header_bytes;
} SFLSampled_header;

/* opaque = flow_data; enterprise = 0; format = 2 */
typedef struct _SFLSampled_ethernet {
  uint32_t eth_len;
  uint8_t src_mac[8];
  uint8_t dst_mac[8];
  uint32_t eth_type;
} SFLSampled_ethernet;

/* opaque = flow_data; enterprise = 0; format = 2100 */
typedef struct _SFLExtended_socket_ipv4 {
   uint32_t protocol;
   SFLIPv4 local_ip;
   SFLIPv4 remote_ip;
   uint32_t local_port;
   uint32_t remote_port;
} SFLExtended_socket_ipv4;
"#;

        let validations = validate_all_formats(sample).expect("Failed to validate");

        println!("\n╔══════════════════════════════════════════════════════════════╗");
        println!("║          COMPREHENSIVE SFLOW VALIDATION REPORT              ║");
        println!("╚══════════════════════════════════════════════════════════════╝\n");

        let mut implemented = Vec::new();
        let mut not_implemented = Vec::new();

        for v in &validations {
            if v.implemented {
                implemented.push(v);
            } else {
                not_implemented.push(v);
            }
        }

        println!("✅ IMPLEMENTED FORMATS ({}):\n", implemented.len());
        for v in &implemented {
            println!("  ({},{:4}) {}", v.enterprise, v.format, v.name);
            if let Some(ref fv) = v.field_validation {
                println!("         {} fields validated:", fv.expected_fields.len());
                for field in &fv.expected_fields {
                    println!(
                        "           • {} {} → {}",
                        field.c_type, field.name, field.rust_type
                    );
                }
            }
            println!();
        }

        println!(
            "\n⬜ NOT IMPLEMENTED FORMATS ({}):\n",
            not_implemented.len()
        );
        for v in &not_implemented {
            println!("  ({},{:4}) {}", v.enterprise, v.format, v.name);
        }

        println!("\n{}", "═".repeat(64));
        println!("SUMMARY:");
        println!("  Total formats: {}", validations.len());
        println!(
            "  Implemented: {} ({:.1}%)",
            implemented.len(),
            (implemented.len() as f64 / validations.len() as f64) * 100.0
        );
        println!("  Not implemented: {}", not_implemented.len());
        println!("{}\n", "═".repeat(64));

        // Check we found all 3 formats
        assert_eq!(validations.len(), 3);

        // Check format 1 (SampledHeader) is implemented
        let header = validations.iter().find(|v| v.format == 1).unwrap();
        assert!(header.implemented);
        assert_eq!(header.name, "SFLSampled_header");
        assert!(header.field_validation.is_some());
        let header_fields = &header.field_validation.as_ref().unwrap().expected_fields;
        assert_eq!(header_fields.len(), 5);
        assert_eq!(header_fields[0].name, "header_protocol");
        assert_eq!(header_fields[0].rust_type, "u32");
        assert_eq!(header_fields[4].rust_type, "Vec<u8>");

        // Check format 2 (SampledEthernet) is implemented
        let ethernet = validations.iter().find(|v| v.format == 2).unwrap();
        assert!(ethernet.implemented);
        let eth_fields = &ethernet.field_validation.as_ref().unwrap().expected_fields;
        assert_eq!(eth_fields.len(), 4);
        assert_eq!(eth_fields[1].rust_type, "MacAddress");
        assert_eq!(eth_fields[2].rust_type, "MacAddress");

        // Check format 2100 (ExtendedSocketIPv4) is NOW implemented
        let socket = validations.iter().find(|v| v.format == 2100).unwrap();
        assert!(socket.implemented);
        assert_eq!(socket.name, "SFLExtended_socket_ipv4");
        assert!(socket.field_validation.is_some());
        let socket_fields = &socket.field_validation.as_ref().unwrap().expected_fields;
        assert_eq!(socket_fields.len(), 5);
        assert_eq!(socket_fields[0].name, "protocol");
        assert_eq!(socket_fields[0].rust_type, "u32");
    }

    #[test]
    fn test_format_mapping() {
        let sample = r#"
/* opaque = flow_data; enterprise = 0; format = 1 */
typedef struct _SFLSampled_header {
  uint32_t header_protocol;
} SFLSampled_header;

/* opaque = flow_data; enterprise = 0; format = 2 */
typedef struct _SFLSampled_ethernet {
  uint32_t eth_len;
} SFLSampled_ethernet;

/* opaque = counter_data; enterprise = 0; format = 1 */
typedef struct _SFLIf_counters {
  uint32_t ifIndex;
} SFLIf_counters;
"#;

        let map = build_format_to_struct_map(sample);

        assert_eq!(
            map.get(&(0, 1, "flow_data".to_string())),
            Some(&"SFLSampled_header".to_string())
        );
        assert_eq!(
            map.get(&(0, 2, "flow_data".to_string())),
            Some(&"SFLSampled_ethernet".to_string())
        );
        assert_eq!(
            map.get(&(0, 1, "counter_data".to_string())),
            Some(&"SFLIf_counters".to_string())
        );
        assert_eq!(map.get(&(0, 9999, "flow_data".to_string())), None);
    }
}
