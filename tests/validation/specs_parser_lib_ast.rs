//! AST-based parser for extracting sFlow struct metadata
//!
//! Uses `syn` crate to parse Rust source files and extract:
//! - Struct names and field information
//! - Format numbers from doc comments
//! - Field names and types

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use syn::{Attribute, Fields, Item, Type};

/// Metadata for a discovered sFlow structure
#[derive(Debug, Clone)]
pub struct StructMetadata {
    pub name: String,
    pub enterprise: u32,
    pub format: u32,
    pub data_type: String, // "flow_data" or "counter_data"
    pub fields: Vec<FieldMetadata>,
}

/// Field metadata
#[derive(Debug, Clone, PartialEq)]
pub struct FieldMetadata {
    pub name: String,
    pub type_name: String,
}

/// Type alias for the registry map
pub type StructRegistry = HashMap<(u32, u32, String), StructMetadata>;

/// Extract format number from doc comment
/// Looks for: "/// ... - Format (0,1)"
fn extract_format_from_attrs(attrs: &[Attribute]) -> Option<(u32, u32)> {
    for attr in attrs {
        if attr.path().is_ident("doc") {
            if let Ok(doc_str) = attr.meta.require_name_value() {
                if let syn::Expr::Lit(expr_lit) = &doc_str.value {
                    if let syn::Lit::Str(lit_str) = &expr_lit.lit {
                        let doc = lit_str.value();
                        // Look for "Format (enterprise, format)"
                        if let Some(start) = doc.find("Format (") {
                            let rest = &doc[start + 8..];
                            if let Some(end) = rest.find(')') {
                                let nums = &rest[..end];
                                let parts: Vec<&str> = nums.split(',').map(|s| s.trim()).collect();
                                if parts.len() == 2 {
                                    if let (Ok(ent), Ok(fmt)) = (parts[0].parse(), parts[1].parse())
                                    {
                                        return Some((ent, fmt));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

/// Convert syn::Type to string representation
fn type_to_string(ty: &Type) -> String {
    match ty {
        Type::Path(type_path) => {
            // Get the last segment of the path
            if let Some(segment) = type_path.path.segments.last() {
                let mut result = segment.ident.to_string();

                // Handle generic arguments (e.g., Vec<u8>)
                if let syn::PathArguments::AngleBracketed(args) = &segment.arguments {
                    result.push('<');
                    let arg_strs: Vec<String> = args
                        .args
                        .iter()
                        .map(|arg| match arg {
                            syn::GenericArgument::Type(t) => type_to_string(t),
                            _ => "?".to_string(),
                        })
                        .collect();
                    result.push_str(&arg_strs.join(", "));
                    result.push('>');
                }

                result
            } else {
                "Unknown".to_string()
            }
        }
        Type::Array(type_array) => {
            let elem_type = type_to_string(&type_array.elem);
            if let syn::Expr::Lit(expr_lit) = &type_array.len {
                if let syn::Lit::Int(lit_int) = &expr_lit.lit {
                    return format!("[{}; {}]", elem_type, lit_int);
                }
            }
            format!("[{}; ?]", elem_type)
        }
        _ => "Unknown".to_string(),
    }
}

/// Extract field metadata from struct fields
fn extract_fields(fields: &Fields) -> Vec<FieldMetadata> {
    let mut result = Vec::new();

    match fields {
        Fields::Named(fields_named) => {
            for field in &fields_named.named {
                if let Some(ident) = &field.ident {
                    result.push(FieldMetadata {
                        name: ident.to_string(),
                        type_name: type_to_string(&field.ty),
                    });
                }
            }
        }
        Fields::Unnamed(_) => {
            // Tuple structs - not used in sFlow
        }
        Fields::Unit => {
            // Unit structs - not used in sFlow
        }
    }

    result
}

/// Parse a Rust source file and extract sFlow struct metadata
pub fn parse_source_file(
    file_path: &Path,
    data_type: &str,
) -> Result<Vec<StructMetadata>, Box<dyn std::error::Error>> {
    let content = fs::read_to_string(file_path)?;
    let syntax_tree = syn::parse_file(&content)?;

    let mut structs = Vec::new();

    for item in syntax_tree.items {
        if let Item::Struct(item_struct) = item {
            // Check if this struct has a Format doc comment
            if let Some((enterprise, format)) = extract_format_from_attrs(&item_struct.attrs) {
                let fields = extract_fields(&item_struct.fields);

                structs.push(StructMetadata {
                    name: item_struct.ident.to_string(),
                    enterprise,
                    format,
                    data_type: data_type.to_string(),
                    fields,
                });
            }
        }
    }

    Ok(structs)
}

/// Build a registry of all implemented formats by parsing source files
pub fn build_registry_from_source(
    src_dir: &Path,
) -> Result<StructRegistry, Box<dyn std::error::Error>> {
    let mut registry = HashMap::new();

    // Parse flow records
    let flows_file = src_dir.join("models/record_flows.rs");
    if flows_file.exists() {
        for metadata in parse_source_file(&flows_file, "flow_data")? {
            let key = (
                metadata.enterprise,
                metadata.format,
                metadata.data_type.clone(),
            );
            registry.insert(key, metadata);
        }
    }

    // Parse counter records
    let counters_file = src_dir.join("models/record_counters.rs");
    if counters_file.exists() {
        for metadata in parse_source_file(&counters_file, "counter_data")? {
            let key = (
                metadata.enterprise,
                metadata.format,
                metadata.data_type.clone(),
            );
            registry.insert(key, metadata);
        }
    }

    Ok(registry)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_parse_flows_file() {
        let src_dir = PathBuf::from("src");
        let flows_file = src_dir.join("models/record_flows.rs");

        if !flows_file.exists() {
            println!("Skipping test - file not found: {:?}", flows_file);
            return;
        }

        let structs =
            parse_source_file(&flows_file, "flow_data").expect("Failed to parse flows file");

        assert!(!structs.is_empty(), "Should find at least one struct");

        // Find SampledHeader
        let sampled_header = structs.iter().find(|s| s.name == "SampledHeader");
        assert!(sampled_header.is_some(), "Should find SampledHeader");

        let sh = sampled_header.unwrap();
        assert_eq!(sh.enterprise, 0);
        assert_eq!(sh.format, 1);
        assert_eq!(sh.data_type, "flow_data");
        assert!(
            sh.fields.len() >= 4,
            "SampledHeader should have at least 4 fields"
        );

        // Check field names
        let field_names: Vec<&str> = sh.fields.iter().map(|f| f.name.as_str()).collect();
        assert!(
            field_names.contains(&"protocol"),
            "Should have 'protocol' field"
        );
        assert!(
            field_names.contains(&"frame_length"),
            "Should have 'frame_length' field"
        );
        assert!(
            field_names.contains(&"stripped"),
            "Should have 'stripped' field"
        );
        assert!(
            field_names.contains(&"header"),
            "Should have 'header' field"
        );

        // Check field types
        let protocol_field = sh.fields.iter().find(|f| f.name == "protocol").unwrap();
        assert_eq!(protocol_field.type_name, "HeaderProtocol");

        let frame_length_field = sh.fields.iter().find(|f| f.name == "frame_length").unwrap();
        assert_eq!(frame_length_field.type_name, "u32");

        let header_field = sh.fields.iter().find(|f| f.name == "header").unwrap();
        assert_eq!(header_field.type_name, "Vec<u8>");
    }

    #[test]
    fn test_build_registry() {
        let src_dir = PathBuf::from("src");

        if !src_dir.exists() {
            println!("Skipping test - src directory not found");
            return;
        }

        let registry = build_registry_from_source(&src_dir).expect("Failed to build registry");

        assert!(!registry.is_empty(), "Registry should not be empty");

        // Check for known formats
        assert!(
            registry.contains_key(&(0, 1, "flow_data".to_string())),
            "Should have SampledHeader (0,1)"
        );
        assert!(
            registry.contains_key(&(0, 2, "flow_data".to_string())),
            "Should have SampledEthernet (0,2)"
        );
        assert!(
            registry.contains_key(&(0, 1001, "flow_data".to_string())),
            "Should have ExtendedSwitch (0,1001)"
        );
        assert!(
            registry.contains_key(&(0, 1, "counter_data".to_string())),
            "Should have GenericInterfaceCounters (0,1)"
        );

        println!("\n=== Discovered Formats ===");
        let mut keys: Vec<_> = registry.keys().collect();
        keys.sort_by_key(|(e, f, d)| (*e, *f, d.clone()));

        for (ent, fmt, dtype) in keys {
            let metadata = registry.get(&(*ent, *fmt, dtype.clone())).unwrap();
            println!(
                "({},{:4}) {} [{}] - {} fields",
                ent,
                fmt,
                metadata.name,
                dtype,
                metadata.fields.len()
            );
        }

        println!("\nTotal formats discovered: {}", registry.len());
    }

    #[test]
    fn test_field_types() {
        let src_dir = PathBuf::from("src");
        let flows_file = src_dir.join("models/record_flows.rs");

        if !flows_file.exists() {
            println!("Skipping test - file not found");
            return;
        }

        let structs = parse_source_file(&flows_file, "flow_data").expect("Failed to parse");

        // Test various type representations
        for s in &structs {
            println!("\n{} ({}:{}):", s.name, s.enterprise, s.format);
            for field in &s.fields {
                println!("  {}: {}", field.name, field.type_name);
            }
        }
    }
}
