//! # ToolClad
//!
//! Declarative CLI tool interface contracts for agentic runtimes.
//!
//! ToolClad reads `.clad.toml` manifests that define the complete behavioral
//! contract for a CLI tool: typed parameters, validation rules, command
//! construction templates, output parsing, and policy metadata. A single
//! manifest replaces wrapper scripts, MCP tool schemas, and execution wiring.
//!
//! ## Security Model
//!
//! ToolClad inverts the sandbox approach. Instead of letting an LLM generate
//! arbitrary shell commands and intercepting dangerous ones (deny-list),
//! ToolClad constrains the LLM to fill typed parameters that are validated
//! against a manifest (allow-list). The dangerous action cannot be expressed
//! because the interface doesn't permit it.
//!
//! All string-based types reject shell metacharacters (`;|&$\`(){}[]<>!`)
//! by default.
//!
//! ## Core Types
//!
//! | Type | Validates |
//! |------|-----------|
//! | `string` | Non-empty, injection-safe, optional regex pattern |
//! | `integer` | Numeric with optional min/max and clamping |
//! | `port` | 1-65535 |
//! | `boolean` | Exactly `"true"` or `"false"` |
//! | `enum` | Value in declared `allowed` list |
//! | `scope_target` | Injection-safe, no wildcards, valid IP/CIDR/hostname |
//! | `url` | Valid URL with optional scheme restriction |
//! | `path` | No traversal (`../`) |
//! | `ip_address` | Valid IPv4 or IPv6 |
//! | `cidr` | Valid CIDR notation |
//!
//! ## Loading a Manifest
//!
//! ```no_run
//! let manifest = toolclad::load_manifest("tools/whois_lookup.clad.toml").unwrap();
//! println!("Tool: {} ({})", manifest.tool.name, manifest.tool.binary);
//! ```
//!
//! ## Validating Arguments
//!
//! ```
//! use toolclad::types::ArgDef;
//!
//! let def = ArgDef {
//!     type_name: "enum".to_string(),
//!     allowed: Some(vec!["ping".into(), "service".into()]),
//!     required: true,
//!     position: 1,
//!     default: None,
//!     pattern: None,
//!     sanitize: None,
//!     description: String::new(),
//!     min: None,
//!     max: None,
//!     clamp: false,
//! };
//!
//! assert!(toolclad::validator::validate_arg("scan_type", &def, "ping").is_ok());
//! assert!(toolclad::validator::validate_arg("scan_type", &def, "exploit").is_err());
//! ```
//!
//! ## Generating MCP Schema
//!
//! ```no_run
//! let manifest = toolclad::load_manifest("tools/nmap_scan.clad.toml").unwrap();
//! let schema = toolclad::generate_mcp_schema(&manifest);
//! println!("{}", serde_json::to_string_pretty(&schema).unwrap());
//! ```
//!
//! ## Executing a Tool
//!
//! ```no_run
//! use std::collections::HashMap;
//!
//! let manifest = toolclad::load_manifest("tools/whois_lookup.clad.toml").unwrap();
//! let mut args = HashMap::new();
//! args.insert("target".to_string(), "example.com".to_string());
//! let envelope = toolclad::executor::execute(&manifest, &args).unwrap();
//! println!("{}", serde_json::to_string_pretty(&envelope).unwrap());
//! ```
//!
//! ## Manifest Format
//!
//! See the [ToolClad Design Spec](https://github.com/ThirdKeyAI/ToolClad/blob/main/TOOLCLAD_DESIGN_SPEC.md)
//! for the full `.clad.toml` format specification.

pub mod executor;
pub mod types;
pub mod validator;

use std::path::Path;
use types::{Manifest, ToolCladError};

/// Load and parse a `.clad.toml` manifest from the given path.
pub fn load_manifest<P: AsRef<Path>>(path: P) -> Result<Manifest, ToolCladError> {
    let path = path.as_ref();
    let content = std::fs::read_to_string(path).map_err(|e| {
        ToolCladError::ManifestError(format!("failed to read '{}': {e}", path.display()))
    })?;
    parse_manifest(&content)
}

/// Parse a manifest from a TOML string.
pub fn parse_manifest(toml_str: &str) -> Result<Manifest, ToolCladError> {
    let manifest: Manifest = toml::from_str(toml_str)
        .map_err(|e| ToolCladError::ManifestError(format!("TOML parse error: {e}")))?;
    validate_manifest(&manifest)?;
    Ok(manifest)
}

/// Validate internal consistency of a parsed manifest.
fn validate_manifest(manifest: &Manifest) -> Result<(), ToolCladError> {
    // Must have either a template, an executor, an HTTP backend, or an MCP proxy.
    if manifest.command.template.is_none()
        && manifest.command.executor.is_none()
        && manifest.http.is_none()
        && manifest.mcp.is_none()
    {
        return Err(ToolCladError::ManifestError(
            "[command] must have either 'template' or 'executor', or an [http] or [mcp] backend"
                .to_string(),
        ));
    }

    // Validate that enum args have an allowed list.
    for (name, def) in &manifest.args {
        if def.type_name == "enum" && def.allowed.is_none() {
            return Err(ToolCladError::ManifestError(format!(
                "argument '{name}' is type 'enum' but has no 'allowed' list"
            )));
        }
    }

    // Validate that mapping keys reference existing args.
    if let Some(ref mappings) = manifest.command.mappings {
        for arg_name in mappings.keys() {
            if !manifest.args.contains_key(arg_name) {
                return Err(ToolCladError::ManifestError(format!(
                    "mapping references unknown argument '{arg_name}'"
                )));
            }
        }
    }

    // Validate risk_tier values.
    let valid_tiers = ["low", "medium", "high", "critical"];
    if !valid_tiers.contains(&manifest.tool.risk_tier.as_str()) {
        return Err(ToolCladError::ManifestError(format!(
            "invalid risk_tier '{}', must be one of: {}",
            manifest.tool.risk_tier,
            valid_tiers.join(", ")
        )));
    }

    Ok(())
}

/// Generate an MCP-compatible JSON schema from a manifest.
pub fn generate_mcp_schema(manifest: &Manifest) -> serde_json::Value {
    let mut properties = serde_json::Map::new();
    let mut required = Vec::new();

    // Sort args by position for consistent output.
    let mut args: Vec<_> = manifest.args.iter().collect();
    args.sort_by_key(|(_, def)| def.position);

    for (name, def) in &args {
        let mut prop = serde_json::Map::new();

        // Map ToolClad types to JSON Schema types.
        let json_type = match def.type_name.as_str() {
            "integer" | "port" => "integer",
            "boolean" => "boolean",
            _ => "string",
        };
        prop.insert("type".to_string(), serde_json::json!(json_type));

        if !def.description.is_empty() {
            prop.insert(
                "description".to_string(),
                serde_json::json!(def.description),
            );
        }

        if let Some(ref allowed) = def.allowed {
            prop.insert("enum".to_string(), serde_json::json!(allowed));
        }

        if let Some(ref default_val) = def.default {
            let dv = match default_val {
                toml::Value::String(s) => serde_json::json!(s),
                toml::Value::Integer(n) => serde_json::json!(n),
                toml::Value::Float(f) => serde_json::json!(f),
                toml::Value::Boolean(b) => serde_json::json!(b),
                _ => serde_json::json!(default_val.to_string()),
            };
            prop.insert("default".to_string(), dv);
        }

        if let Some(ref pattern) = def.pattern {
            prop.insert("pattern".to_string(), serde_json::json!(pattern));
        }

        if let Some(min) = def.min {
            prop.insert("minimum".to_string(), serde_json::json!(min));
        }
        if let Some(max) = def.max {
            prop.insert("maximum".to_string(), serde_json::json!(max));
        }

        properties.insert((*name).clone(), serde_json::Value::Object(prop));

        if def.required {
            required.push(serde_json::json!(name));
        }
    }

    let input_schema = serde_json::json!({
        "type": "object",
        "properties": properties,
        "required": required,
    });

    // Build the envelope output schema wrapping the declared results schema.
    let output_schema = if manifest.output.envelope {
        serde_json::json!({
            "type": "object",
            "properties": {
                "status": { "type": "string", "enum": ["success", "error"] },
                "scan_id": { "type": "string" },
                "tool": { "type": "string" },
                "command": { "type": "string" },
                "duration_ms": { "type": "integer" },
                "timestamp": { "type": "string", "format": "date-time" },
                "output_file": { "type": "string" },
                "output_hash": { "type": "string" },
                "results": manifest.output.schema,
            }
        })
    } else {
        manifest.output.schema.clone()
    };

    serde_json::json!({
        "name": manifest.tool.name,
        "description": manifest.tool.description,
        "inputSchema": input_schema,
        "outputSchema": output_schema,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const WHOIS_MANIFEST: &str = r#"
[tool]
name = "whois_lookup"
version = "1.0.0"
binary = "whois"
description = "WHOIS domain/IP registration lookup"
timeout_seconds = 30
risk_tier = "low"

[tool.cedar]
resource = "PenTest::ScanTarget"
action = "execute_tool"

[args.target]
position = 1
required = true
type = "scope_target"
description = "Domain name or IP address to query"

[command]
template = "whois {target}"

[output]
format = "text"
envelope = true

[output.schema]
type = "object"

[output.schema.properties.raw_output]
type = "string"
description = "Raw WHOIS registration data"
"#;

    #[test]
    fn test_parse_whois_manifest() {
        let m = parse_manifest(WHOIS_MANIFEST).unwrap();
        assert_eq!(m.tool.name, "whois_lookup");
        assert_eq!(m.tool.binary, "whois");
        assert_eq!(m.tool.timeout_seconds, 30);
        assert!(m.args.contains_key("target"));
        assert!(m.args["target"].required);
        assert_eq!(m.args["target"].type_name, "scope_target");
    }

    #[test]
    fn test_parse_nmap_manifest() {
        let toml_str = r#"
[tool]
name = "nmap_scan"
version = "1.0.0"
binary = "nmap"
description = "Network port scanning"
timeout_seconds = 600
risk_tier = "low"

[args.target]
position = 1
required = true
type = "scope_target"
description = "Target"

[args.scan_type]
position = 2
required = true
type = "enum"
allowed = ["ping", "service"]
description = "Scan type"

[args.extra_flags]
position = 3
required = false
type = "string"
sanitize = ["injection"]
default = ""
description = "Extra flags"

[command]
template = "nmap {_scan_type_flags} {extra_flags} {target}"

[command.mappings.scan_type]
ping = "-sn -PE"
service = "-sT -sV"

[output]
format = "text"
envelope = true

[output.schema]
type = "object"
"#;
        let m = parse_manifest(toml_str).unwrap();
        assert_eq!(m.tool.name, "nmap_scan");
        assert!(m.command.mappings.is_some());
        let mappings = m.command.mappings.as_ref().unwrap();
        assert_eq!(mappings["scan_type"]["ping"], "-sn -PE");
    }

    #[test]
    fn test_manifest_missing_command() {
        let toml_str = r#"
[tool]
name = "bad"
version = "1.0.0"
binary = "bad"
description = "bad"
risk_tier = "low"

[command]

[output]
format = "text"

[output.schema]
type = "object"
"#;
        let result = parse_manifest(toml_str);
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_mcp_schema() {
        let m = parse_manifest(WHOIS_MANIFEST).unwrap();
        let schema = generate_mcp_schema(&m);
        assert_eq!(schema["name"], "whois_lookup");
        assert!(schema["inputSchema"]["properties"]["target"].is_object());
        assert!(schema["outputSchema"]["properties"]["results"].is_object());
    }

    #[test]
    fn test_parse_http_manifest() {
        let toml_str = r#"
[tool]
name = "api_check"
version = "1.0.0"
binary = "curl"
description = "HTTP API health check"
timeout_seconds = 30
risk_tier = "low"

[args.endpoint]
position = 1
required = true
type = "string"
description = "API endpoint path"

[command]
template = "curl {endpoint}"

[http]
method = "GET"
url = "https://api.example.com/{endpoint}"
headers = { "Authorization" = "Bearer {_secret:api_key}", "Accept" = "application/json" }
success_status = [200, 201]
error_status = [500, 502, 503]

[output]
format = "json"
envelope = true

[output.schema]
type = "object"
"#;
        let m = parse_manifest(toml_str).unwrap();
        assert!(m.http.is_some());
        let http = m.http.as_ref().unwrap();
        assert_eq!(http.method, "GET");
        assert_eq!(http.url, "https://api.example.com/{endpoint}");
        assert_eq!(http.headers.len(), 2);
        assert!(http.headers.contains_key("Authorization"));
        assert_eq!(http.success_status, vec![200, 201]);
        assert_eq!(http.error_status, vec![500, 502, 503]);
        assert!(http.body_template.is_none());
    }

    #[test]
    fn test_parse_http_manifest_with_body() {
        let toml_str = r#"
[tool]
name = "webhook_post"
version = "1.0.0"
binary = "curl"
description = "Post to webhook"
timeout_seconds = 15
risk_tier = "medium"

[args.message]
position = 1
required = true
type = "string"
description = "Message to send"

[command]
template = "curl -X POST"

[http]
method = "POST"
url = "https://hooks.example.com/notify"
headers = { "Content-Type" = "application/json" }
body_template = '{"text": "{message}"}'
success_status = [200]

[output]
format = "json"
envelope = true

[output.schema]
type = "object"
"#;
        let m = parse_manifest(toml_str).unwrap();
        let http = m.http.as_ref().unwrap();
        assert_eq!(http.method, "POST");
        assert!(http.body_template.is_some());
        assert!(http.body_template.as_ref().unwrap().contains("{message}"));
    }

    #[test]
    fn test_parse_mcp_proxy_manifest() {
        let toml_str = r#"
[tool]
name = "code_review"
version = "1.0.0"
binary = "mcp-proxy"
description = "Delegate code review to MCP server"
timeout_seconds = 120
risk_tier = "low"

[args.repo]
position = 1
required = true
type = "string"
description = "Repository name"

[args.pr_number]
position = 2
required = true
type = "integer"
description = "Pull request number"
min = 1

[command]
template = "mcp-proxy"

[mcp]
server = "code-review-server"
tool = "analyze_pr"
field_map = { "repo" = "repository", "pr_number" = "pull_request_id" }

[output]
format = "json"
envelope = true

[output.schema]
type = "object"
"#;
        let m = parse_manifest(toml_str).unwrap();
        assert!(m.mcp.is_some());
        let mcp = m.mcp.as_ref().unwrap();
        assert_eq!(mcp.server, "code-review-server");
        assert_eq!(mcp.tool, "analyze_pr");
        assert_eq!(mcp.field_map.len(), 2);
        assert_eq!(mcp.field_map["repo"], "repository");
        assert_eq!(mcp.field_map["pr_number"], "pull_request_id");
    }

    #[test]
    fn test_parse_mcp_proxy_no_field_map() {
        let toml_str = r#"
[tool]
name = "simple_proxy"
version = "1.0.0"
binary = "mcp-proxy"
description = "Simple MCP proxy"
timeout_seconds = 60
risk_tier = "low"

[args.query]
position = 1
required = true
type = "string"
description = "Search query"

[command]
template = "mcp-proxy"

[mcp]
server = "search-server"
tool = "search"

[output]
format = "json"
envelope = true

[output.schema]
type = "object"
"#;
        let m = parse_manifest(toml_str).unwrap();
        let mcp = m.mcp.as_ref().unwrap();
        assert_eq!(mcp.server, "search-server");
        assert_eq!(mcp.tool, "search");
        assert!(mcp.field_map.is_empty());
    }

    #[test]
    fn test_http_backend_without_command_template() {
        let toml_str = r#"
[tool]
name = "http_only"
version = "1.0.0"
binary = "none"
description = "HTTP-only tool"
timeout_seconds = 30
risk_tier = "low"

[command]

[http]
method = "GET"
url = "https://example.com/health"

[output]
format = "json"
envelope = true

[output.schema]
type = "object"
"#;
        let m = parse_manifest(toml_str).unwrap();
        assert!(m.http.is_some());
        assert!(m.command.template.is_none());
    }
}
