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
//!     ..Default::default()
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

use std::collections::HashMap;
use std::path::Path;
use types::{CustomTypeDef, Manifest, ToolCladError};

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
    // Must have at least one execution backend.
    if manifest.command.template.is_none()
        && manifest.command.executor.is_none()
        && manifest.http.is_none()
        && manifest.mcp.is_none()
        && manifest.session.is_none()
        && manifest.browser.is_none()
    {
        return Err(ToolCladError::ManifestError(
            "manifest must define at least one execution backend: [command] template/executor, [http], [mcp], [session], or [browser]"
                .to_string(),
        ));
    }

    // Validate argument types and constraints.
    for (name, def) in &manifest.args {
        if !validator::SUPPORTED_TYPES.contains(&def.type_name.as_str()) {
            return Err(ToolCladError::ManifestError(format!(
                "unknown type '{}' for argument '{}'",
                def.type_name, name
            )));
        }
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
    let valid_tiers = ["info", "low", "medium", "high", "critical"];
    if !valid_tiers.contains(&manifest.tool.risk_tier.as_str()) {
        return Err(ToolCladError::ManifestError(format!(
            "invalid risk_tier '{}', must be one of: {}",
            manifest.tool.risk_tier,
            valid_tiers.join(", ")
        )));
    }

    Ok(())
}

/// Load custom type definitions from a toolclad.toml file.
pub fn load_custom_types<P: AsRef<Path>>(
    path: P,
) -> Result<HashMap<String, CustomTypeDef>, ToolCladError> {
    let content = std::fs::read_to_string(path.as_ref())
        .map_err(|e| ToolCladError::ManifestError(format!("failed to read toolclad.toml: {e}")))?;
    let config: toml::Value = toml::from_str(&content).map_err(|e| {
        ToolCladError::ManifestError(format!("TOML parse error in toolclad.toml: {e}"))
    })?;

    let mut types = HashMap::new();
    if let Some(types_table) = config.get("types").and_then(|t| t.as_table()) {
        for (name, def) in types_table {
            let base = def.get("base").and_then(|b| b.as_str()).ok_or_else(|| {
                ToolCladError::ManifestError(format!("custom type '{name}' missing 'base' field"))
            })?;

            let custom = CustomTypeDef {
                base: base.to_string(),
                allowed: def.get("allowed").and_then(|a| a.as_array()).map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                }),
                pattern: def
                    .get("pattern")
                    .and_then(|p| p.as_str())
                    .map(String::from),
                min: def.get("min").and_then(|m| m.as_integer()),
                max: def.get("max").and_then(|m| m.as_integer()),
            };
            types.insert(name.clone(), custom);
        }
    }
    Ok(types)
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
                "status": { "type": "string", "enum": ["success", "error", "timeout", "delegation_preview"] },
                "scan_id": { "type": "string" },
                "tool": { "type": "string" },
                "command": { "type": "string" },
                "duration_ms": { "type": "integer" },
                "timestamp": { "type": "string", "format": "date-time" },
                "output_file": { "type": "string" },
                "output_hash": { "type": "string" },
                "exit_code": { "type": "integer" },
                "stderr": { "type": "string" },
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

[output]
format = "text"

[output.schema]
type = "object"
"#;
        let result = parse_manifest(toml_str);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("at least one execution backend"));
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
    fn test_parse_session_manifest() {
        let toml_str = r#"
[tool]
name = "psql_session"
version = "1.0.0"
binary = "psql"
description = "Interactive PostgreSQL session"
timeout_seconds = 300
risk_tier = "medium"

[command]

[session]
startup_command = "psql -h localhost -U analyst analytics_db"
ready_pattern = "analytics_db=>"
startup_timeout_seconds = 15
idle_timeout_seconds = 600
session_timeout_seconds = 3600
max_interactions = 200

[session.interaction]
input_sanitize = ["injection"]
output_max_bytes = 2097152
output_wait_ms = 3000

[session.commands.select]
pattern = "^SELECT\\b"
description = "Run a SELECT query"
risk_tier = "low"

[session.commands.select.args.query]
position = 1
required = true
type = "string"
description = "SQL SELECT query"

[output]
format = "text"
envelope = true

[output.schema]
type = "object"
"#;
        let m = parse_manifest(toml_str).unwrap();
        assert_eq!(m.tool.name, "psql_session");
        assert!(m.session.is_some());
        let session = m.session.as_ref().unwrap();
        assert_eq!(
            session.startup_command,
            "psql -h localhost -U analyst analytics_db"
        );
        assert_eq!(session.ready_pattern, "analytics_db=>");
        assert_eq!(session.startup_timeout_seconds, 15);
        assert_eq!(session.idle_timeout_seconds, 600);
        assert_eq!(session.session_timeout_seconds, 3600);
        assert_eq!(session.max_interactions, 200);
        let interaction = session.interaction.as_ref().unwrap();
        assert_eq!(interaction.input_sanitize, vec!["injection"]);
        assert_eq!(interaction.output_max_bytes, 2_097_152);
        assert_eq!(interaction.output_wait_ms, 3000);
        assert!(session.commands.contains_key("select"));
        let select_cmd = &session.commands["select"];
        assert_eq!(select_cmd.risk_tier, "low");
        assert!(select_cmd.args.contains_key("query"));
    }

    #[test]
    fn test_parse_browser_manifest() {
        let toml_str = r#"
[tool]
name = "web_scraper"
version = "1.0.0"
binary = "chrome"
description = "Browser-based web scraper"
timeout_seconds = 120
risk_tier = "medium"

[command]

[browser]
engine = "cdp"
headless = true
connect = "live"
extract_mode = "html"
startup_timeout_seconds = 20
session_timeout_seconds = 900
idle_timeout_seconds = 120
max_interactions = 50

[browser.scope]
allowed_domains = ["example.com", "docs.example.com"]
blocked_domains = ["evil.com"]
allow_external = false

[browser.commands.navigate]
description = "Navigate to a URL"
risk_tier = "low"

[browser.commands.navigate.args.url]
position = 1
required = true
type = "url"
description = "URL to navigate to"

[browser.commands.click]
description = "Click an element"
risk_tier = "medium"
human_approval = true

[browser.state]
fields = ["current_url", "page_title"]

[output]
format = "json"
envelope = true

[output.schema]
type = "object"
"#;
        let m = parse_manifest(toml_str).unwrap();
        assert_eq!(m.tool.name, "web_scraper");
        assert!(m.browser.is_some());
        let browser = m.browser.as_ref().unwrap();
        assert_eq!(browser.engine, "cdp");
        assert!(browser.headless);
        assert_eq!(browser.connect, "live");
        assert_eq!(browser.extract_mode, "html");
        assert_eq!(browser.startup_timeout_seconds, 20);
        assert_eq!(browser.session_timeout_seconds, 900);
        assert_eq!(browser.idle_timeout_seconds, 120);
        assert_eq!(browser.max_interactions, 50);
        let scope = browser.scope.as_ref().unwrap();
        assert_eq!(
            scope.allowed_domains,
            vec!["example.com", "docs.example.com"]
        );
        assert_eq!(scope.blocked_domains, vec!["evil.com"]);
        assert!(!scope.allow_external);
        assert!(browser.commands.contains_key("navigate"));
        assert!(browser.commands.contains_key("click"));
        assert!(browser.commands["click"].human_approval);
        let state = browser.state.as_ref().unwrap();
        assert_eq!(state.fields, vec!["current_url", "page_title"]);
    }

    #[test]
    fn test_browser_defaults() {
        let toml_str = r#"
[tool]
name = "browser_defaults"
version = "1.0.0"
binary = "chrome"
description = "Browser with defaults"
timeout_seconds = 60
risk_tier = "low"

[command]

[browser]

[output]
format = "json"
envelope = true

[output.schema]
type = "object"
"#;
        let m = parse_manifest(toml_str).unwrap();
        let browser = m.browser.as_ref().unwrap();
        assert_eq!(browser.engine, "cdp");
        assert!(browser.headless);
        assert_eq!(browser.connect, "launch");
        assert_eq!(browser.extract_mode, "accessibility_tree");
        assert_eq!(browser.startup_timeout_seconds, 10);
        assert_eq!(browser.session_timeout_seconds, 600);
        assert_eq!(browser.idle_timeout_seconds, 120);
        assert_eq!(browser.max_interactions, 200);
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
        assert!(m.command.executor.is_none());
    }
}
