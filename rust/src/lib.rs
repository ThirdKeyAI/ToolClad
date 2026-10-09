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
//! by default. String-derived values (`string`, `path`, `credential_file`,
//! `regex_match`, `url`, `scope_target`, `duration`, `msf_options`) are also
//! refused if they contain NUL or control characters, quotes or backslashes,
//! whitespace, or start with `-`/`+`, so a value can never be re-split into
//! extra arguments or parsed by the target binary as an option. An arg opts
//! out per rule with `allow_leading_dash = true` or (declared `exec` only)
//! `allow_whitespace = true`.
//!
//! Commands are built from an argv array. A legacy `[command] template` is
//! tokenized once at load, on manifest text only; substituted values are
//! never re-split and `end_of_options = "--"` can fence user values off from
//! option parsing entirely.
//!
//! A manifest key the runtime does not know is a load error
//! (`unknown key 'tool.tiemout_seconds' in manifest`), never a silently
//! ignored control. The only escape hatch is
//! `toolclad validate --allow-unknown-keys`, which [`load_manifest_with`]
//! exposes through [`LoadOptions`]; [`load_manifest`] and [`parse_manifest`]
//! are always strict. At call time an argument name the manifest does not
//! declare is refused the same way.
//!
//! ## Core Types
//!
//! | Type | Validates |
//! |------|-----------|
//! | `string` | Non-empty, injection-safe, optional regex pattern |
//! | `integer` | Numeric with optional min/max and clamping |
//! | `number` | Float with optional `min_float`/`max_float` and clamping |
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

use std::collections::{HashMap, HashSet};
use std::path::Path;
use types::{CustomTypeDef, Manifest, ToolCladError, MODES};

/// Loader options. The default is strict; see [`load_manifest_with`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LoadOptions {
    /// Downgrade unknown manifest keys from a load error to a warning on
    /// stderr (`warning: unknown key '<section>.<key>' in manifest`) and drop
    /// them. An authoring aid for `toolclad validate --allow-unknown-keys`;
    /// the plain loaders never set it.
    pub allow_unknown_keys: bool,
}

/// Load and parse a `.clad.toml` manifest from the given path.
///
/// Strict: an unknown key anywhere in the manifest is a load error.
pub fn load_manifest<P: AsRef<Path>>(path: P) -> Result<Manifest, ToolCladError> {
    load_manifest_with(path, LoadOptions::default())
}

/// [`load_manifest`] with explicit [`LoadOptions`].
pub fn load_manifest_with<P: AsRef<Path>>(
    path: P,
    options: LoadOptions,
) -> Result<Manifest, ToolCladError> {
    let path = path.as_ref();
    let content = std::fs::read_to_string(path).map_err(|e| {
        ToolCladError::ManifestError(format!("failed to read '{}': {e}", path.display()))
    })?;
    parse_manifest_with(&content, options)
}

/// Parse a manifest from a TOML string.
///
/// Strict: an unknown key anywhere in the manifest is a load error.
pub fn parse_manifest(toml_str: &str) -> Result<Manifest, ToolCladError> {
    parse_manifest_with(toml_str, LoadOptions::default())
}

/// [`parse_manifest`] with explicit [`LoadOptions`].
pub fn parse_manifest_with(
    toml_str: &str,
    options: LoadOptions,
) -> Result<Manifest, ToolCladError> {
    let parse_err =
        |e: toml::de::Error| ToolCladError::ManifestError(format!("TOML parse error: {e}"));

    // Walk the raw document against the key allowlist first so every unknown
    // key is reported by its full path. `deny_unknown_fields` on the types is
    // the second layer and catches anything the table and the structs disagree
    // on.
    let mut doc: toml::Table = toml::from_str(toml_str).map_err(parse_err)?;
    let unknown = prune_unknown_keys(&mut doc);

    let mut manifest: Manifest = if unknown.is_empty() {
        // Deserialize from the text so a structural error keeps its position.
        toml::from_str(toml_str).map_err(parse_err)?
    } else if options.allow_unknown_keys {
        for key in &unknown {
            eprintln!("warning: unknown key '{key}' in manifest");
        }
        toml::Value::Table(doc).try_into().map_err(parse_err)?
    } else {
        return Err(ToolCladError::ManifestError(unknown_keys_message(&unknown)));
    };

    compile_command(&mut manifest)?;
    validate_manifest(&manifest)?;
    Ok(manifest)
}

/// Keys every argument table accepts (`[args.<n>]`, `[session.commands.<n>.args.<n>]`,
/// `[browser.commands.<n>.args.<n>]`).
const ARG_KEYS: &[&str] = &[
    "position",
    "required",
    "type",
    "description",
    "default",
    "allowed",
    "pattern",
    "sanitize",
    "min",
    "max",
    "min_float",
    "max_float",
    "clamp",
    "schemes",
    "scope_check",
    "block_internal",
    "allow_leading_dash",
    "allow_whitespace",
];

/// The manifest key allowlist, one entry per section: `(section, keys)`.
///
/// This is the Rust copy of the cross-runtime allowlist and is meant to be
/// diffed against it line by line. A `*` segment stands for a user-chosen
/// name (`[args.<n>]`, `[command.conditionals.<n>]`, ...). A table that is not
/// listed here is an open map whose keys are user data (`command.defaults`,
/// `command.mappings`, `output.schema`, `http.headers`, `mcp.field_map`) and
/// is not walked.
const KNOWN_KEYS: &[(&str, &[&str])] = &[
    (
        "",
        &[
            "tool", "args", "command", "output", "http", "mcp", "session", "browser",
        ],
    ),
    (
        "tool",
        &[
            "name",
            "version",
            "binary",
            "description",
            "timeout_seconds",
            "risk_tier",
            "human_approval",
            "dispatch",
            "mode",
            "network_egress",
            "allow_interpreter",
            "cedar",
            "evidence",
            "limits",
        ],
    ),
    ("tool.cedar", &["resource", "action"]),
    (
        "tool.evidence",
        &["output_dir", "capture", "hash", "screenshots"],
    ),
    (
        "tool.limits",
        &[
            "nproc",
            "nofile",
            "fsize_bytes",
            "address_space_bytes",
            "cpu_seconds",
        ],
    ),
    ("args.*", ARG_KEYS),
    (
        "command",
        &[
            "template",
            "exec",
            "executor",
            "defaults",
            "mappings",
            "conditionals",
            "end_of_options",
        ],
    ),
    ("command.conditionals.*", &["when", "template"]),
    (
        "output",
        &["format", "parser", "envelope", "schema", "max_bytes"],
    ),
    (
        "http",
        &[
            "method",
            "url",
            "headers",
            "body_template",
            "success_status",
            "error_status",
        ],
    ),
    ("mcp", &["server", "tool", "field_map"]),
    (
        "session",
        &[
            "startup_command",
            "ready_pattern",
            "startup_timeout_seconds",
            "idle_timeout_seconds",
            "session_timeout_seconds",
            "max_interactions",
            "interaction",
            "commands",
            "child_detection",
        ],
    ),
    (
        "session.interaction",
        &["input_sanitize", "output_max_bytes", "output_wait_ms"],
    ),
    (
        "session.commands.*",
        &[
            "pattern",
            "description",
            "risk_tier",
            "human_approval",
            "extract_target",
            "args",
        ],
    ),
    ("session.commands.*.args.*", ARG_KEYS),
    ("session.child_detection", &["pattern", "type", "manifest"]),
    (
        "browser",
        &[
            "engine",
            "headless",
            "connect",
            "extract_mode",
            "startup_timeout_seconds",
            "session_timeout_seconds",
            "idle_timeout_seconds",
            "max_interactions",
            "scope",
            "commands",
            "state",
            "defaults",
        ],
    ),
    ("browser.defaults", &["extract_mode"]),
    (
        "browser.scope",
        &["allowed_domains", "blocked_domains", "allow_external"],
    ),
    (
        "browser.commands.*",
        &["description", "risk_tier", "human_approval", "args"],
    ),
    ("browser.commands.*.args.*", ARG_KEYS),
    ("browser.state", &["fields"]),
];

fn known_keys(section: &str) -> Option<&'static [&'static str]> {
    KNOWN_KEYS
        .iter()
        .find(|(name, _)| *name == section)
        .map(|(_, keys)| *keys)
}

fn join_path(base: &str, key: &str) -> String {
    if base.is_empty() {
        key.to_string()
    } else {
        format!("{base}.{key}")
    }
}

/// Remove every key [`KNOWN_KEYS`] does not list from the document and return
/// the concrete dotted path of each removed key, sorted.
fn prune_unknown_keys(doc: &mut toml::Table) -> Vec<String> {
    let mut unknown = Vec::new();
    prune_section(doc, "", "", &mut unknown);
    unknown.sort();
    unknown
}

/// `section` is the allowlist pattern (`session.commands.*`), `path` the
/// concrete location in this document (`session.commands.select`).
fn prune_section(table: &mut toml::Table, section: &str, path: &str, unknown: &mut Vec<String>) {
    let Some(allowed) = known_keys(section) else {
        return;
    };
    let keys: Vec<String> = table.keys().cloned().collect();
    for key in keys {
        let key_path = join_path(path, &key);
        if !allowed.contains(&key.as_str()) {
            table.remove(&key);
            unknown.push(key_path);
            continue;
        }
        let Some(toml::Value::Table(child)) = table.get_mut(&key) else {
            continue;
        };
        let child_section = join_path(section, &key);
        if known_keys(&child_section).is_some() {
            prune_section(child, &child_section, &key_path, unknown);
            continue;
        }
        let named_section = join_path(&child_section, "*");
        if known_keys(&named_section).is_some() {
            for (name, entry) in child.iter_mut() {
                if let toml::Value::Table(sub) = entry {
                    prune_section(sub, &named_section, &join_path(&key_path, name), unknown);
                }
            }
        }
    }
}

fn unknown_keys_message(keys: &[String]) -> String {
    keys.iter()
        .map(|k| format!("unknown key '{k}' in manifest"))
        .collect::<Vec<_>>()
        .join("; ")
}

/// Compile the `[command]` section into its canonical exec form.
///
/// A `template` with no `exec` is tokenized here, once, on trusted manifest
/// text; every conditional template is tokenized the same way. The result is
/// what the executor substitutes into — values are never re-split.
fn compile_command(manifest: &mut Manifest) -> Result<(), ToolCladError> {
    let cmd = &mut manifest.command;
    cmd.exec_was_declared = cmd.exec.is_some();

    if cmd.exec.is_none() {
        if let Some(ref template) = cmd.template {
            cmd.exec = Some(executor::tokenize_template(template)?);
            eprintln!(
                "warning: [command] template is deprecated and will be removed in the next minor release; use exec = [...]"
            );
        }
    }

    if let Some(ref mut conditionals) = cmd.conditionals {
        for (name, cond) in conditionals.iter_mut() {
            cond.tokens = executor::tokenize_template(&cond.template).map_err(|e| {
                let msg = match e {
                    ToolCladError::ManifestError(m) => m,
                    other => other.to_string(),
                };
                ToolCladError::ManifestError(format!("conditional '{name}': {msg}"))
            })?;
        }
    }

    if let Some(ref eoo) = cmd.end_of_options {
        if eoo != "--" {
            return Err(ToolCladError::ManifestError(format!(
                "end_of_options must be exactly \"--\" (got '{eoo}')"
            )));
        }
    }

    Ok(())
}

/// Load-time placeholder check: every `{name}` in the compiled exec form and
/// in every conditional must name a declared arg, a `[command.defaults]` key,
/// `_<arg>_flags` for a mapped arg, `_<cond>` for a declared conditional, or
/// an executor-injected variable. A trusted multi-token variable must stand
/// alone as a whole token.
fn check_placeholders(manifest: &Manifest) -> Result<(), ToolCladError> {
    let cmd = &manifest.command;

    let mut single: HashSet<String> = manifest.args.keys().cloned().collect();
    if let Some(ref defaults) = cmd.defaults {
        single.extend(defaults.keys().cloned());
    }
    single.extend(executor::INJECTED_VARS.iter().map(|s| s.to_string()));

    let mut trusted: HashSet<String> = HashSet::new();
    if let Some(ref mappings) = cmd.mappings {
        trusted.extend(mappings.keys().map(|k| format!("_{k}_flags")));
    }
    if let Some(ref conditionals) = cmd.conditionals {
        trusted.extend(conditionals.keys().map(|k| format!("_{k}")));
    }

    let check = |tokens: &[String], context: &str| -> Result<(), ToolCladError> {
        for token in tokens {
            for name in executor::placeholder_names(token) {
                if trusted.contains(&name) {
                    if token != &format!("{{{name}}}") {
                        return Err(ToolCladError::ManifestError(format!(
                            "placeholder '{{{name}}}' expands to multiple tokens and must be a whole token in {context}"
                        )));
                    }
                } else if !single.contains(&name) {
                    return Err(ToolCladError::ManifestError(format!(
                        "unresolved placeholder '{{{name}}}' in {context}"
                    )));
                }
            }
        }
        Ok(())
    };

    if let Some(ref exec) = cmd.exec {
        check(exec, "command")?;
    }
    if let Some(ref conditionals) = cmd.conditionals {
        for (name, cond) in conditionals {
            check(&cond.tokens, &format!("conditional '{name}'"))?;
        }
    }
    if let Some(ref mappings) = cmd.mappings {
        for (arg, table) in mappings {
            for value in table.values() {
                executor::tokenize_template(value).map_err(|e| {
                    let msg = match e {
                        ToolCladError::ManifestError(m) => m,
                        other => other.to_string(),
                    };
                    ToolCladError::ManifestError(format!("mapping for '{arg}': {msg}"))
                })?;
            }
        }
    }
    Ok(())
}

/// Binaries that connect to a network destination derived from their arguments
/// — the ones for which an unconstrained `scope_target`/`url` is an SSRF surface.
const EGRESS_BINARIES: &[&str] = &[
    "curl", "wget", "nmap", "nc", "ncat", "netcat", "masscan", "telnet", "ssh", "ping", "fping",
    "httpie", "http", "wfuzz", "ffuf", "hydra", "nikto",
];

fn command_basename(s: &str) -> String {
    s.rsplit(['/', '\\'])
        .next()
        .unwrap_or(s)
        .to_ascii_lowercase()
}

/// True if the manifest's command dispatches one of the known egress binaries
/// (checked across `tool.binary`, `command.exec[0]`, and `command.template`).
fn command_invokes_egress_binary(m: &Manifest) -> bool {
    let mut names: Vec<String> = Vec::new();
    if !m.tool.binary.is_empty() {
        names.push(command_basename(&m.tool.binary));
    }
    if let Some(first) = m.command.exec.as_ref().and_then(|e| e.first()) {
        names.push(command_basename(first));
    }
    if let Some(first) = m
        .command
        .template
        .as_ref()
        .and_then(|t| t.split_whitespace().next())
    {
        names.push(command_basename(first));
    }
    names.iter().any(|n| EGRESS_BINARIES.contains(&n.as_str()))
}

/// Validate internal consistency of a parsed manifest.
fn validate_manifest(manifest: &Manifest) -> Result<(), ToolCladError> {
    // Validate dispatch mode.
    let valid_dispatch = ["exec", "callback"];
    if !valid_dispatch.contains(&manifest.tool.dispatch.as_str()) {
        return Err(ToolCladError::ManifestError(format!(
            "invalid dispatch '{}', must be one of: {}",
            manifest.tool.dispatch,
            valid_dispatch.join(", ")
        )));
    }

    // Validate the advisory mode when declared.
    if let Some(ref mode) = manifest.tool.mode {
        if !MODES.contains(&mode.as_str()) {
            return Err(ToolCladError::ManifestError(format!(
                "invalid mode '{mode}', must be one of: {}",
                MODES.join(", ")
            )));
        }
    }

    let is_callback = manifest.tool.dispatch == "callback";

    // exec dispatch requires a backend and an [output] block.
    if !is_callback {
        if manifest.command.template.is_none()
            && manifest.command.exec.is_none()
            && manifest.command.executor.is_none()
            && manifest.http.is_none()
            && manifest.mcp.is_none()
            && manifest.session.is_none()
            && manifest.browser.is_none()
        {
            return Err(ToolCladError::ManifestError(
                "manifest must define at least one execution backend: [command] template/executor, [http], [mcp], [session], or [browser] (or set tool.dispatch = \"callback\" for validator-only manifests)"
                    .to_string(),
            ));
        }
        if manifest.output.is_none() {
            return Err(ToolCladError::ManifestError(
                "manifest is missing [output] block (or set tool.dispatch = \"callback\" for validator-only manifests)"
                    .to_string(),
            ));
        }
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

    // Egress safety: a tool that connects to a network target must default-deny
    // internal/SSRF addresses. If the command invokes a known network-egress
    // binary and a scope_target/url arg does not set block_internal, refuse the
    // manifest. (HTTP/MCP/browser backends are separate egress surfaces.)
    if command_invokes_egress_binary(manifest) {
        for (name, def) in &manifest.args {
            if matches!(def.type_name.as_str(), "scope_target" | "url") && !def.block_internal {
                return Err(ToolCladError::ManifestError(format!(
                    "argument '{name}' is a network target for an egress binary but block_internal is not set; \
                     set block_internal = true to default-deny internal/SSRF targets"
                )));
            }
        }
    }

    // Validate that mapping keys reference existing args, and that a mapping
    // over an enum covers every allowed value: a missing case must be a load
    // failure, not a silently flag-less invocation. Map a value to "" to say
    // "no flags".
    if let Some(ref mappings) = manifest.command.mappings {
        for (arg_name, table) in mappings {
            let Some(def) = manifest.args.get(arg_name) else {
                return Err(ToolCladError::ManifestError(format!(
                    "mapping references unknown argument '{arg_name}'"
                )));
            };
            if def.type_name == "enum" {
                if let Some(ref allowed) = def.allowed {
                    let mut missing: Vec<&str> = allowed
                        .iter()
                        .filter(|v| !table.contains_key(*v))
                        .map(String::as_str)
                        .collect();
                    missing.sort_unstable();
                    if !missing.is_empty() {
                        return Err(ToolCladError::ManifestError(format!(
                            "mapping for enum argument '{arg_name}' does not cover allowed values: [{}] (map a value to \"\" for no flags)",
                            missing.join(", ")
                        )));
                    }
                }
            }
        }
    }

    // Every placeholder in the compiled command must resolve to something the
    // manifest declares; a typo must not survive to build time.
    check_placeholders(manifest)?;

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
                min_float: def.get("min_float").and_then(|m| m.as_float()),
                max_float: def.get("max_float").and_then(|m| m.as_float()),
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

        // Map ToolClad types to JSON Schema types with constraints.
        match def.type_name.as_str() {
            "integer" => {
                prop.insert("type".to_string(), serde_json::json!("integer"));
            }
            "number" => {
                prop.insert("type".to_string(), serde_json::json!("number"));
                if let Some(lo) = def.min_float {
                    prop.insert("minimum".to_string(), serde_json::json!(lo));
                }
                if let Some(hi) = def.max_float {
                    prop.insert("maximum".to_string(), serde_json::json!(hi));
                }
            }
            "port" => {
                prop.insert("type".to_string(), serde_json::json!("integer"));
                if def.min.is_none() {
                    prop.insert("minimum".to_string(), serde_json::json!(1));
                }
                if def.max.is_none() {
                    prop.insert("maximum".to_string(), serde_json::json!(65535));
                }
            }
            "boolean" => {
                prop.insert("type".to_string(), serde_json::json!("boolean"));
            }
            "ip_address" => {
                prop.insert("type".to_string(), serde_json::json!("string"));
                prop.insert("format".to_string(), serde_json::json!("ipv4"));
            }
            "cidr" => {
                prop.insert("type".to_string(), serde_json::json!("string"));
                if def.pattern.is_none() {
                    prop.insert(
                        "pattern".to_string(),
                        serde_json::json!(r"^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$"),
                    );
                }
            }
            "url" => {
                prop.insert("type".to_string(), serde_json::json!("string"));
                prop.insert("format".to_string(), serde_json::json!("uri"));
            }
            "duration" => {
                prop.insert("type".to_string(), serde_json::json!("string"));
                if def.pattern.is_none() {
                    prop.insert(
                        "pattern".to_string(),
                        serde_json::json!(r"^(\d+|(?:\d+h)?(?:\d+m)?(?:\d+s)?(?:\d+ms)?)$"),
                    );
                }
            }
            _ => {
                prop.insert("type".to_string(), serde_json::json!("string"));
            }
        };

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
    // For callback-only manifests with no [output] block, omit the output schema.
    let output_schema = match manifest.output.as_ref() {
        Some(out) if out.envelope => serde_json::json!({
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
                "results": out.schema,
            }
        }),
        Some(out) => out.schema.clone(),
        None => serde_json::Value::Null,
    };

    let mut envelope = serde_json::Map::new();
    envelope.insert("name".to_string(), serde_json::json!(manifest.tool.name));
    envelope.insert(
        "description".to_string(),
        serde_json::json!(manifest.tool.description),
    );
    envelope.insert("inputSchema".to_string(), input_schema);
    if !output_schema.is_null() {
        envelope.insert("outputSchema".to_string(), output_schema);
    }
    serde_json::Value::Object(envelope)
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
block_internal = true
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
    fn test_egress_binary_requires_block_internal() {
        // curl on a url arg WITHOUT block_internal must be refused at load.
        let bad = r#"
[tool]
name = "fetch"
version = "1.0.0"
binary = "curl"
description = "x"
[args.url]
position = 1
required = true
type = "url"
[command]
template = "curl {url}"
[output]
format = "text"
"#;
        let err = parse_manifest(bad).unwrap_err().to_string();
        assert!(err.contains("block_internal"), "unexpected: {err}");

        // Same manifest WITH block_internal loads fine.
        let good = bad.replace("type = \"url\"", "type = \"url\"\nblock_internal = true");
        assert!(parse_manifest(&good).is_ok());

        // Non-egress binary (whois) does not require the flag.
        let whois = r#"
[tool]
name = "whois"
version = "1.0.0"
binary = "whois"
description = "x"
[args.target]
position = 1
required = true
type = "scope_target"
[command]
template = "whois {target}"
[output]
format = "text"
"#;
        assert!(parse_manifest(whois).is_ok());
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
    fn test_generate_mcp_schema_number_type() {
        let toml_str = r#"
[tool]
name = "score"
version = "1.0.0"
binary = "callback"
description = "x"
risk_tier = "low"
dispatch = "callback"

[args.confidence]
position = 1
required = true
type = "number"
min_float = 0.0
max_float = 1.0
description = "Confidence"
"#;
        let m = parse_manifest(toml_str).unwrap();
        let schema = generate_mcp_schema(&m);
        let prop = &schema["inputSchema"]["properties"]["confidence"];
        assert_eq!(prop["type"], "number");
        assert_eq!(prop["minimum"], 0.0);
        assert_eq!(prop["maximum"], 1.0);
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
mode = "session"
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
        assert_eq!(m.tool.mode.as_deref(), Some("session"));
        assert_eq!(m.mode(), "session");
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
mode = "browser"
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
        assert_eq!(m.mode(), "browser");
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
    fn test_callback_dispatch_allows_no_backend_or_output() {
        // Validator-only embedding: in-process dispatch, no [output] / no backend.
        let toml_str = r#"
[tool]
name = "store_knowledge"
version = "1.0.0"
binary = "callback"
description = "In-process callback dispatch"
risk_tier = "low"
dispatch = "callback"

[args.confidence]
position = 1
required = true
type = "number"
min_float = 0.0
max_float = 1.0
description = "Confidence score 0–1"
"#;
        let m = parse_manifest(toml_str).unwrap();
        assert_eq!(m.tool.dispatch, "callback");
        assert!(m.output.is_none());
        assert!(m.command.exec.is_none());
    }

    #[test]
    fn test_callback_dispatch_schema_omits_output() {
        let toml_str = r#"
[tool]
name = "store_knowledge"
version = "1.0.0"
binary = "callback"
description = "In-process callback dispatch"
risk_tier = "low"
dispatch = "callback"

[args.note]
position = 1
required = true
type = "string"
description = "Note text"
"#;
        let m = parse_manifest(toml_str).unwrap();
        let schema = generate_mcp_schema(&m);
        assert_eq!(schema["name"], "store_knowledge");
        assert!(schema.get("outputSchema").is_none());
    }

    #[test]
    fn test_invalid_dispatch_rejected() {
        let toml_str = r#"
[tool]
name = "bad"
version = "1.0.0"
binary = "x"
description = "x"
risk_tier = "low"
dispatch = "rocket"

[command]
exec = ["true"]

[output]
format = "text"

[output.schema]
type = "object"
"#;
        let err = parse_manifest(toml_str).unwrap_err().to_string();
        assert!(err.contains("invalid dispatch"));
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

    // ---- W1: compile-to-exec at load ------------------------------------

    /// A non-egress manifest skeleton; `$COMMAND` is replaced per test.
    fn echo_manifest(command: &str) -> String {
        format!(
            r#"
[tool]
name = "echo_tool"
version = "1.0.0"
binary = "echo"
description = "x"

[args.target]
position = 1
required = true
type = "scope_target"

[args.label]
position = 2
required = false
type = "string"
default = ""
allow_whitespace = true

{command}

[output]
format = "text"
"#
        )
    }

    #[test]
    fn test_template_is_compiled_to_exec_at_load() {
        let m = parse_manifest(WHOIS_MANIFEST).unwrap();
        assert_eq!(
            m.command.exec.as_deref(),
            Some(&["whois".to_string(), "{target}".to_string()][..])
        );
        // The template is kept for display; it did not declare exec.
        assert_eq!(m.command.template.as_deref(), Some("whois {target}"));
        assert!(!m.command.exec_was_declared);

        let declared =
            parse_manifest(&echo_manifest("[command]\nexec = [\"echo\", \"{target}\"]")).unwrap();
        assert!(declared.command.exec_was_declared);

        // Both present: exec wins and counts as declared.
        let both = parse_manifest(&echo_manifest(
            "[command]\ntemplate = \"echo {target}\"\nexec = [\"echo\", \"{target}\"]",
        ))
        .unwrap();
        assert!(both.command.exec_was_declared);
    }

    #[test]
    fn test_template_placeholder_inside_quotes_refused_at_load() {
        let err = parse_manifest(&echo_manifest(
            "[command]\ntemplate = \"echo '{label}' {target}\"",
        ))
        .unwrap_err()
        .to_string();
        assert!(err.contains("inside quotes"), "unexpected: {err}");

        // Same rule for a conditional template.
        let err = parse_manifest(&echo_manifest(
            "[command]\ntemplate = \"echo {_lbl} {target}\"\n\n[command.conditionals.lbl]\nwhen = \"label != ''\"\ntemplate = \"-l \\\"{label}\\\"\"",
        ))
        .unwrap_err()
        .to_string();
        assert!(err.contains("conditional 'lbl'"), "unexpected: {err}");
        assert!(err.contains("inside quotes"), "unexpected: {err}");

        // A brace escape inside quotes is fine.
        let m = parse_manifest(&echo_manifest(
            "[command]\ntemplate = \"echo -w '%{{http_code}}' {target}\"",
        ))
        .unwrap();
        assert_eq!(m.command.exec.as_ref().unwrap()[2], "%{{http_code}}");
    }

    #[test]
    fn test_unresolved_placeholder_refused_at_load() {
        let err = parse_manifest(&echo_manifest(
            "[command]\ntemplate = \"echo {nope} {target}\"",
        ))
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("unresolved placeholder '{nope}' in command"),
            "unexpected: {err}"
        );
        let err = parse_manifest(&echo_manifest(
            "[command]\nexec = [\"echo\", \"--x={typo}\", \"{target}\"]",
        ))
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("unresolved placeholder '{typo}'"),
            "unexpected: {err}"
        );

        // Inside a conditional.
        let err = parse_manifest(&echo_manifest(
            "[command]\ntemplate = \"echo {_lbl} {target}\"\n\n[command.conditionals.lbl]\nwhen = \"label != ''\"\ntemplate = \"-l {labl}\"",
        ))
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("unresolved placeholder '{labl}'"),
            "unexpected: {err}"
        );
        assert!(err.contains("conditional 'lbl'"), "unexpected: {err}");

        // The legacy `_<arg>` mapping alias is gone; only `_<arg>_flags` exists.
        let err = parse_manifest(&echo_manifest(
            "[command]\ntemplate = \"echo {_label} {target}\"\n\n[command.mappings.label]\nx = \"-x\"",
        ))
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("unresolved placeholder '{_label}'"),
            "unexpected: {err}"
        );
        assert!(parse_manifest(&echo_manifest(
            "[command]\ntemplate = \"echo {_label_flags} {target}\"\n\n[command.mappings.label]\nx = \"-x\"",
        ))
        .is_ok());

        // Injected vars and [command.defaults] keys resolve.
        assert!(parse_manifest(&echo_manifest(
            "[command]\ntemplate = \"echo {_scan_id} {_output_file} {_evidence_dir} {rate} {target}\"\n\n[command.defaults]\nrate = 10",
        ))
        .is_ok());

        // A trusted multi-token var glued to literal text is refused.
        let err = parse_manifest(&echo_manifest(
            "[command]\ntemplate = \"echo --f={_label_flags} {target}\"\n\n[command.mappings.label]\nx = \"-x\"",
        ))
        .unwrap_err()
        .to_string();
        assert!(err.contains("whole token"), "unexpected: {err}");
    }

    #[test]
    fn test_literal_brace_escape_survives_load_and_build() {
        let m = parse_manifest(&echo_manifest(
            "[command]\nexec = [\"echo\", \"-w\", \"%{{http_code}}\", \"{target}\"]",
        ))
        .unwrap();
        let args = HashMap::from([("target".to_string(), "10.0.1.1".to_string())]);
        let argv = executor::build_command_argv(&m, &args).unwrap();
        assert_eq!(argv, vec!["echo", "-w", "%{http_code}", "10.0.1.1"]);
    }

    #[test]
    fn test_end_of_options_validated_at_load_and_applied() {
        let err = parse_manifest(&echo_manifest(
            "[command]\nexec = [\"echo\", \"{target}\"]\nend_of_options = \"-\"",
        ))
        .unwrap_err()
        .to_string();
        assert!(err.contains("end_of_options"), "unexpected: {err}");

        let m = parse_manifest(&echo_manifest(
            "[command]\nexec = [\"echo\", \"-n\", \"{target}\", \"{label}\"]\nend_of_options = \"--\"",
        ))
        .unwrap();
        let args = HashMap::from([
            ("target".to_string(), "10.0.1.1".to_string()),
            ("label".to_string(), "x".to_string()),
        ]);
        let argv = executor::build_command_argv(&m, &args).unwrap();
        assert_eq!(argv, vec!["echo", "-n", "--", "10.0.1.1", "x"]);
        let dry = executor::dry_run(&m, &args).unwrap();
        assert_eq!(dry.command, "echo -n -- 10.0.1.1 x");
    }

    #[test]
    fn test_exec_value_with_space_is_one_argv_element() {
        // Declared exec + allow_whitespace: the value passes validation in
        // exec mode and lands in argv as exactly one element.
        let m = parse_manifest(&echo_manifest(
            "[command]\nexec = [\"echo\", \"--label\", \"{label}\", \"{target}\"]",
        ))
        .unwrap();
        assert!(m.command.exec_was_declared);
        let label = validator::validate_arg_mode(
            "label",
            &m.args["label"],
            "X: y -d @/etc/passwd",
            m.command.exec_was_declared,
        )
        .unwrap();
        let args = HashMap::from([
            ("target".to_string(), "10.0.1.1".to_string()),
            ("label".to_string(), label),
        ]);
        let argv = executor::build_command_argv(&m, &args).unwrap();
        assert_eq!(argv.len(), 4, "argv: {argv:?}");
        assert_eq!(argv[2], "X: y -d @/etc/passwd");
        let dry = executor::dry_run(&m, &args).unwrap();
        assert_eq!(dry.command, "echo --label X: y -d @/etc/passwd 10.0.1.1");

        // The same manifest written as a template stays strict: the compiled
        // exec is not a declared exec, so allow_whitespace is not honored.
        let t = parse_manifest(&echo_manifest(
            "[command]\ntemplate = \"echo --label {label} {target}\"",
        ))
        .unwrap();
        assert!(!t.command.exec_was_declared);
        let err = executor::dry_run(&t, &args).unwrap_err().to_string();
        assert!(
            err.contains("must not contain whitespace"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn test_conditional_tokens_populated_at_load() {
        let m = parse_manifest(&echo_manifest(
            "[command]\nexec = [\"echo\", \"{_lbl}\", \"{target}\"]\n\n[command.conditionals.lbl]\nwhen = \"label != ''\"\ntemplate = \"-l {label}\"",
        ))
        .unwrap();
        let cond = &m.command.conditionals.as_ref().unwrap()["lbl"];
        assert_eq!(cond.tokens, vec!["-l", "{label}"]);

        let args = HashMap::from([
            ("target".to_string(), "10.0.1.1".to_string()),
            ("label".to_string(), "X-Trace: abc".to_string()),
        ]);
        let argv = executor::build_command_argv(&m, &args).unwrap();
        assert_eq!(argv, vec!["echo", "-l", "X-Trace: abc", "10.0.1.1"]);
    }

    #[test]
    fn test_enum_mapping_must_cover_allowed_values_at_load() {
        let base = r#"
[tool]
name = "echo_tool"
version = "1.0.0"
binary = "echo"
description = "x"

[args.target]
position = 1
required = true
type = "scope_target"

[args.mode]
position = 2
required = true
type = "enum"
allowed = ["fast", "slow", "none"]

[command]
exec = ["echo", "{_mode_flags}", "{target}"]

[command.mappings.mode]
$MAPPING

[output]
format = "text"
"#;
        // Two of three allowed values mapped: refused, naming the gap.
        let err = parse_manifest(&base.replace("$MAPPING", "fast = \"-T4\"\nslow = \"-T1\""))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("mapping for enum argument 'mode'"),
            "unexpected: {err}"
        );
        assert!(err.contains("[none]"), "unexpected: {err}");

        // Mapping the remaining value to "" means "no flags" and loads.
        let m = parse_manifest(
            &base.replace("$MAPPING", "fast = \"-T4\"\nslow = \"-T1\"\nnone = \"\""),
        )
        .unwrap();
        let args = HashMap::from([
            ("target".to_string(), "10.0.1.1".to_string()),
            ("mode".to_string(), "none".to_string()),
        ]);
        assert_eq!(
            executor::build_command_argv(&m, &args).unwrap(),
            vec!["echo", "10.0.1.1"]
        );
    }

    #[test]
    fn test_unbalanced_mapping_value_refused_at_load() {
        let err = parse_manifest(&echo_manifest(
            "[command]\ntemplate = \"echo {_label_flags} {target}\"\n\n[command.mappings.label]\nx = \"-x 'oops\"",
        ))
        .unwrap_err()
        .to_string();
        assert!(err.contains("mapping for 'label'"), "unexpected: {err}");
        assert!(err.contains("unbalanced quote"), "unexpected: {err}");
    }

    // ----- unknown manifest keys -----------------------------------------

    /// Smallest valid oneshot manifest with a hole in each section to drop
    /// extra lines into.
    fn oneshot(tool: &str, arg: &str, command: &str, output: &str) -> String {
        format!(
            r#"
[tool]
name = "t"
version = "1.0.0"
binary = "echo"
description = "d"
{tool}

[args.target]
position = 1
required = true
type = "scope_target"
{arg}

[command]
exec = ["echo", "{{target}}"]
{command}

[output]
format = "text"
{output}
"#
        )
    }

    #[test]
    fn test_unknown_tool_key_refused() {
        let err = parse_manifest(&oneshot("tiemout_seconds = 5", "", "", ""))
            .unwrap_err()
            .to_string();
        assert_eq!(
            err,
            "manifest error: unknown key 'tool.tiemout_seconds' in manifest"
        );
    }

    #[test]
    fn test_unknown_arg_key_refused() {
        let err = parse_manifest(&oneshot("", "block_internal_typo = true", "", ""))
            .unwrap_err()
            .to_string();
        assert_eq!(
            err,
            "manifest error: unknown key 'args.target.block_internal_typo' in manifest"
        );
    }

    #[test]
    fn test_unknown_command_output_http_conditional_keys_refused() {
        let err = parse_manifest(&oneshot("", "", "shell = true", ""))
            .unwrap_err()
            .to_string();
        assert_eq!(
            err,
            "manifest error: unknown key 'command.shell' in manifest"
        );

        let err = parse_manifest(&oneshot("", "", "", "max_byte = 1"))
            .unwrap_err()
            .to_string();
        assert_eq!(
            err,
            "manifest error: unknown key 'output.max_byte' in manifest"
        );

        let cond = "[command.conditionals.rate_flag]\nwhen = \"target != ''\"\ntemplate = \"-x\"\nwhenn = \"y\"";
        let err = parse_manifest(&oneshot("", "", cond, ""))
            .unwrap_err()
            .to_string();
        assert_eq!(
            err,
            "manifest error: unknown key 'command.conditionals.rate_flag.whenn' in manifest"
        );
        // Inline-table form of the same conditional.
        let cond = "[command.conditionals]\nrate_flag = { when = \"target != ''\", template = \"-x\", whenn = \"y\" }";
        let err = parse_manifest(&oneshot("", "", cond, ""))
            .unwrap_err()
            .to_string();
        assert_eq!(
            err,
            "manifest error: unknown key 'command.conditionals.rate_flag.whenn' in manifest"
        );

        let http = oneshot("", "", "", "")
            + "\n[http]\nmethod = \"GET\"\nurl = \"https://example.com/\"\nverb = \"GET\"\n";
        let err = parse_manifest(&http).unwrap_err().to_string();
        assert_eq!(err, "manifest error: unknown key 'http.verb' in manifest");
    }

    #[test]
    fn test_several_unknown_keys_reported_together_sorted() {
        let bad = oneshot(
            "tiemout_seconds = 5",
            "block_internal_typo = true",
            "shell = true",
            "max_byte = 1",
        ) + "\n[toolz]\nx = 1\n";
        let err = parse_manifest(&bad).unwrap_err().to_string();
        assert_eq!(
            err,
            "manifest error: \
             unknown key 'args.target.block_internal_typo' in manifest; \
             unknown key 'command.shell' in manifest; \
             unknown key 'output.max_byte' in manifest; \
             unknown key 'tool.tiemout_seconds' in manifest; \
             unknown key 'toolz' in manifest"
        );
    }

    #[test]
    fn test_allow_unknown_keys_downgrades_to_warning() {
        let text = oneshot("tiemout_seconds = 5", "block_internal_typo = true", "", "");
        let strict = LoadOptions::default();
        assert!(!strict.allow_unknown_keys);
        assert!(parse_manifest_with(&text, strict).is_err());

        let lenient = LoadOptions {
            allow_unknown_keys: true,
        };
        let m = parse_manifest_with(&text, lenient).unwrap();
        // The unknown keys were dropped, not applied under another name.
        assert_eq!(m.tool.timeout_seconds, 60);
        assert!(!m.args["target"].block_internal);
    }

    #[test]
    fn test_open_maps_are_not_walked() {
        // Keys inside these tables are user-chosen names, never unknown keys.
        let command = "\n[command.defaults]\nrate = 1\nmax_byte = 2\n\n\
                       [command.mappings.target]\nanything = \"-x\"\n";
        let output = "\n[output.schema]\ntype = \"object\"\nshell = true\n\n\
                      [output.schema.properties.whenn]\ntype = \"string\"\n";
        let m = parse_manifest(&oneshot("", "", command, output)).unwrap();
        assert!(m.command.defaults.unwrap().contains_key("max_byte"));

        let remote = oneshot("", "", "", "")
            + "\n[http]\nmethod = \"GET\"\nurl = \"https://example.com/\"\n\
               [http.headers]\nX-Anything = \"1\"\n\n\
               [mcp]\nserver = \"s\"\ntool = \"t\"\n[mcp.field_map]\nwhatever = \"x\"\n";
        let m = parse_manifest(&remote).unwrap();
        assert!(m.http.unwrap().headers.contains_key("X-Anything"));
        assert!(m.mcp.unwrap().field_map.contains_key("whatever"));
    }

    #[test]
    fn test_serde_is_the_second_layer() {
        // Even without the allowlist walk, the types refuse unknown fields.
        let err = toml::from_str::<types::ArgDef>("type = \"string\"\nblock_internal_typo = true")
            .unwrap_err()
            .to_string();
        assert!(err.contains("unknown field"), "unexpected: {err}");
        let err = toml::from_str::<types::ToolMeta>(
            "name = \"t\"\nversion = \"1\"\nbinary = \"b\"\ndescription = \"d\"\ntiemout_seconds = 5",
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("unknown field"), "unexpected: {err}");
    }

    #[test]
    fn test_tool_mode_validated_and_derived() {
        for mode in MODES {
            let m = parse_manifest(&oneshot(&format!("mode = \"{mode}\""), "", "", "")).unwrap();
            assert_eq!(m.tool.mode.as_deref(), Some(*mode));
            // Advisory: the declared value wins even without a matching section.
            assert_eq!(m.mode(), *mode);
        }
        let err = parse_manifest(&oneshot("mode = \"sessionz\"", "", "", ""))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("invalid mode 'sessionz', must be one of: oneshot, session, browser"),
            "unexpected: {err}"
        );

        // Derived from the backend section when absent.
        let m = parse_manifest(&oneshot("", "", "", "")).unwrap();
        assert!(m.tool.mode.is_none());
        assert_eq!(m.mode(), "oneshot");
        let m = parse_manifest(
            ALL_SESSION_BROWSER_KEYS
                .replace("mode = \"session\"\n", "")
                .as_str(),
        )
        .unwrap();
        assert!(m.tool.mode.is_none());
        assert_eq!(m.mode(), "session");
        let m = parse_manifest(
            ALL_SESSION_BROWSER_KEYS
                .replace("mode = \"session\"\n", "")
                .replace("startup_command", "startup_command_")
                .as_str(),
        );
        assert!(m.is_err()); // sanity: the replacement above hit a real key
    }

    // Every key in the manifest allowlist, spread over three manifests. These are
    // the drift guard between this runtime's allowlist and the others'.

    const ALL_ONESHOT_KEYS: &str = r#"
[tool]
name = "all_oneshot_keys"
version = "1.0.0"
binary = "echo"
description = "exercises every tool, cedar, evidence, limits, args, command and output key"
timeout_seconds = 30
risk_tier = "low"
human_approval = false
dispatch = "exec"
mode = "oneshot"
network_egress = false
allow_interpreter = false

[tool.cedar]
resource = "Tool::AllKeys"
action = "execute_tool"

[tool.evidence]
output_dir = "{evidence_dir}/{scan_id}"
capture = false
hash = "sha256"
screenshots = false

[tool.limits]
nproc = 64
nofile = 256
fsize_bytes = 1048576
address_space_bytes = 268435456
cpu_seconds = 30

[args.target]
position = 1
required = true
type = "scope_target"
description = "host"
sanitize = ["injection"]
scope_check = false
block_internal = true
allow_leading_dash = false
allow_whitespace = false

[args.level]
position = 2
required = false
type = "enum"
allowed = ["low", "high"]
default = "low"
description = "level"

[args.count]
position = 3
required = false
type = "integer"
min = 1
max = 10
clamp = true
default = 5
description = "count"

[args.ratio]
position = 4
required = false
type = "number"
min_float = 0.0
max_float = 1.0
default = 0.5
description = "ratio"

[args.site]
position = 5
required = false
type = "url"
schemes = ["https"]
pattern = "^https://"
default = "https://example.com/"
description = "site"

[command]
exec = ["echo", "{_level_flags}", "{count}", "{ratio}", "{site}", "{rate}", "{_verbose}", "{target}"]
template = "echo {target}"
executor = "/usr/local/bin/all-keys-runner"
end_of_options = "--"

[command.defaults]
rate = 100

[command.mappings.level]
low = "-l"
high = "-h"

[command.conditionals.verbose]
when = "count != '5'"
template = "-v {count}"

[output]
format = "json"
parser = "builtin:json"
envelope = true
max_bytes = 1048576

[output.schema]
type = "object"
"#;

    const ALL_SESSION_BROWSER_KEYS: &str = r#"
[tool]
name = "all_session_browser_keys"
version = "1.0.0"
binary = "psql"
mode = "session"
description = "exercises every session and browser key"

[command]

[session]
startup_command = "psql"
ready_pattern = "=>"
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
human_approval = false
extract_target = false

[session.commands.select.args.query]
position = 1
required = true
type = "string"
description = "SQL"

[session.child_detection]
pattern = "session (\\d+) opened"
type = "meterpreter"
manifest = "tools/meterpreter.clad.toml"

[browser]
engine = "cdp"
headless = true
connect = "launch"
extract_mode = "html"
startup_timeout_seconds = 10
session_timeout_seconds = 600
idle_timeout_seconds = 120
max_interactions = 200

[browser.defaults]
extract_mode = "accessibility_tree"

[browser.scope]
allowed_domains = ["example.com"]
blocked_domains = ["evil.example"]
allow_external = false

[browser.commands.navigate]
description = "Navigate"
risk_tier = "low"
human_approval = false

[browser.commands.navigate.args.url]
position = 1
required = true
type = "url"
description = "URL"

[browser.state]
fields = ["current_url"]

[output]
format = "text"
envelope = true
"#;

    const ALL_HTTP_MCP_KEYS: &str = r#"
[tool]
name = "all_http_mcp_keys"
version = "1.0.0"
binary = "curl"
description = "exercises every http and mcp key"

[args.endpoint]
position = 1
required = true
type = "string"
description = "API endpoint path"

[command]
exec = ["curl", "{endpoint}"]

[http]
method = "POST"
url = "https://api.example.com/{endpoint}"
headers = { "Accept" = "application/json" }
body_template = "{\"q\": \"{endpoint}\"}"
success_status = [200, 201]
error_status = [500]

[mcp]
server = "search"
tool = "query"
field_map = { endpoint = "q" }

[output]
format = "json"
envelope = true
"#;

    /// Keys present at every concrete location matching `section` in `doc`.
    fn keys_at(doc: &toml::Table, section: &str) -> HashSet<String> {
        fn walk(table: &toml::Table, segments: &[&str], out: &mut HashSet<String>) {
            let Some((head, rest)) = segments.split_first() else {
                out.extend(table.keys().cloned());
                return;
            };
            if *head == "*" {
                for value in table.values() {
                    if let toml::Value::Table(t) = value {
                        walk(t, rest, out);
                    }
                }
            } else if let Some(toml::Value::Table(t)) = table.get(*head) {
                walk(t, rest, out);
            }
        }
        let segments: Vec<&str> = section.split('.').filter(|s| !s.is_empty()).collect();
        let mut out = HashSet::new();
        walk(doc, &segments, &mut out);
        out
    }

    #[test]
    fn test_every_allowlisted_key_is_accepted() {
        let docs = [
            ALL_ONESHOT_KEYS,
            ALL_SESSION_BROWSER_KEYS,
            ALL_HTTP_MCP_KEYS,
        ];
        for doc in docs {
            parse_manifest(doc).unwrap_or_else(|e| panic!("{e}\n{doc}"));
        }

        // Drift guard: every key in KNOWN_KEYS must appear in one of the
        // manifests above at its own section, so adding a key to the table
        // forces it into a manifest that the structs then have to accept.
        // Argument tables share one allowlist, so their coverage is pooled.
        const ARG_SECTIONS: &[&str] = &[
            "args.*",
            "session.commands.*.args.*",
            "browser.commands.*.args.*",
        ];
        let tables: Vec<toml::Table> = docs.iter().map(|d| toml::from_str(d).unwrap()).collect();
        let mut missing = Vec::new();
        for (section, keys) in KNOWN_KEYS {
            let sections: &[&str] = if ARG_SECTIONS.contains(section) {
                ARG_SECTIONS
            } else {
                std::slice::from_ref(section)
            };
            let mut seen = HashSet::new();
            for s in sections {
                for t in &tables {
                    seen.extend(keys_at(t, s));
                }
            }
            for key in *keys {
                if !seen.contains(*key) {
                    missing.push(join_path(section, key));
                }
            }
        }
        assert!(
            missing.is_empty(),
            "allowlisted keys not exercised by the drift-guard manifests: {missing:?}"
        );

        // And the new keys land in their fields, not just past the gate.
        let m = parse_manifest(ALL_ONESHOT_KEYS).unwrap();
        assert_eq!(m.mode(), "oneshot");
        assert!(!m.tool.network_egress);
        assert!(!m.tool.allow_interpreter);
        let limits = m.tool.limits.as_ref().unwrap();
        assert_eq!(limits.nproc, Some(64));
        assert_eq!(limits.nofile, Some(256));
        assert_eq!(limits.fsize_bytes, Some(1_048_576));
        assert_eq!(limits.address_space_bytes, Some(268_435_456));
        assert_eq!(limits.cpu_seconds, Some(30));
        assert!(!m.tool.evidence.as_ref().unwrap().screenshots);
        assert_eq!(m.output.as_ref().unwrap().max_bytes, 1_048_576);
        assert_eq!(m.command.end_of_options.as_deref(), Some("--"));

        let m = parse_manifest(ALL_SESSION_BROWSER_KEYS).unwrap();
        let child = m
            .session
            .as_ref()
            .unwrap()
            .child_detection
            .as_ref()
            .unwrap();
        assert_eq!(child.type_name, "meterpreter");
        assert_eq!(child.manifest, "tools/meterpreter.clad.toml");
        let defaults = m.browser.as_ref().unwrap().defaults.as_ref().unwrap();
        assert_eq!(defaults.extract_mode.as_deref(), Some("accessibility_tree"));
        // Defaults for the registered-but-inert keys.
        assert_eq!(m.output.as_ref().unwrap().max_bytes, 8_388_608);
    }
}
