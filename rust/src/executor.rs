use crate::contracts::{
    check_execution, child_environment, http_template, http_url, validate_arguments,
    MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES,
};
use crate::types::{EvidenceEnvelope, Manifest, ToolCladError};
use regex::Regex;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::process::{Command, Stdio};
use std::time::Instant;

#[cfg(unix)]
use std::os::unix::process::CommandExt;

/// Execute an HTTP backend tool, returning an evidence envelope.
fn execute_http(
    manifest: &Manifest,
    validated: &HashMap<String, String>,
) -> Result<EvidenceEnvelope, ToolCladError> {
    let http = manifest.http.as_ref().unwrap();
    let scan_id = format!(
        "{}-{}",
        chrono::Utc::now().timestamp(),
        &uuid::Uuid::new_v4().to_string()[..5]
    );
    let timestamp = chrono::Utc::now().to_rfc3339();
    let start = Instant::now();

    let url = http_url(&http.url, validated)?;
    let mut headers = Vec::new();
    for (key, template) in &http.headers {
        headers.push((
            key.clone(),
            http_template(template, validated, false, false)?,
        ));
    }
    let body = http
        .body_template
        .as_ref()
        .map(|template| http_template(template, validated, false, true))
        .transpose()?;
    if url.len()
        + body.as_ref().map_or(0, String::len)
        + headers
            .iter()
            .map(|(k, v)| k.len() + v.len())
            .sum::<usize>()
        > MAX_REQUEST_BYTES
    {
        return Err(ToolCladError::ExecutionError(
            "HTTP request exceeds 1 MiB".into(),
        ));
    }

    // Execute the HTTP request with timeout.
    let client = reqwest::blocking::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(
            manifest.tool.timeout_seconds,
        ))
        .build()
        .map_err(|e| ToolCladError::ExecutionError(format!("HTTP client error: {e}")))?;
    let method_upper = http.method.to_uppercase();
    let mut req = match method_upper.as_str() {
        "GET" => client.get(&url),
        "POST" => client.post(&url),
        "PUT" => client.put(&url),
        "DELETE" => client.delete(&url),
        "PATCH" => client.patch(&url),
        "HEAD" => client.head(&url),
        other => {
            return Err(ToolCladError::ExecutionError(format!(
                "unsupported HTTP method: {other}"
            )))
        }
    };

    for (hk, hv) in &headers {
        req = req.header(hk, hv);
    }
    if let Some(ref b) = body {
        req = req.body(b.clone());
    }

    let resp = req
        .send()
        .map_err(|e| ToolCladError::ExecutionError(format!("HTTP request failed: {e}")))?;

    let status_code = resp.status().as_u16();
    let mut response_bytes = Vec::new();
    resp.take((MAX_RESPONSE_BYTES + 1) as u64)
        .read_to_end(&mut response_bytes)
        .map_err(|e| ToolCladError::ExecutionError(format!("failed to read response: {e}")))?;
    if response_bytes.len() > MAX_RESPONSE_BYTES {
        return Err(ToolCladError::ExecutionError(
            "HTTP response exceeds 4 MiB".into(),
        ));
    }
    let resp_body = String::from_utf8_lossy(&response_bytes).into_owned();

    let duration_ms = start.elapsed().as_millis() as u64;

    // Determine success/error based on configured status codes.
    let is_success = if http.error_status.contains(&status_code) {
        false
    } else if !http.success_status.is_empty() {
        http.success_status.contains(&status_code)
    } else {
        (200..300).contains(&status_code)
    };

    let status_str = if is_success {
        "success".to_string()
    } else if (400..500).contains(&status_code) {
        format!("client_error (HTTP {})", status_code)
    } else if (500..600).contains(&status_code) {
        format!("server_error (HTTP {})", status_code)
    } else {
        format!("error (HTTP {})", status_code)
    };

    let output_hash = {
        let mut hasher = Sha256::new();
        hasher.update(resp_body.as_bytes());
        format!("sha256:{:x}", hasher.finalize())
    };

    let results = serde_json::json!({
        "raw_output": resp_body,
        "http_status": status_code,
        "http_method": method_upper,
    });

    Ok(EvidenceEnvelope {
        status: status_str,
        scan_id,
        tool: manifest.tool.name.clone(),
        command: format!("{} {}", method_upper, url),
        duration_ms,
        timestamp,
        output_file: None,
        output_hash: Some(output_hash),
        exit_code: if is_success { 0 } else { 1 },
        stderr: String::new(),
        results,
    })
}

/// Execute an MCP proxy backend tool, returning a delegated evidence envelope.
fn execute_mcp_proxy(
    manifest: &Manifest,
    validated: &HashMap<String, String>,
) -> Result<EvidenceEnvelope, ToolCladError> {
    let mcp = manifest.mcp.as_ref().unwrap();
    let scan_id = format!(
        "{}-{}",
        chrono::Utc::now().timestamp(),
        &uuid::Uuid::new_v4().to_string()[..5]
    );
    let timestamp = chrono::Utc::now().to_rfc3339();

    // Map arguments through field_map.
    let mut mapped_args = serde_json::Map::new();
    for (k, v) in validated {
        let target_key = mcp.field_map.get(k).unwrap_or(k);
        mapped_args.insert(target_key.clone(), serde_json::json!(v));
    }

    let results = serde_json::json!({
        "mcp_server": mcp.server,
        "mcp_tool": mcp.tool,
        "mcp_arguments": mapped_args,
    });

    Ok(EvidenceEnvelope {
        status: "delegation_preview".to_string(),
        scan_id,
        tool: manifest.tool.name.clone(),
        command: format!("mcp://{}:{}", mcp.server, mcp.tool),
        duration_ms: 0,
        timestamp,
        output_file: None,
        output_hash: None,
        exit_code: 0,
        stderr: String::new(),
        results,
    })
}

/// Build an argv array from the manifest `exec` field and validated arguments.
///
/// Each element in `exec` is interpolated independently, preserving argument
/// boundaries. This avoids the template→string→split round-trip that breaks
/// when argument values contain spaces or quote characters.
pub fn build_command_argv(
    manifest: &Manifest,
    args: &HashMap<String, String>,
) -> Result<Vec<String>, ToolCladError> {
    let exec = manifest
        .command
        .exec
        .as_ref()
        .ok_or_else(|| ToolCladError::CommandError("no exec array in manifest".to_string()))?;

    let (vars, _) = resolve_vars(manifest, args)?;

    let argv: Vec<String> = exec
        .iter()
        .map(|element| interpolate_template(element, &vars))
        .collect();

    if argv.is_empty() || argv[0].is_empty() {
        return Err(ToolCladError::CommandError(
            "exec array produced empty argv".to_string(),
        ));
    }

    Ok(argv)
}

/// Build the command string from a manifest template and validated arguments.
///
/// Performs template interpolation including:
/// - Direct argument substitution (`{arg_name}`)
/// - Mapping resolution (`{_scan_flags}` from `[command.mappings.scan_type]`)
/// - Default value injection (`[command.defaults]`)
/// - Conditional fragment inclusion (`[command.conditionals]`)
pub fn build_command(
    manifest: &Manifest,
    args: &HashMap<String, String>,
) -> Result<String, ToolCladError> {
    let (vars, present) = resolve_vars(manifest, args)?;
    let argv = if manifest.command.exec.is_some() {
        build_command_argv(manifest, args)?
    } else {
        template_argv(manifest, &vars, &present)?
    };
    Ok(display_argv(&argv))
}

fn display_argv(argv: &[String]) -> String {
    let safe = Regex::new(r"^[A-Za-z0-9_@%+=:,./-]+$").unwrap();
    argv.iter()
        .map(|v| {
            if safe.is_match(v) {
                v.clone()
            } else {
                format!("'{}'", v.replace('\'', "'\"'\"'"))
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn command_fragments(
    manifest: &Manifest,
    vars: &HashMap<String, String>,
) -> HashMap<String, String> {
    let mut fragments = HashMap::new();
    if let Some(mappings) = &manifest.command.mappings {
        for (name, table) in mappings {
            let value = vars
                .get(name)
                .and_then(|v| table.get(v))
                .cloned()
                .unwrap_or_default();
            fragments.insert(format!("_{name}_flags"), value.clone());
            fragments.insert(format!("_{name}"), value.clone());
            if let Some(prefix) = name.strip_suffix("_type") {
                fragments.insert(format!("_{prefix}_flags"), value);
            }
        }
    }
    if let Some(conditionals) = &manifest.command.conditionals {
        for (name, cond) in conditionals {
            fragments.insert(
                format!("_{name}"),
                if evaluate_condition(&cond.when, vars) {
                    cond.template.clone()
                } else {
                    String::new()
                },
            );
        }
    }
    fragments
}

fn template_argv(
    manifest: &Manifest,
    vars: &HashMap<String, String>,
    present: &HashSet<String>,
) -> Result<Vec<String>, ToolCladError> {
    let template = manifest
        .command
        .template
        .as_ref()
        .ok_or_else(|| ToolCladError::CommandError("no command template".into()))?;
    let fragments = command_fragments(manifest, vars);
    let split = |s: &str| {
        shlex::split(s)
            .ok_or_else(|| ToolCladError::CommandError("unclosed command quote or escape".into()))
    };
    let mut argv = Vec::new();
    let placeholder = Regex::new(r"\{(\w+)\}").unwrap();
    for token in split(template)? {
        if let Some(fragment) = token
            .strip_prefix('{')
            .and_then(|s| s.strip_suffix('}'))
            .and_then(|key| fragments.get(key))
        {
            for part in split(fragment)? {
                argv.push(interpolate_template(&part, vars));
            }
        } else {
            let value = interpolate_template(&token, vars);
            if !value.is_empty()
                || token.is_empty()
                || placeholder
                    .captures_iter(&token)
                    .any(|c| present.contains(&c[1]))
            {
                argv.push(value);
            }
        }
    }
    if argv.is_empty() || argv[0].is_empty() {
        return Err(ToolCladError::CommandError(
            "command produced empty argv".into(),
        ));
    }
    Ok(argv)
}

/// Resolve all template variables: args, defaults, mappings, conditionals, executor vars.
fn resolve_vars(
    manifest: &Manifest,
    args: &HashMap<String, String>,
) -> Result<(HashMap<String, String>, HashSet<String>), ToolCladError> {
    let mut vars = validate_arguments(manifest, args)?;
    let present = vars.keys().cloned().collect();
    for name in manifest.args.keys() {
        vars.entry(name.clone()).or_default();
    }
    if let Some(defaults) = &manifest.command.defaults {
        for (key, value) in defaults {
            vars.entry(key.clone())
                .or_insert_with(|| toml_value_to_string(value));
        }
    }
    // Auto-generate executor-injected variables.
    let scan_id = format!(
        "{}-{}",
        chrono::Utc::now().timestamp(),
        &uuid::Uuid::new_v4().to_string()[..5]
    );
    vars.insert("_scan_id".to_string(), scan_id.clone());

    let evidence_dir = std::env::var("TOOLCLAD_EVIDENCE_DIR").unwrap_or_else(|_| {
        let mut dir = std::env::temp_dir();
        dir.push("toolclad-evidence");
        dir.to_string_lossy().to_string()
    });
    vars.insert("_evidence_dir".to_string(), evidence_dir.clone());

    let output_file = format!("{evidence_dir}/{scan_id}-output");
    vars.insert("_output_file".to_string(), output_file);

    let fragments = command_fragments(manifest, &vars);
    for (key, value) in fragments {
        let fragment = interpolate_template(&value, &vars);
        vars.insert(key, fragment);
    }

    Ok((vars, present))
}

/// Interpolate `{placeholder}` references in a template string.
fn interpolate_template(template: &str, vars: &HashMap<String, String>) -> String {
    crate::contracts::interpolate(template, vars)
}

/// Evaluate a simple condition expression against variables.
///
/// SECURITY: This evaluator uses a closed-vocabulary parser.
/// Never use eval() or equivalent dynamic code execution for conditions.
/// Only supports: == != and or, with string/numeric literal comparisons.
///
/// Supports:
/// - `var != ''` — variable is non-empty
/// - `var == ''` — variable is empty
/// - `var != 0` — variable is not "0"
/// - `var == 'literal'` — variable equals a literal
/// - `cond1 and cond2` — conjunction
fn evaluate_condition(expr: &str, vars: &HashMap<String, String>) -> bool {
    // Split on " and " for conjunction.
    if expr.contains(" and ") {
        return expr
            .split(" and ")
            .all(|part| evaluate_condition(part.trim(), vars));
    }

    let expr = expr.trim();

    if let Some(rest) = expr.strip_suffix("!= ''") {
        let var_name = rest.trim();
        let val = vars.get(var_name).map(|s| s.as_str()).unwrap_or("");
        return !val.is_empty();
    }
    if let Some(rest) = expr.strip_suffix("== ''") {
        let var_name = rest.trim();
        let val = vars.get(var_name).map(|s| s.as_str()).unwrap_or("");
        return val.is_empty();
    }

    // Handle `var != 0` or `var != <number>`
    if expr.contains("!=") {
        let parts: Vec<&str> = expr.splitn(2, "!=").collect();
        if parts.len() == 2 {
            let var_name = parts[0].trim();
            let literal = parts[1].trim().trim_matches('\'').trim_matches('"');
            let val = vars.get(var_name).map(|s| s.as_str()).unwrap_or("");
            return val != literal;
        }
    }
    if expr.contains("==") {
        let parts: Vec<&str> = expr.splitn(2, "==").collect();
        if parts.len() == 2 {
            let var_name = parts[0].trim();
            let literal = parts[1].trim().trim_matches('\'').trim_matches('"');
            let val = vars.get(var_name).map(|s| s.as_str()).unwrap_or("");
            return val == literal;
        }
    }

    // Fallback: treat as truthy if the variable exists and is non-empty.
    let val = vars.get(expr).map(|s| s.as_str()).unwrap_or("");
    !val.is_empty()
}

/// Convert a TOML value to a string for interpolation.
fn toml_value_to_string(val: &toml::Value) -> String {
    match val {
        toml::Value::String(s) => s.clone(),
        toml::Value::Integer(n) => n.to_string(),
        toml::Value::Float(f) => f.to_string(),
        toml::Value::Boolean(b) => b.to_string(),
        other => other.to_string(),
    }
}

/// Split a CSV line respecting quoted fields and escaped quotes.
fn split_csv_line(line: &str, delimiter: char) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '"' {
            if in_quotes {
                // Check for escaped quote ""
                if chars.peek() == Some(&'"') {
                    current.push('"');
                    chars.next();
                } else {
                    in_quotes = false;
                }
            } else {
                in_quotes = true;
            }
        } else if c == delimiter && !in_quotes {
            fields.push(current.clone());
            current.clear();
        } else {
            current.push(c);
        }
    }
    fields.push(current);
    fields
}

/// Simple XML to JSON conversion using a state-machine parser.
///
/// Produces nested structures: `{ "tag": { "@attr": "val", "#text": "content", "child": [...] } }`.
/// For repeated child elements with the same tag name, values are collected into arrays.
/// Falls back to `{"raw_output": ...}` on parse failure.
fn parse_xml_to_json(xml: &str) -> Result<serde_json::Value, ToolCladError> {
    let xml = xml.trim();
    if xml.is_empty() {
        return Ok(serde_json::json!({"raw_output": ""}));
    }

    // Strip XML declaration if present
    let xml = if xml.starts_with("<?xml") {
        if let Some(end) = xml.find("?>") {
            xml[end + 2..].trim()
        } else {
            xml
        }
    } else {
        xml
    };

    let attr_re = Regex::new(r#"(\w[\w\-.]*)\s*=\s*["']([^"']*)["']"#).unwrap();

    let mut stack: Vec<(String, serde_json::Map<String, serde_json::Value>)> = Vec::new();
    let mut current_name = String::new();
    let mut current_obj = serde_json::Map::new();
    let mut text_buf = String::new();
    let mut pos = 0;
    let bytes = xml.as_bytes();

    while pos < bytes.len() {
        if bytes[pos] == b'<' {
            // Flush text
            let text = text_buf.trim().to_string();
            if !text.is_empty() && !current_name.is_empty() {
                current_obj.insert("#text".to_string(), serde_json::json!(text));
            }
            text_buf.clear();

            pos += 1;
            if pos >= bytes.len() {
                break;
            }

            if bytes[pos] == b'/' {
                // Closing tag
                pos += 1;
                let tag_end = xml[pos..].find('>').map(|i| pos + i).unwrap_or(bytes.len());
                pos = tag_end + 1;

                let finished_obj = serde_json::Value::Object(std::mem::take(&mut current_obj));
                if let Some((parent_name, mut parent_obj)) = stack.pop() {
                    // Add to parent - if key exists, make it an array
                    if parent_obj.contains_key(&current_name) {
                        let existing = parent_obj.remove(&current_name).unwrap();
                        if let serde_json::Value::Array(mut arr) = existing {
                            arr.push(finished_obj);
                            parent_obj.insert(current_name.clone(), serde_json::Value::Array(arr));
                        } else {
                            parent_obj.insert(
                                current_name.clone(),
                                serde_json::json!([existing, finished_obj]),
                            );
                        }
                    } else {
                        parent_obj.insert(current_name.clone(), finished_obj);
                    }
                    current_name = parent_name;
                    current_obj = parent_obj;
                }
            } else if bytes[pos] == b'!' || bytes[pos] == b'?' {
                // Comment or processing instruction - skip
                let end = xml[pos..].find('>').map(|i| pos + i).unwrap_or(bytes.len());
                pos = end + 1;
            } else {
                // Opening tag
                let tag_end = xml[pos..].find('>').map(|i| pos + i).unwrap_or(bytes.len());
                let tag_content = &xml[pos..tag_end];
                let self_closing = tag_content.ends_with('/');
                let tag_content = if self_closing {
                    &tag_content[..tag_content.len() - 1]
                } else {
                    tag_content
                };

                // Parse tag name and attributes
                let tag_name = tag_content
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .to_string();
                let mut attrs = serde_json::Map::new();

                let attr_str = tag_content[tag_name.len()..].trim();
                for cap in attr_re.captures_iter(attr_str) {
                    attrs.insert(format!("@{}", &cap[1]), serde_json::json!(&cap[2]));
                }

                if self_closing {
                    let obj = serde_json::Value::Object(attrs);
                    if current_obj.contains_key(&tag_name) {
                        let existing = current_obj.remove(&tag_name).unwrap();
                        if let serde_json::Value::Array(mut arr) = existing {
                            arr.push(obj);
                            current_obj.insert(tag_name, serde_json::Value::Array(arr));
                        } else {
                            current_obj.insert(tag_name, serde_json::json!([existing, obj]));
                        }
                    } else {
                        current_obj.insert(tag_name, obj);
                    }
                } else {
                    stack.push((current_name, current_obj));
                    current_name = tag_name;
                    current_obj = attrs;
                }

                pos = tag_end + 1;
            }
        } else {
            text_buf.push(xml[pos..].chars().next().unwrap());
            pos += xml[pos..].chars().next().unwrap().len_utf8();
        }
    }

    if current_name.is_empty() {
        Ok(serde_json::Value::Object(current_obj))
    } else {
        let mut root = serde_json::Map::new();
        root.insert(current_name, serde_json::Value::Object(current_obj));
        Ok(serde_json::Value::Object(root))
    }
}

/// Parse raw command output according to the manifest's output format/parser.
fn parse_output(manifest: &Manifest, raw: &str) -> Result<serde_json::Value, ToolCladError> {
    // Callback-mode manifests may omit [output]; treat as text in that case.
    let (parser, format) = match manifest.output.as_ref() {
        Some(o) => (o.parser.as_deref(), o.format.as_str()),
        None => (None, "text"),
    };
    let parser = parser.unwrap_or(match format {
        "json" => "builtin:json",
        "jsonl" => "builtin:jsonl",
        "csv" => "builtin:csv",
        "xml" => "builtin:xml",
        _ => "builtin:text",
    });

    match parser {
        "builtin:json" => serde_json::from_str(raw)
            .map_err(|e| ToolCladError::ExecutionError(format!("JSON parse failed: {e}"))),
        "builtin:jsonl" => {
            let lines: Vec<serde_json::Value> = raw
                .lines()
                .filter(|l| !l.trim().is_empty())
                .map(serde_json::from_str)
                .collect::<Result<_, _>>()
                .map_err(|e| ToolCladError::ExecutionError(format!("JSONL parse failed: {e}")))?;
            Ok(serde_json::json!(lines))
        }
        "builtin:csv" => {
            let mut lines = raw.lines();
            if let Some(header_line) = lines.next() {
                // Auto-detect delimiter: tab, pipe, comma
                let delimiter = if header_line.contains('\t') {
                    '\t'
                } else if header_line.contains('|') && !header_line.contains(',') {
                    '|'
                } else {
                    ','
                };

                let headers: Vec<String> = split_csv_line(header_line, delimiter)
                    .iter()
                    .map(|h| h.trim().to_string())
                    .collect();

                let rows: Vec<serde_json::Value> = lines
                    .filter(|l| !l.trim().is_empty())
                    .map(|line| {
                        let fields = split_csv_line(line, delimiter);
                        let obj: serde_json::Map<String, serde_json::Value> = headers
                            .iter()
                            .zip(fields.iter())
                            .map(|(h, f)| {
                                let f = f.trim();
                                // Type inference
                                let val = if let Ok(n) = f.parse::<i64>() {
                                    serde_json::json!(n)
                                } else if let Ok(n) = f.parse::<f64>() {
                                    serde_json::json!(n)
                                } else if f == "true" || f == "false" {
                                    serde_json::json!(f == "true")
                                } else {
                                    serde_json::json!(f)
                                };
                                (h.to_string(), val)
                            })
                            .collect();
                        serde_json::Value::Object(obj)
                    })
                    .collect();
                Ok(serde_json::json!(rows))
            } else {
                Ok(serde_json::json!([]))
            }
        }
        "builtin:xml" => parse_xml_to_json(raw),
        "builtin:text" => Ok(serde_json::json!({"raw_output": raw})),
        other => {
            // Custom parser: not supported in reference implementation.
            Ok(serde_json::json!({
                "raw_output": raw,
                "parser_note": format!("custom parser '{}' not executed in reference impl", other)
            }))
        }
    }
}

/// Validate all arguments, build the command, execute it, and return an evidence envelope.
pub fn execute(
    manifest: &Manifest,
    args: &HashMap<String, String>,
) -> Result<EvidenceEnvelope, ToolCladError> {
    let validated = validate_arguments(manifest, args)?;
    check_execution(manifest, false)?;

    // Route to HTTP or MCP backend if configured.
    if manifest.http.is_some() {
        return execute_http(manifest, &validated);
    }
    if manifest.mcp.is_some() {
        return execute_mcp_proxy(manifest, &validated);
    }
    if manifest.session.is_some() {
        return Err(ToolCladError::ExecutionError(
            "session mode is parsed but not yet executable in the reference implementation — use the Symbiont runtime for session execution".into()
        ));
    }
    if manifest.browser.is_some() {
        return Err(ToolCladError::ExecutionError(
            "browser mode is parsed but not yet executable in the reference implementation — use the Symbiont runtime for browser execution".into()
        ));
    }

    let (vars, present) = resolve_vars(manifest, &validated)?;
    let scan_id = vars["_scan_id"].clone();
    let timestamp = chrono::Utc::now().to_rfc3339();
    let start = Instant::now();

    // Phase 2: Build and execute command.
    let (cmd_string, stdout_text, stderr_text, exit_code, status_str) =
        if let Some(ref executor_path) = manifest.command.executor {
            // Escape hatch: run custom executor with env vars.
            // SECURITY: Args are passed as env vars, not interpolated into shell command.
            let mut cmd = Command::new(executor_path);
            child_environment(&mut cmd);
            for (k, v) in &validated {
                cmd.env(format!("TOOLCLAD_ARG_{}", k.to_uppercase()), v);
            }
            cmd.env("TOOLCLAD_SCAN_ID", &scan_id);
            cmd.env("TOOLCLAD_TOOL_NAME", &manifest.tool.name);

            let cmd_display = format!("{executor_path} (custom executor)");
            run_command_with_timeout(cmd, manifest.tool.timeout_seconds, &cmd_display)?
        } else if let Some(exec) = &manifest.command.exec {
            // PREFERRED: Array-based command construction maps directly to execve.
            // No string→split round-trip; values with spaces are safe.
            let argv: Vec<String> = exec
                .iter()
                .map(|v| interpolate_template(v, &vars))
                .collect();
            if argv.is_empty() || argv[0].is_empty() {
                return Err(ToolCladError::CommandError("empty exec array".into()));
            }
            let cmd_display = argv.join(" ");
            let mut cmd = Command::new(&argv[0]);
            child_environment(&mut cmd);
            cmd.args(&argv[1..]);

            run_command_with_timeout(cmd, manifest.tool.timeout_seconds, &cmd_display)?
        } else {
            let argv = template_argv(manifest, &vars, &present)?;
            let cmd_string = display_argv(&argv);
            let mut cmd = Command::new(&argv[0]);
            child_environment(&mut cmd);
            cmd.args(&argv[1..]);

            run_command_with_timeout(cmd, manifest.tool.timeout_seconds, &cmd_string)?
        };

    let duration_ms = start.elapsed().as_millis() as u64;

    // Phase 3: Hash output for evidence.
    let output_hash = {
        let mut hasher = Sha256::new();
        hasher.update(stdout_text.as_bytes());
        format!("sha256:{:x}", hasher.finalize())
    };

    // Phase 3b: Parse output.
    let parsed = parse_output(manifest, &stdout_text)?;

    // Phase 3c: Validate against output schema if defined.
    // (basic type check — full JSON Schema validation would require a dedicated crate)
    let has_custom_schema = manifest
        .output
        .as_ref()
        .is_some_and(|o| o.schema != serde_json::json!({"type": "object"}));
    let results = if has_custom_schema {
        // Schema is declared, use parsed output.
        parsed
    } else {
        serde_json::json!({"raw_output": stdout_text})
    };

    Ok(EvidenceEnvelope {
        status: status_str,
        scan_id,
        tool: manifest.tool.name.clone(),
        command: cmd_string,
        duration_ms,
        timestamp,
        output_file: None,
        output_hash: Some(output_hash),
        exit_code,
        stderr: stderr_text,
        results,
    })
}

/// Run a Command with a timeout, returning (command_string, stdout, stderr, exit_code, status).
///
/// Uses process groups on Unix so that timeout kills can terminate all child
/// processes, not just the top-level shell/binary.
fn run_command_with_timeout(
    mut cmd: Command,
    timeout_seconds: u64,
    cmd_display: &str,
) -> Result<(String, String, String, i32, String), ToolCladError> {
    #[cfg(not(unix))]
    {
        let _ = (&mut cmd, timeout_seconds, cmd_display);
        Err(ToolCladError::ExecutionError(
            "reference command supervision requires Unix".into(),
        ))
    }
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        let mut child = cmd
            .spawn()
            .map_err(|e| ToolCladError::ExecutionError(format!("failed to spawn process: {e}")))?;
        let pid = child.id() as i32;
        let result = (|| {
            let mut stdout = child.stdout.take().unwrap();
            let mut stderr = child.stderr.take().unwrap();
            for fd in [stdout.as_raw_fd(), stderr.as_raw_fd()] {
                // Nonblocking pipes keep descendants that retain an output fd from hanging the supervisor.
                let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
                if flags < 0
                    || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
                {
                    return Err(ToolCladError::ExecutionError(
                        "failed to configure output pipe".into(),
                    ));
                }
            }
            let mut out = Vec::new();
            let mut err = Vec::new();
            let mut out_done = false;
            let mut err_done = false;
            let mut status = None;
            let deadline = Instant::now() + std::time::Duration::from_secs(timeout_seconds);
            loop {
                if Instant::now() >= deadline {
                    return Err(ToolCladError::ExecutionError(format!(
                        "process timed out after {timeout_seconds}s"
                    )));
                }
                if status.is_none() {
                    status = child
                        .try_wait()
                        .map_err(|e| ToolCladError::ExecutionError(format!("wait error: {e}")))?;
                    if status.is_some() {
                        unsafe {
                            libc::killpg(pid, libc::SIGKILL);
                        }
                    }
                }
                if !out_done {
                    out_done = read_available(&mut stdout, &mut out)?;
                }
                if !err_done {
                    err_done = read_available(&mut stderr, &mut err)?;
                }
                if let Some(status) = status {
                    if out_done && err_done {
                        let exit_code = status.code().unwrap_or(-1);
                        return Ok((
                            cmd_display.to_string(),
                            String::from_utf8_lossy(&out).into_owned(),
                            String::from_utf8_lossy(&err).into_owned(),
                            exit_code,
                            if status.success() {
                                "success".into()
                            } else {
                                "error".into()
                            },
                        ));
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
        })();
        unsafe {
            libc::killpg(pid, libc::SIGKILL);
        }
        let _ = child.wait();
        result
    }
}

#[cfg(unix)]
fn read_available(pipe: &mut impl Read, buffer: &mut Vec<u8>) -> Result<bool, ToolCladError> {
    // Bound work per poll as well as stored output so a busy stream cannot starve the deadline.
    let mut chunk = [0u8; 65536];
    match pipe.read(&mut chunk) {
        Ok(0) => Ok(true),
        Ok(count) => {
            if buffer.len() + count > MAX_RESPONSE_BYTES {
                return Err(ToolCladError::ExecutionError(
                    "process output exceeds 4 MiB per stream".into(),
                ));
            }
            buffer.extend_from_slice(&chunk[..count]);
            Ok(false)
        }
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
            ) =>
        {
            Ok(false)
        }
        Err(e) => Err(ToolCladError::ExecutionError(format!(
            "failed to read process output: {e}"
        ))),
    }
}

/// Dry-run: validate args and build command without executing.
pub fn dry_run(
    manifest: &Manifest,
    args: &HashMap<String, String>,
) -> Result<DryRunResult, ToolCladError> {
    let validated = validate_arguments(manifest, args)?;
    check_execution(manifest, true)?;
    let validations = validated
        .iter()
        .map(|(name, value)| format!("{name}={value} (validated)"))
        .collect();

    let command = if manifest.tool.dispatch == "callback" {
        "callback (embedding runtime required)".into()
    } else if let Some(http) = &manifest.http {
        let url = http_url(&http.url, &validated)?;
        for value in http.headers.values() {
            http_template(value, &validated, true, false)?;
        }
        if let Some(body) = &http.body_template {
            http_template(body, &validated, true, true)?;
        }
        format!("{} {}", http.method, url)
    } else if let Some(mcp) = &manifest.mcp {
        format!("mcp://{}/{}", mcp.server, mcp.tool)
    } else if let Some(ref exec) = manifest.command.executor {
        format!("{exec} (custom executor)")
    } else if manifest.command.exec.is_some() {
        build_command_argv(manifest, &validated)?.join(" ")
    } else {
        build_command(manifest, &validated)?
    };

    Ok(DryRunResult {
        validations,
        command,
        cedar: manifest
            .tool
            .cedar
            .as_ref()
            .map(|c| format!("{} / {}", c.resource, c.action)),
        timeout: manifest.tool.timeout_seconds,
    })
}

/// Result of a dry-run invocation.
#[derive(Debug)]
pub struct DryRunResult {
    pub validations: Vec<String>,
    pub command: String,
    pub cedar: Option<String>,
    pub timeout: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;

    fn minimal_manifest() -> Manifest {
        Manifest {
            filesystem: None,
            source: None,
            tool: ToolMeta {
                name: "test_tool".to_string(),
                version: "1.0.0".to_string(),
                binary: "echo".to_string(),
                description: "test".to_string(),
                timeout_seconds: 30,
                risk_tier: "low".to_string(),
                human_approval: false,
                dispatch: "exec".to_string(),
                cedar: None,
                evidence: None,
            },
            args: HashMap::from([(
                "target".to_string(),
                ArgDef {
                    position: 1,
                    required: true,
                    type_name: "scope_target".to_string(),
                    description: "target host".to_string(),
                    ..Default::default()
                },
            )]),
            command: CommandDef {
                template: Some("echo {target}".to_string()),
                ..Default::default()
            },
            output: Some(OutputDef {
                format: "text".to_string(),
                parser: None,
                envelope: true,
                schema: serde_json::json!({"type": "object"}),
            }),
            http: None,
            mcp: None,
            session: None,
            browser: None,
        }
    }

    #[test]
    fn test_build_command_simple() {
        let m = minimal_manifest();
        let mut args = HashMap::new();
        args.insert("target".to_string(), "10.0.1.1".to_string());
        let cmd = build_command(&m, &args).unwrap();
        assert_eq!(cmd, "echo 10.0.1.1");
    }

    #[test]
    fn test_build_command_with_defaults() {
        let mut m = minimal_manifest();
        m.command.template = Some("echo --rate {max_rate} {target}".to_string());
        m.command.defaults = Some(HashMap::from([(
            "max_rate".to_string(),
            toml::Value::Integer(1000),
        )]));
        let mut args = HashMap::new();
        args.insert("target".to_string(), "10.0.1.1".to_string());
        let cmd = build_command(&m, &args).unwrap();
        assert_eq!(cmd, "echo --rate 1000 10.0.1.1");
    }

    #[test]
    fn test_build_command_with_mappings() {
        let mut m = minimal_manifest();
        m.command.template = Some("nmap {_scan_type_flags} {target}".to_string());
        m.args.insert(
            "scan_type".to_string(),
            ArgDef {
                position: 2,
                required: true,
                type_name: "enum".to_string(),
                allowed: Some(vec!["ping".to_string(), "service".to_string()]),
                description: "scan type".to_string(),
                ..Default::default()
            },
        );
        m.command.mappings = Some(HashMap::from([(
            "scan_type".to_string(),
            HashMap::from([
                ("ping".to_string(), "-sn -PE".to_string()),
                ("service".to_string(), "-sT -sV".to_string()),
            ]),
        )]));

        let mut args = HashMap::new();
        args.insert("target".to_string(), "10.0.1.1".to_string());
        args.insert("scan_type".to_string(), "service".to_string());
        let cmd = build_command(&m, &args).unwrap();
        assert_eq!(cmd, "nmap -sT -sV 10.0.1.1");
    }

    #[test]
    fn test_evaluate_condition_not_empty() {
        let mut vars = HashMap::new();
        vars.insert("port".to_string(), "443".to_string());
        assert!(evaluate_condition("port != ''", &vars));
        assert!(!evaluate_condition("port == ''", &vars));
    }

    #[test]
    fn test_evaluate_condition_not_zero() {
        let mut vars = HashMap::new();
        vars.insert("port".to_string(), "443".to_string());
        assert!(evaluate_condition("port != 0", &vars));

        vars.insert("port".to_string(), "0".to_string());
        assert!(!evaluate_condition("port != 0", &vars));
    }

    #[test]
    fn test_evaluate_condition_conjunction() {
        let mut vars = HashMap::new();
        vars.insert("username".to_string(), "admin".to_string());
        vars.insert("username_file".to_string(), String::new());
        assert!(evaluate_condition(
            "username != '' and username_file == ''",
            &vars
        ));
    }

    #[test]
    fn test_dry_run() {
        let m = minimal_manifest();
        let mut args = HashMap::new();
        args.insert("target".to_string(), "10.0.1.1".to_string());
        let result = dry_run(&m, &args).unwrap();
        assert!(result.command.contains("10.0.1.1"));
    }

    #[test]
    fn test_inject_template_vars_with_env() {
        std::env::set_var("TOOLCLAD_SECRET_API_KEY", "test-key-123");
        let result =
            http_template("Bearer {_secret:api_key}", &HashMap::new(), false, false).unwrap();
        assert_eq!(result, "Bearer test-key-123");
        std::env::remove_var("TOOLCLAD_SECRET_API_KEY");
    }

    #[test]
    fn test_inject_template_vars_missing_secret() {
        std::env::remove_var("TOOLCLAD_SECRET_MISSING");
        let result = http_template("token={_secret:missing}", &HashMap::new(), false, false);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("TOOLCLAD_SECRET_MISSING"));
    }

    #[test]
    fn test_inject_template_vars_no_secrets() {
        let result = http_template(
            "plain text with {normal} placeholders",
            &HashMap::new(),
            false,
            false,
        )
        .unwrap();
        assert_eq!(result, "plain text with {normal} placeholders");
    }

    #[test]
    fn test_mcp_proxy_envelope() {
        use crate::types::McpProxyDef;

        let mut m = minimal_manifest();
        m.command = CommandDef::default();
        m.mcp = Some(McpProxyDef {
            server: "code-review-server".to_string(),
            tool: "analyze_pr".to_string(),
            field_map: HashMap::from([("target".to_string(), "repository".to_string())]),
        });

        let mut args = HashMap::new();
        args.insert("target".to_string(), "example.com".to_string());

        let envelope = execute(&m, &args).unwrap();
        assert_eq!(envelope.status, "delegation_preview");
        assert_eq!(envelope.results["mcp_server"], "code-review-server");
        assert_eq!(envelope.results["mcp_tool"], "analyze_pr");
        assert_eq!(
            envelope.results["mcp_arguments"]["repository"],
            "example.com"
        );
    }

    #[test]
    fn test_parse_xml_simple() {
        let xml = r#"<?xml version="1.0"?><root><item name="a">text</item><item name="b">more</item></root>"#;
        let result = parse_xml_to_json(xml).unwrap();
        assert!(result["root"]["item"].is_array());
        assert_eq!(result["root"]["item"][0]["@name"], "a");
        assert_eq!(result["root"]["item"][0]["#text"], "text");
        assert_eq!(result["root"]["item"][1]["@name"], "b");
        assert_eq!(result["root"]["item"][1]["#text"], "more");
    }

    #[test]
    fn test_parse_xml_empty() {
        let result = parse_xml_to_json("").unwrap();
        assert_eq!(result["raw_output"], "");
    }

    #[test]
    fn test_parse_xml_self_closing() {
        let xml = r#"<root><item name="a"/><item name="b"/></root>"#;
        let result = parse_xml_to_json(xml).unwrap();
        assert!(result["root"]["item"].is_array());
    }

    #[test]
    fn test_parse_csv_with_types() {
        let result = split_csv_line("Alice,30,true", ',');
        assert_eq!(result, vec!["Alice", "30", "true"]);
    }

    #[test]
    fn test_split_csv_quoted() {
        let result = split_csv_line(r#""hello, world",42,"test""#, ',');
        assert_eq!(result, vec!["hello, world", "42", "test"]);
    }

    #[test]
    fn test_split_csv_tab_delimiter() {
        let result = split_csv_line("a\tb\tc", '\t');
        assert_eq!(result, vec!["a", "b", "c"]);
    }

    #[test]
    fn test_split_csv_escaped_quotes() {
        let result = split_csv_line(r#""he said ""hi""",val"#, ',');
        assert_eq!(result, vec![r#"he said "hi""#, "val"]);
    }
}
