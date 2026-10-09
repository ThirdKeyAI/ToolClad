use crate::scope::ScopeDef;
use crate::types::{ConditionalDef, EvidenceEnvelope, Manifest, ToolCladError};
use crate::validator::validate_arg_in;
use regex::Regex;
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::process::{Command, Stdio};
use std::sync::LazyLock;
use std::time::Instant;

#[cfg(unix)]
use std::os::unix::process::CommandExt;

/// Replace `{_secret:name}` with `TOOLCLAD_SECRET_{NAME}` env var.
fn inject_template_vars(template: &str) -> Result<String, ToolCladError> {
    let re = Regex::new(r"\{_secret:([a-zA-Z0-9_]+)\}").unwrap();
    let mut result = template.to_string();
    for cap in re.captures_iter(template) {
        let name = &cap[1];
        let env_key = format!("TOOLCLAD_SECRET_{}", name.to_uppercase());
        let val = std::env::var(&env_key).map_err(|_| {
            ToolCladError::ExecutionError(format!("Secret '{}' not found (set {})", name, env_key))
        })?;
        result = result.replace(&cap[0], &val);
    }
    Ok(result)
}

/// The interpolated parts of an HTTP backend request.
#[derive(Debug)]
struct HttpRequestParts {
    url: String,
    headers: Vec<(String, String)>,
    body: Option<String>,
}

/// Build the URL, headers and body of an HTTP backend request.
///
/// Order matters: `{_secret:name}` references are expanded on the manifest
/// template FIRST, then validated arguments are interpolated. A value that
/// smuggles a `{_secret:…}` reference therefore lands after secret expansion
/// has already happened and stays a literal: it can never pull a secret into
/// an attacker-chosen URL, header or body. The `url` validator independently
/// rejects `{` and `}`; this ordering does not rely on that.
fn build_http_request(
    manifest: &Manifest,
    validated: &HashMap<String, String>,
) -> Result<HttpRequestParts, ToolCladError> {
    let http = manifest.http.as_ref().ok_or_else(|| {
        ToolCladError::ExecutionError("manifest has no [http] section".to_string())
    })?;

    // URL: secrets on the template, then arguments.
    let mut url = inject_template_vars(&http.url)?;
    for (k, v) in validated {
        url = url.replace(&format!("{{{k}}}"), v);
    }

    // Headers: same order for every value.
    let mut headers: Vec<(String, String)> = Vec::with_capacity(http.headers.len());
    for (hk, hv) in &http.headers {
        let mut val = inject_template_vars(hv)?;
        for (k, v) in validated {
            val = val.replace(&format!("{{{k}}}"), v);
        }
        headers.push((hk.clone(), val));
    }

    // Body: secrets on the template, then JSON-escaped arguments.
    let body = match http.body_template {
        Some(ref body_tmpl) => {
            let mut b = inject_template_vars(body_tmpl)?;
            for (k, v) in validated {
                // JSON-escape the value to prevent injection into JSON body.
                let escaped = serde_json::to_string(v)
                    .unwrap_or_else(|_| format!("\"{}\"", v))
                    .trim_matches('"')
                    .to_string();
                b = b.replace(&format!("{{{k}}}"), &escaped);
            }
            Some(b)
        }
        None => None,
    };

    Ok(HttpRequestParts { url, headers, body })
}

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

    let HttpRequestParts { url, headers, body } = build_http_request(manifest, validated)?;

    // Execute the HTTP request with timeout.
    let client = reqwest::blocking::Client::builder()
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
    let resp_body = resp
        .text()
        .map_err(|e| ToolCladError::ExecutionError(format!("failed to read response: {e}")))?;

    let duration_ms = start.elapsed().as_millis() as u64;

    // Determine success/error based on configured status codes.
    let is_success = if !http.success_status.is_empty() {
        http.success_status.contains(&status_code)
    } else if !http.error_status.is_empty() {
        !http.error_status.contains(&status_code)
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

/// Matches, in one left-to-right pass, either a brace escape (`{{` / `}}`)
/// or a `{name}` placeholder. Escapes are consumed before placeholders so a
/// literal `%{{http_code}}` is never misread as a placeholder.
static PLACEHOLDER_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\{\{|\}\}|\{(\w+)\}").unwrap());

/// Variables the executor injects into every command; always resolvable.
pub const INJECTED_VARS: &[&str] = &["_scan_id", "_output_file", "_evidence_dir"];

/// Tokenize a trusted manifest template string into an argv-shaped vector.
///
/// POSIX-like: `'…'` and `"…"` group whitespace, `\` escapes the next
/// character outside single quotes. The tokenizer runs on manifest text only
/// — substituted values are never re-split. A `{` inside quotes is refused
/// (unless it opens a `{{` escape) because a quoted placeholder would let a
/// value break out of its token; placeholders must be whole, unquoted tokens.
pub fn tokenize_template(s: &str) -> Result<Vec<String>, ToolCladError> {
    let mut tokens: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut started = false;
    let mut in_single = false;
    let mut in_double = false;
    let mut chars = s.char_indices().peekable();

    while let Some((i, c)) = chars.next() {
        match c {
            '\\' if !in_single => match chars.next() {
                Some((_, next)) => {
                    cur.push(next);
                    started = true;
                }
                None => {
                    return Err(ToolCladError::ManifestError(
                        "trailing backslash in command template".to_string(),
                    ))
                }
            },
            '\'' if !in_double => {
                in_single = !in_single;
                started = true;
            }
            '"' if !in_single => {
                in_double = !in_double;
                started = true;
            }
            '{' if in_single || in_double => {
                if chars.peek().map(|(_, n)| *n) == Some('{') {
                    // `{{` escape: a literal brace is fine inside quotes.
                    chars.next();
                    cur.push_str("{{");
                    started = true;
                } else {
                    return Err(ToolCladError::ManifestError(format!(
                        "command template places a placeholder inside quotes at offset {i}; \
                         placeholders must be whole, unquoted tokens (use exec = [...])"
                    )));
                }
            }
            c if c.is_whitespace() && !in_single && !in_double => {
                if started {
                    tokens.push(std::mem::take(&mut cur));
                    started = false;
                }
            }
            c => {
                cur.push(c);
                started = true;
            }
        }
    }

    if in_single || in_double {
        return Err(ToolCladError::ManifestError(
            "unbalanced quote in command template".to_string(),
        ));
    }
    if started {
        tokens.push(cur);
    }
    Ok(tokens)
}

/// Placeholder names referenced by one token, in order, skipping `{{`/`}}`
/// escapes. Shared by the load-time scan and build-time substitution so the
/// two can never disagree about what counts as a placeholder.
pub fn placeholder_names(token: &str) -> Vec<String> {
    PLACEHOLDER_RE
        .captures_iter(token)
        .filter_map(|cap| cap.get(1).map(|m| m.as_str().to_string()))
        .collect()
}

/// If `token` is exactly one `{name}` placeholder (no surrounding text, not
/// an escape), return `name`.
fn exact_placeholder(token: &str) -> Option<&str> {
    let cap = PLACEHOLDER_RE.captures(token)?;
    let whole = cap.get(0)?;
    if whole.start() == 0 && whole.end() == token.len() {
        cap.get(1).map(|m| m.as_str())
    } else {
        None
    }
}

/// The compiled exec form of a manifest: the declared `exec` array, or the
/// tokenized `template` when the manifest was built without going through the
/// loader (which compiles the template at load).
fn compiled_exec(manifest: &Manifest) -> Result<Vec<String>, ToolCladError> {
    if let Some(ref exec) = manifest.command.exec {
        return Ok(exec.clone());
    }
    if let Some(ref template) = manifest.command.template {
        return tokenize_template(template);
    }
    Err(ToolCladError::CommandError(
        "no exec array or command template in manifest (use executor for custom wrappers)"
            .to_string(),
    ))
}

/// The token vector of a conditional: the load-compiled `tokens`, or the
/// tokenized `template` for manifests built without the loader.
fn conditional_tokens(cond: &ConditionalDef) -> Result<Vec<String>, ToolCladError> {
    if !cond.tokens.is_empty() || cond.template.is_empty() {
        return Ok(cond.tokens.clone());
    }
    tokenize_template(&cond.template)
}

/// Single-token variables (`vars`) and trusted multi-token variables
/// (`trusted`) resolved for one invocation.
struct ResolvedVars {
    /// User args, `[command.defaults]`, and executor-injected values. Each is
    /// exactly one argv token's worth of text and is only ever substituted
    /// textually inside a single token.
    vars: HashMap<String, String>,
    /// `_<arg>_flags` from `[command.mappings]` and `_<cond>` from
    /// `[command.conditionals]`: manifest-controlled token vectors spliced
    /// into argv when referenced as a whole token.
    trusted: HashMap<String, Vec<String>>,
}

/// Substitute one token vector per W1.3.
///
/// A token that is exactly `{name}` for a trusted var splices that var's
/// tokens; every other token has its placeholders substituted textually and is
/// emitted as a single argv entry, never re-split. A token that was exactly one
/// placeholder resolving to the empty string is dropped. Returns the argv
/// slice plus the index of the first entry produced from a token that was
/// solely a user-argument placeholder (for `end_of_options`).
fn substitute_tokens(
    tokens: &[String],
    vars: &HashMap<String, String>,
    trusted: &HashMap<String, Vec<String>>,
    user_args: &HashSet<&str>,
    context: &str,
) -> Result<(Vec<String>, Option<usize>), ToolCladError> {
    let mut out: Vec<String> = Vec::new();
    let mut first_user_arg: Option<usize> = None;

    for token in tokens {
        let exact = exact_placeholder(token);
        if let Some(name) = exact {
            if let Some(vec) = trusted.get(name) {
                out.extend(vec.iter().cloned());
                continue;
            }
        }

        let mut result = String::with_capacity(token.len());
        let mut last = 0;
        for cap in PLACEHOLDER_RE.captures_iter(token) {
            let whole = cap.get(0).unwrap();
            result.push_str(&token[last..whole.start()]);
            match whole.as_str() {
                "{{" => result.push('{'),
                "}}" => result.push('}'),
                _ => {
                    let name = &cap[1];
                    match vars.get(name) {
                        Some(v) => result.push_str(v),
                        None if trusted.contains_key(name) => {
                            return Err(ToolCladError::CommandError(format!(
                                "placeholder '{{{name}}}' expands to multiple tokens and must be a whole token in {context}"
                            )));
                        }
                        None => {
                            return Err(ToolCladError::CommandError(format!(
                                "unresolved placeholder '{{{name}}}' in {context}"
                            )));
                        }
                    }
                }
            }
            last = whole.end();
        }
        result.push_str(&token[last..]);

        if let Some(name) = exact {
            if result.is_empty() {
                // An unset optional disappears from argv entirely.
                continue;
            }
            if first_user_arg.is_none() && user_args.contains(name) {
                first_user_arg = Some(out.len());
            }
        }
        out.push(result);
    }

    Ok((out, first_user_arg))
}

/// Build an argv array from the manifest's compiled exec form and validated
/// arguments.
///
/// Each element is substituted independently (see [`tokenize_template`] for
/// how a `template` becomes elements). Trusted multi-token variables
/// (`{_<arg>_flags}`, `{_<cond>}`) splice their token vectors; everything else
/// is substituted inside its own element and never re-split, so a value
/// containing spaces or quotes stays exactly one argv entry.
pub fn build_command_argv(
    manifest: &Manifest,
    args: &HashMap<String, String>,
) -> Result<Vec<String>, ToolCladError> {
    let tokens = compiled_exec(manifest)?;
    let resolved = resolve_vars(manifest, args)?;
    let user_args: HashSet<&str> = manifest.args.keys().map(String::as_str).collect();

    let (mut argv, first_user_arg) = substitute_tokens(
        &tokens,
        &resolved.vars,
        &resolved.trusted,
        &user_args,
        "command",
    )?;

    if let Some(ref eoo) = manifest.command.end_of_options {
        if eoo != "--" {
            return Err(ToolCladError::CommandError(format!(
                "end_of_options must be exactly \"--\" (got '{eoo}')"
            )));
        }
        if let Some(idx) = first_user_arg {
            argv.insert(idx, "--".to_string());
        }
    }

    if argv.is_empty() {
        return Err(ToolCladError::CommandError(
            "exec array produced empty argv".to_string(),
        ));
    }

    Ok(argv)
}

/// Build a display string for the command from a manifest and validated
/// arguments.
///
/// Compatibility shim: this is [`build_command_argv`] joined with single
/// spaces. The string is for display only and is never re-split or executed;
/// use [`build_command_argv`] for anything that reaches a process.
#[deprecated(note = "use build_command_argv; the joined string is for display only")]
pub fn build_command(
    manifest: &Manifest,
    args: &HashMap<String, String>,
) -> Result<String, ToolCladError> {
    Ok(build_command_argv(manifest, args)?.join(" "))
}

/// Resolve the two variable classes for one invocation: single-token vars
/// (declared args, `[command.defaults]`, executor-injected values) and trusted
/// multi-token vars (`_<arg>_flags` from mappings, `_<cond>` from conditionals).
fn resolve_vars(
    manifest: &Manifest,
    args: &HashMap<String, String>,
) -> Result<ResolvedVars, ToolCladError> {
    let mut vars: HashMap<String, String> = HashMap::new();

    // Declared args only: an undeclared key can never reach a placeholder.
    for name in manifest.args.keys() {
        if let Some(v) = args.get(name) {
            vars.insert(name.clone(), v.clone());
        }
    }

    // [command.defaults] for anything not supplied.
    if let Some(ref defaults) = manifest.command.defaults {
        for (key, val) in defaults {
            vars.entry(key.clone())
                .or_insert_with(|| toml_value_to_string(val));
        }
    }

    // Per-arg defaults for anything still missing.
    for (key, def) in &manifest.args {
        if !vars.contains_key(key) {
            if let Some(ref default_val) = def.default {
                vars.insert(key.clone(), toml_value_to_string(default_val));
            }
        }
    }

    // Executor-injected single-token vars. Inserted after user args so a
    // declared arg can never shadow them.
    let scan_id = format!(
        "{}-{}",
        chrono::Utc::now().timestamp(),
        &uuid::Uuid::new_v4().to_string()[..5]
    );
    let evidence_dir = std::env::var("TOOLCLAD_EVIDENCE_DIR").unwrap_or_else(|_| {
        let mut dir = std::env::temp_dir();
        dir.push("toolclad-evidence");
        dir.to_string_lossy().to_string()
    });
    let output_file = format!("{evidence_dir}/{scan_id}-output");
    vars.insert("_scan_id".to_string(), scan_id);
    vars.insert("_evidence_dir".to_string(), evidence_dir);
    vars.insert("_output_file".to_string(), output_file);

    let mut trusted: HashMap<String, Vec<String>> = HashMap::new();

    // Mappings: `[command.mappings.<arg>]` → `_<arg>_flags`. The mapped value
    // is manifest text, so tokenizing it is safe; it is spliced verbatim.
    if let Some(ref mappings) = manifest.command.mappings {
        for (arg_name, mapping) in mappings {
            let tokens = match vars.get(arg_name) {
                Some(arg_val) => match mapping.get(arg_val) {
                    Some(mapped) => tokenize_template(mapped)?,
                    None => {
                        return Err(ToolCladError::CommandError(format!(
                            "no mapping for argument '{arg_name}' value '{arg_val}' in [command.mappings.{arg_name}]"
                        )));
                    }
                },
                None => Vec::new(),
            };
            trusted.insert(format!("_{arg_name}_flags"), tokens);
        }
    }

    // Conditionals: `[command.conditionals.<name>]` → `_<name>`. Each token of
    // the compiled fragment is substituted individually; a false condition
    // contributes nothing. Resolved in name order so the result is stable.
    if let Some(ref conditionals) = manifest.command.conditionals {
        let mut names: Vec<&String> = conditionals.keys().collect();
        names.sort();
        let no_user_args: HashSet<&str> = HashSet::new();
        for cond_name in names {
            let cond_def = &conditionals[cond_name];
            let tokens = if evaluate_condition(&cond_def.when, &vars) {
                let fragment = conditional_tokens(cond_def)?;
                let (out, _) = substitute_tokens(
                    &fragment,
                    &vars,
                    &trusted,
                    &no_user_args,
                    &format!("conditional '{cond_name}'"),
                )?;
                out
            } else {
                Vec::new()
            };
            trusted.insert(format!("_{cond_name}"), tokens);
        }
    }

    Ok(ResolvedVars { vars, trusted })
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
pub(crate) fn toml_value_to_string(val: &toml::Value) -> String {
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

/// Refuse a supplied argument name the manifest does not declare in `[args]`.
///
/// An undeclared argument never reaches the command, but dropping it without
/// a word lets a caller believe it took effect: `extra_flags=-iL /etc/passwd`
/// against a manifest that no longer declares `extra_flags` would otherwise
/// run successfully and say nothing.
fn check_declared_args(
    manifest: &Manifest,
    args: &HashMap<String, String>,
) -> Result<(), ToolCladError> {
    let mut unknown: Vec<&str> = args
        .keys()
        .filter(|name| !manifest.args.contains_key(*name))
        .map(String::as_str)
        .collect();
    if unknown.is_empty() {
        return Ok(());
    }
    unknown.sort_unstable();
    let mut declared: Vec<&str> = manifest.args.keys().map(String::as_str).collect();
    declared.sort_unstable();
    Err(ToolCladError::ValidationError(format!(
        "unknown argument '{}' (declared arguments: {})",
        unknown[0],
        declared.join(", ")
    )))
}

/// The scope for one call: the one cached at load, else — for a manifest
/// built in code, or one whose scope file appeared after load — discovered
/// now from the manifest's source directory, once, when any argument sets
/// `scope_check`.
fn call_scope(manifest: &Manifest) -> Result<Option<Cow<'_, ScopeDef>>, ToolCladError> {
    if let Some(ref scope) = manifest.scope {
        return Ok(Some(Cow::Borrowed(scope)));
    }
    if manifest.args.values().any(|d| d.scope_check) {
        return Ok(crate::scope::discover_scope(manifest.source_dir.as_deref())?.map(Cow::Owned));
    }
    Ok(None)
}

/// Validate all arguments, build the command, execute it, and return an evidence envelope.
pub fn execute(
    manifest: &Manifest,
    args: &HashMap<String, String>,
) -> Result<EvidenceEnvelope, ToolCladError> {
    check_declared_args(manifest, args)?;

    // Phase 1: Validate all arguments. `allow_whitespace` is honored only when
    // the manifest declared `exec` directly; a compiled template stays strict,
    // and so does the `executor` escape hatch (it takes precedence over
    // exec/template and its argument handling is opaque to us).
    // A default is validated like a supplied value (it was type-checked at
    // load; the scope check can only run here).
    let exec_mode = manifest.command.executor.is_none() && manifest.command.exec_was_declared;
    let scope = call_scope(manifest)?;
    let scope = scope.as_deref();
    let mut validated = HashMap::new();
    for (name, def) in &manifest.args {
        if let Some(val) = args.get(name) {
            let clean = validate_arg_in(name, def, val, exec_mode, scope)?;
            validated.insert(name.clone(), clean);
        } else if let Some(ref default_val) = def.default {
            let dv = toml_value_to_string(default_val);
            let clean = validate_arg_in(name, def, &dv, exec_mode, scope)?;
            validated.insert(name.clone(), clean);
        } else if def.required {
            return Err(ToolCladError::ValidationError(format!(
                "missing required argument '{name}'"
            )));
        }
    }

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

    let scan_id = format!(
        "{}-{}",
        chrono::Utc::now().timestamp(),
        &uuid::Uuid::new_v4().to_string()[..5]
    );
    let timestamp = chrono::Utc::now().to_rfc3339();
    let start = Instant::now();

    // Phase 2: Build and execute command.
    let (cmd_string, stdout_text, stderr_text, exit_code, status_str) =
        if let Some(ref executor_path) = manifest.command.executor {
            // Escape hatch: run custom executor with env vars.
            // SECURITY: Args are passed as env vars, not interpolated into shell command.
            let mut cmd = Command::new(executor_path);
            for (k, v) in &validated {
                cmd.env(format!("TOOLCLAD_ARG_{}", k.to_uppercase()), v);
            }
            cmd.env("TOOLCLAD_SCAN_ID", &scan_id);
            cmd.env("TOOLCLAD_TOOL_NAME", &manifest.tool.name);

            let cmd_display = format!("{executor_path} (custom executor)");
            run_command_with_timeout(cmd, manifest.tool.timeout_seconds, &cmd_display)?
        } else {
            // Array-based command construction maps directly to execve. A
            // `template` was tokenized at load into the same array, so there is
            // no string→split round-trip anywhere on the spawn path.
            let argv = build_command_argv(manifest, &validated)?;
            let cmd_display = argv.join(" ");
            let mut cmd = Command::new(&argv[0]);
            cmd.args(&argv[1..]);

            run_command_with_timeout(cmd, manifest.tool.timeout_seconds, &cmd_display)?
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
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

    // SECURITY: Create a new process group so we can kill all children on timeout.
    #[cfg(unix)]
    cmd.process_group(0);

    let mut child = cmd
        .spawn()
        .map_err(|e| ToolCladError::ExecutionError(format!("failed to spawn process: {e}")))?;

    if timeout_seconds > 0 {
        let pid = child.id();

        // Take stdout/stderr handles before polling to avoid deadlock.
        let stdout_pipe = child.stdout.take();
        let stderr_pipe = child.stderr.take();

        // Read stdout/stderr in separate threads to avoid pipe buffer deadlock.
        let stdout_handle = std::thread::spawn(move || {
            let mut buf = String::new();
            if let Some(mut pipe) = stdout_pipe {
                use std::io::Read;
                let _ = pipe.read_to_string(&mut buf);
            }
            buf
        });
        let stderr_handle = std::thread::spawn(move || {
            let mut buf = String::new();
            if let Some(mut pipe) = stderr_pipe {
                use std::io::Read;
                let _ = pipe.read_to_string(&mut buf);
            }
            buf
        });

        // Poll child with timeout.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_seconds);
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) => {
                    if std::time::Instant::now() >= deadline {
                        // Timeout! Kill the entire process group.
                        #[cfg(unix)]
                        unsafe {
                            libc::killpg(pid as i32, libc::SIGKILL);
                        }
                        #[cfg(not(unix))]
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err(ToolCladError::ExecutionError(format!(
                            "process timed out after {timeout_seconds}s"
                        )));
                    }
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                Err(e) => return Err(ToolCladError::ExecutionError(format!("wait error: {e}"))),
            }
        };

        let stdout = stdout_handle.join().unwrap_or_default();
        let stderr = stderr_handle.join().unwrap_or_default();
        let exit_code = status.code().unwrap_or(-1);
        let status_str = if status.success() {
            "success".to_string()
        } else {
            format!("error (exit code: {exit_code}): {stderr}")
        };
        Ok((
            cmd_display.to_string(),
            stdout,
            stderr,
            exit_code,
            status_str,
        ))
    } else {
        let output = child
            .wait_with_output()
            .map_err(|e| ToolCladError::ExecutionError(format!("process error: {e}")))?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let exit_code = output.status.code().unwrap_or(-1);

        let status = if output.status.success() {
            "success".to_string()
        } else {
            format!("error (exit code: {exit_code}): {stderr}")
        };

        Ok((cmd_display.to_string(), stdout, stderr, exit_code, status))
    }
}

/// Dry-run: validate args and build command without executing.
pub fn dry_run(
    manifest: &Manifest,
    args: &HashMap<String, String>,
) -> Result<DryRunResult, ToolCladError> {
    check_declared_args(manifest, args)?;

    // Validate all arguments (strict for the executor escape hatch).
    let exec_mode = manifest.command.executor.is_none() && manifest.command.exec_was_declared;
    let scope = call_scope(manifest)?;
    let scope = scope.as_deref();
    let mut validated = HashMap::new();
    let mut validations = Vec::new();

    for (name, def) in &manifest.args {
        if let Some(val) = args.get(name) {
            match validate_arg_in(name, def, val, exec_mode, scope) {
                Ok(clean) => {
                    validations.push(format!("{name}={clean} ({}: OK)", def.type_name));
                    validated.insert(name.clone(), clean);
                }
                Err(e) => {
                    validations.push(format!("{name}={val} ({}: FAIL: {e})", def.type_name));
                    return Err(e);
                }
            }
        } else if let Some(ref default_val) = def.default {
            let dv = validate_arg_in(
                name,
                def,
                &toml_value_to_string(default_val),
                exec_mode,
                scope,
            )?;
            validations.push(format!("{name}={dv} (default)"));
            validated.insert(name.clone(), dv);
        } else if def.required {
            return Err(ToolCladError::ValidationError(format!(
                "missing required argument '{name}'"
            )));
        }
    }

    let command = if let Some(ref exec) = manifest.command.executor {
        format!("{exec} (custom executor)")
    } else {
        build_command_argv(manifest, &validated)?.join(" ")
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
            tool: ToolMeta {
                name: "test_tool".to_string(),
                version: "1.0.0".to_string(),
                binary: "echo".to_string(),
                description: "test".to_string(),
                timeout_seconds: 30,
                risk_tier: "low".to_string(),
                human_approval: false,
                dispatch: "exec".to_string(),
                mode: None,
                network_egress: false,
                allow_interpreter: false,
                cedar: None,
                evidence: None,
                limits: None,
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
                max_bytes: 8_388_608,
            }),
            http: None,
            mcp: None,
            session: None,
            browser: None,
            source_dir: None,
            scope: None,
        }
    }

    #[test]
    #[allow(deprecated)]
    fn test_build_command_simple() {
        let m = minimal_manifest();
        let mut args = HashMap::new();
        args.insert("target".to_string(), "10.0.1.1".to_string());
        let cmd = build_command(&m, &args).unwrap();
        assert_eq!(cmd, "echo 10.0.1.1");
    }

    #[test]
    #[allow(deprecated)]
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
    #[allow(deprecated)]
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
    fn test_undeclared_argument_refused_at_call_time() {
        // `extra_flags` is not in [args]; it must be refused, not dropped.
        let m = minimal_manifest();
        let mut args = HashMap::new();
        args.insert("target".to_string(), "10.0.1.1".to_string());
        args.insert("extra_flags".to_string(), "-iL /etc/passwd".to_string());

        let err = dry_run(&m, &args).unwrap_err().to_string();
        assert_eq!(
            err,
            "validation error: unknown argument 'extra_flags' (declared arguments: target)"
        );
        let err = execute(&m, &args).unwrap_err().to_string();
        assert!(
            err.contains("unknown argument 'extra_flags'"),
            "unexpected: {err}"
        );

        // Several unknown names: the first in sorted order is named, so the
        // message is deterministic regardless of map iteration order.
        args.insert("zz".to_string(), "1".to_string());
        args.insert("aa".to_string(), "1".to_string());
        let err = dry_run(&m, &args).unwrap_err().to_string();
        assert!(err.contains("unknown argument 'aa'"), "unexpected: {err}");

        // Only declared names: still fine.
        let mut ok = HashMap::new();
        ok.insert("target".to_string(), "10.0.1.1".to_string());
        assert!(dry_run(&m, &ok).is_ok());
    }

    #[test]
    fn test_dry_run() {
        let m = minimal_manifest();
        let mut args = HashMap::new();
        args.insert("target".to_string(), "10.0.1.1".to_string());
        let result = dry_run(&m, &args).unwrap();
        assert!(result.command.contains("10.0.1.1"));
    }

    /// Serializes tests that touch `TOOLCLAD_SECRET_*` environment variables,
    /// which are process-global and would otherwise race across threads.
    static SECRET_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn test_inject_template_vars_with_env() {
        let _guard = SECRET_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("TOOLCLAD_SECRET_API_KEY", "test-key-123");
        let result = inject_template_vars("Bearer {_secret:api_key}").unwrap();
        std::env::remove_var("TOOLCLAD_SECRET_API_KEY");
        assert_eq!(result, "Bearer test-key-123");
    }

    /// An `[http]` manifest whose URL, a header and the body all echo the
    /// `target` argument, and whose Authorization header carries a secret.
    fn http_manifest() -> Manifest {
        let mut m = minimal_manifest();
        m.command = CommandDef::default();
        m.http = Some(HttpDef {
            method: "POST".to_string(),
            url: "{target}".to_string(),
            headers: HashMap::from([
                (
                    "Authorization".to_string(),
                    "Bearer {_secret:api_key}".to_string(),
                ),
                ("X-Echo".to_string(), "{target}".to_string()),
            ]),
            body_template: Some(r#"{"q":"{target}"}"#.to_string()),
            success_status: vec![],
            error_status: vec![],
        });
        m
    }

    #[test]
    fn test_http_secrets_expand_on_template_before_args() {
        let _guard = SECRET_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("TOOLCLAD_SECRET_API_KEY", "s3cr3t-value");
        let m = http_manifest();
        // Validation is bypassed on purpose: the `url` validator rejects `{`,
        // but the ordering must hold even for a value that got this far.
        let smuggle = "https://attacker.example/?k={_secret:api_key}";
        let validated = HashMap::from([("target".to_string(), smuggle.to_string())]);
        let built = build_http_request(&m, &validated);
        std::env::remove_var("TOOLCLAD_SECRET_API_KEY");
        let parts = built.unwrap();

        assert!(
            !parts.url.contains("s3cr3t-value"),
            "secret leaked into url: {}",
            parts.url
        );
        assert_eq!(parts.url, smuggle);
        let header = |name: &str| {
            parts
                .headers
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.clone())
                .unwrap_or_else(|| panic!("missing header {name}"))
        };
        // The manifest's own reference still expands...
        assert_eq!(header("Authorization"), "Bearer s3cr3t-value");
        // ...but an argument echoed into a header or the body stays literal.
        assert_eq!(header("X-Echo"), smuggle);
        let body = parts.body.unwrap();
        assert!(
            !body.contains("s3cr3t-value"),
            "secret leaked into body: {body}"
        );
        assert!(body.contains("{_secret:api_key}"), "{body}");
    }

    #[test]
    fn test_http_missing_template_secret_fails_before_args() {
        let _guard = SECRET_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("TOOLCLAD_SECRET_API_KEY");
        let m = http_manifest();
        let validated = HashMap::from([("target".to_string(), "https://example.com/".to_string())]);
        let err = build_http_request(&m, &validated).unwrap_err().to_string();
        assert!(err.contains("TOOLCLAD_SECRET_API_KEY"), "{err}");
    }

    #[test]
    fn test_execute_rejects_url_arg_carrying_secret_reference() {
        // End to end through `execute`: the `url` validator refuses the value
        // before any request is built, so nothing touches the network here.
        let mut m = http_manifest();
        m.http.as_mut().unwrap().headers.clear();
        m.args.get_mut("target").unwrap().type_name = "url".to_string();
        let args = HashMap::from([(
            "target".to_string(),
            "https://attacker.example/?k={_secret:api_key}".to_string(),
        )]);
        let err = execute(&m, &args).unwrap_err().to_string();
        assert!(err.contains("metacharacter"), "{err}");
    }

    #[test]
    fn test_inject_template_vars_missing_secret() {
        std::env::remove_var("TOOLCLAD_SECRET_MISSING");
        let result = inject_template_vars("token={_secret:missing}");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("TOOLCLAD_SECRET_MISSING"));
    }

    #[test]
    fn test_inject_template_vars_no_secrets() {
        let result = inject_template_vars("plain text with {normal} placeholders").unwrap();
        assert_eq!(result, "plain text with {normal} placeholders");
    }

    #[test]
    fn test_mcp_proxy_envelope() {
        use crate::types::McpProxyDef;

        let mut m = minimal_manifest();
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

    // ---- W1: tokenizer -------------------------------------------------

    #[test]
    fn test_tokenize_template_basic() {
        assert_eq!(
            tokenize_template("nmap {_scan_type_flags}  {target}").unwrap(),
            vec!["nmap", "{_scan_type_flags}", "{target}"]
        );
        assert_eq!(tokenize_template("").unwrap(), Vec::<String>::new());
        assert_eq!(tokenize_template("   ").unwrap(), Vec::<String>::new());
    }

    #[test]
    fn test_tokenize_template_quotes_and_escapes() {
        assert_eq!(
            tokenize_template(r#"curl -H 'X: y' -w "a b" c\ d"#).unwrap(),
            vec!["curl", "-H", "X: y", "-w", "a b", "c d"]
        );
        // Empty quoted string is a real (empty) token.
        assert_eq!(tokenize_template("echo ''").unwrap(), vec!["echo", ""]);
        // Backslash is literal inside single quotes.
        assert_eq!(
            tokenize_template(r"echo '\n'").unwrap(),
            vec!["echo", r"\n"]
        );
    }

    #[test]
    fn test_tokenize_template_rejects_placeholder_inside_quotes() {
        let err = tokenize_template("curl -H '{headers}' {url}")
            .unwrap_err()
            .to_string();
        assert!(err.contains("inside quotes"), "unexpected: {err}");
        assert!(err.contains("use exec = [...]"), "unexpected: {err}");
        assert!(tokenize_template(r#"curl -H "X: {value}""#).is_err());
    }

    #[test]
    fn test_tokenize_template_allows_brace_escape_inside_quotes() {
        assert_eq!(
            tokenize_template("curl -w '%{{http_code}}' {url}").unwrap(),
            vec!["curl", "-w", "%{{http_code}}", "{url}"]
        );
    }

    #[test]
    fn test_tokenize_template_rejects_unbalanced_quotes_and_trailing_backslash() {
        let err = tokenize_template("echo 'oops").unwrap_err().to_string();
        assert!(err.contains("unbalanced quote"), "unexpected: {err}");
        assert!(tokenize_template("echo \"oops").is_err());
        let err = tokenize_template("echo x\\").unwrap_err().to_string();
        assert!(err.contains("trailing backslash"), "unexpected: {err}");
    }

    #[test]
    fn test_placeholder_names_skip_escapes() {
        assert_eq!(placeholder_names("%{{http_code}}"), Vec::<String>::new());
        assert_eq!(placeholder_names("{a}-{{x}}-{b}"), vec!["a", "b"]);
        assert_eq!(exact_placeholder("{target}"), Some("target"));
        assert_eq!(exact_placeholder("x{target}"), None);
        assert_eq!(exact_placeholder("{{target}}"), None);
    }

    // ---- W1: substitution ----------------------------------------------

    fn exec_manifest(exec: &[&str]) -> Manifest {
        let mut m = minimal_manifest();
        m.command.template = None;
        m.command.exec = Some(exec.iter().map(|s| s.to_string()).collect());
        m.command.exec_was_declared = true;
        m
    }

    #[test]
    fn test_value_with_space_stays_one_argv_element() {
        let mut m = exec_manifest(&["echo", "--name", "{label}", "{target}"]);
        m.args.insert(
            "label".to_string(),
            ArgDef {
                type_name: "string".to_string(),
                allow_whitespace: true,
                ..Default::default()
            },
        );
        let args = HashMap::from([
            ("label".to_string(), "X: y -d @/etc/passwd".to_string()),
            ("target".to_string(), "10.0.1.1".to_string()),
        ]);
        let argv = build_command_argv(&m, &args).unwrap();
        assert_eq!(argv.len(), 4, "argv: {argv:?}");
        assert_eq!(
            argv,
            vec!["echo", "--name", "X: y -d @/etc/passwd", "10.0.1.1"]
        );
    }

    #[test]
    fn test_empty_sole_placeholder_is_dropped() {
        let mut m = exec_manifest(&["echo", "{extra}", "--x={extra}", "{target}"]);
        m.args.insert(
            "extra".to_string(),
            ArgDef {
                type_name: "string".to_string(),
                default: Some(toml::Value::String(String::new())),
                ..Default::default()
            },
        );
        let args = HashMap::from([("target".to_string(), "10.0.1.1".to_string())]);
        let argv = build_command_argv(&m, &args).unwrap();
        // `{extra}` alone vanishes; `--x={extra}` keeps its literal text.
        assert_eq!(argv, vec!["echo", "--x=", "10.0.1.1"]);
    }

    #[test]
    fn test_unresolved_placeholder_is_build_error() {
        let m = exec_manifest(&["echo", "{nope}"]);
        let args = HashMap::from([("target".to_string(), "10.0.1.1".to_string())]);
        let err = build_command_argv(&m, &args).unwrap_err().to_string();
        assert!(
            err.contains("unresolved placeholder '{nope}' in command"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn test_literal_brace_escape_in_exec() {
        let m = exec_manifest(&["echo", "-w", "%{{http_code}}", "{target}"]);
        let args = HashMap::from([("target".to_string(), "10.0.1.1".to_string())]);
        let argv = build_command_argv(&m, &args).unwrap();
        assert_eq!(argv, vec!["echo", "-w", "%{http_code}", "10.0.1.1"]);
    }

    #[test]
    fn test_mapping_splices_tokens_and_legacy_alias_removed() {
        let mut m = exec_manifest(&["echo", "{_scan_type_flags}", "{target}"]);
        m.args.insert(
            "scan_type".to_string(),
            ArgDef {
                type_name: "enum".to_string(),
                allowed: Some(vec!["ping".to_string(), "service".to_string()]),
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
        let args = HashMap::from([
            ("target".to_string(), "10.0.1.1".to_string()),
            ("scan_type".to_string(), "service".to_string()),
        ]);
        let argv = build_command_argv(&m, &args).unwrap();
        assert_eq!(argv, vec!["echo", "-sT", "-sV", "10.0.1.1"]);

        // The legacy `_<arg>` short alias no longer exists.
        m.command.exec = Some(vec![
            "echo".into(),
            "{_scan_type}".into(),
            "{target}".into(),
        ]);
        let err = build_command_argv(&m, &args).unwrap_err().to_string();
        assert!(
            err.contains("unresolved placeholder '{_scan_type}'"),
            "unexpected: {err}"
        );

        // A trusted var embedded in a larger token is refused, never joined.
        m.command.exec = Some(vec!["echo".into(), "--f={_scan_type_flags}".into()]);
        let err = build_command_argv(&m, &args).unwrap_err().to_string();
        assert!(err.contains("whole token"), "unexpected: {err}");

        // A value with no mapping entry is a build error, not a silent drop.
        m.command.exec = Some(vec!["echo".into(), "{_scan_type_flags}".into()]);
        let bad = HashMap::from([
            ("target".to_string(), "10.0.1.1".to_string()),
            ("scan_type".to_string(), "stealth".to_string()),
        ]);
        let err = build_command_argv(&m, &bad).unwrap_err().to_string();
        assert!(err.contains("no mapping"), "unexpected: {err}");
    }

    #[test]
    fn test_conditional_tokens_substituted_individually() {
        let mut m = exec_manifest(&["echo", "{_header_flags}", "{target}"]);
        m.args.insert(
            "headers".to_string(),
            ArgDef {
                type_name: "string".to_string(),
                allow_whitespace: true,
                default: Some(toml::Value::String(String::new())),
                ..Default::default()
            },
        );
        m.command.conditionals = Some(HashMap::from([(
            "header_flags".to_string(),
            ConditionalDef {
                when: "headers != ''".to_string(),
                template: "-H {headers}".to_string(),
                tokens: Vec::new(),
            },
        )]));

        let args = HashMap::from([
            ("target".to_string(), "10.0.1.1".to_string()),
            ("headers".to_string(), "X-Trace: abc".to_string()),
        ]);
        let argv = build_command_argv(&m, &args).unwrap();
        assert_eq!(argv, vec!["echo", "-H", "X-Trace: abc", "10.0.1.1"]);

        // Condition false: the conditional contributes nothing.
        let args = HashMap::from([("target".to_string(), "10.0.1.1".to_string())]);
        let argv = build_command_argv(&m, &args).unwrap();
        assert_eq!(argv, vec!["echo", "10.0.1.1"]);
    }

    #[test]
    fn test_end_of_options_inserted_before_first_user_arg() {
        let mut m = exec_manifest(&["echo", "-v", "{_scan_type_flags}", "{target}", "{extra}"]);
        m.command.end_of_options = Some("--".to_string());
        m.args.insert(
            "scan_type".to_string(),
            ArgDef {
                type_name: "enum".to_string(),
                allowed: Some(vec!["ping".to_string()]),
                ..Default::default()
            },
        );
        m.args.insert(
            "extra".to_string(),
            ArgDef {
                type_name: "string".to_string(),
                default: Some(toml::Value::String(String::new())),
                ..Default::default()
            },
        );
        m.command.mappings = Some(HashMap::from([(
            "scan_type".to_string(),
            HashMap::from([("ping".to_string(), "-sn -PE".to_string())]),
        )]));
        let args = HashMap::from([
            ("target".to_string(), "10.0.1.1".to_string()),
            ("scan_type".to_string(), "ping".to_string()),
            ("extra".to_string(), "more".to_string()),
        ]);
        let argv = build_command_argv(&m, &args).unwrap();
        // `--` lands before the first user-arg token, not before mapping
        // output, and is inserted exactly once.
        assert_eq!(
            argv,
            vec!["echo", "-v", "-sn", "-PE", "--", "10.0.1.1", "more"]
        );

        // No user-arg-only token: nothing inserted.
        m.command.exec = Some(vec!["echo".into(), "{_scan_type_flags}".into()]);
        let argv = build_command_argv(&m, &args).unwrap();
        assert_eq!(argv, vec!["echo", "-sn", "-PE"]);

        // Anything but "--" is refused.
        m.command.end_of_options = Some("-".to_string());
        assert!(build_command_argv(&m, &args).is_err());
    }

    #[test]
    fn test_injected_vars_cannot_be_shadowed_by_args() {
        let m = exec_manifest(&["echo", "{_scan_id}", "{target}"]);
        let args = HashMap::from([
            ("target".to_string(), "10.0.1.1".to_string()),
            ("_scan_id".to_string(), "forged".to_string()),
        ]);
        let argv = build_command_argv(&m, &args).unwrap();
        assert_ne!(argv[1], "forged");
        assert_eq!(argv[2], "10.0.1.1");
    }

    #[test]
    fn test_executor_hatch_takes_precedence_and_is_strict() {
        // executor + declared exec + allow_whitespace: the executor wins, and
        // its validation is strict, so the spaced value is refused.
        let mut m = exec_manifest(&["echo", "{label}", "{target}"]);
        m.command.executor = Some("/usr/bin/true".to_string());
        m.args.insert(
            "label".to_string(),
            ArgDef {
                type_name: "string".to_string(),
                allow_whitespace: true,
                ..Default::default()
            },
        );
        let args = HashMap::from([
            ("label".to_string(), "a b".to_string()),
            ("target".to_string(), "10.0.1.1".to_string()),
        ]);
        let err = dry_run(&m, &args).unwrap_err().to_string();
        assert!(err.contains("whitespace"), "unexpected: {err}");

        let ok = HashMap::from([
            ("label".to_string(), "ab".to_string()),
            ("target".to_string(), "10.0.1.1".to_string()),
        ]);
        let dry = dry_run(&m, &ok).unwrap();
        assert_eq!(dry.command, "/usr/bin/true (custom executor)");
    }

    #[test]
    fn test_template_mode_rejects_whitespace_even_with_allow_whitespace() {
        // A manifest built from a template (not a declared exec) is strict:
        // the executor passes exec_mode = false, so the value is refused.
        let mut m = minimal_manifest();
        m.command.template = Some("echo {label} {target}".to_string());
        m.args.insert(
            "label".to_string(),
            ArgDef {
                type_name: "string".to_string(),
                allow_whitespace: true,
                ..Default::default()
            },
        );
        assert!(!m.command.exec_was_declared);
        let args = HashMap::from([
            ("label".to_string(), "a b".to_string()),
            ("target".to_string(), "10.0.1.1".to_string()),
        ]);
        let err = dry_run(&m, &args).unwrap_err().to_string();
        assert!(err.contains("whitespace"), "unexpected: {err}");
    }
}
