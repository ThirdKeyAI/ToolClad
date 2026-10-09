use crate::scope::ScopeDef;
use crate::types::{ConditionalDef, EvidenceEnvelope, Manifest, ToolCladError, ToolLimits};
use crate::validator::validate_arg_in;
use regex::Regex;
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{mpsc, Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::process::CommandExt;

/// Where `{_secret:name}` values come from for one call: the file named by
/// `TOOLCLAD_SECRETS_FILE` (read at most once, on first use) wins over the
/// `TOOLCLAD_SECRET_<NAME>` environment variable.
#[derive(Default)]
struct SecretSource {
    file: Option<Option<HashMap<String, String>>>,
}

impl SecretSource {
    fn lookup(&mut self, name: &str) -> Result<String, ToolCladError> {
        if self.file.is_none() {
            self.file = Some(load_secrets_file()?);
        }
        if let Some(Some(map)) = &self.file {
            if let Some(v) = map.get(name) {
                return Ok(v.clone());
            }
        }
        let env_key = format!("TOOLCLAD_SECRET_{}", name.to_uppercase());
        std::env::var(&env_key).map_err(|_| {
            ToolCladError::ExecutionError(format!("Secret '{}' not found (set {})", name, env_key))
        })
    }
}

/// Read `TOOLCLAD_SECRETS_FILE` (top-level `name = "value"` TOML pairs), or
/// `None` when it is unset. A file readable by group or others is refused:
/// that check is what makes the file better than an environment variable.
fn load_secrets_file() -> Result<Option<HashMap<String, String>>, ToolCladError> {
    let Some(path) = std::env::var_os("TOOLCLAD_SECRETS_FILE") else {
        return Ok(None);
    };
    let shown = path.to_string_lossy().to_string();
    let err = |msg: String| ToolCladError::ExecutionError(msg);
    let mut file = std::fs::File::open(&path).map_err(|e| {
        err(format!(
            "TOOLCLAD_SECRETS_FILE '{shown}' cannot be opened: {e}"
        ))
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = file
            .metadata()
            .map_err(|e| err(format!("TOOLCLAD_SECRETS_FILE '{shown}': {e}")))?
            .permissions()
            .mode()
            & 0o777;
        if mode & 0o077 != 0 {
            return Err(err(format!(
                "TOOLCLAD_SECRETS_FILE '{shown}' is readable by group or others (mode {mode:04o}); chmod 600 it"
            )));
        }
    }
    let mut text = String::new();
    std::io::Read::read_to_string(&mut file, &mut text).map_err(|e| {
        err(format!(
            "TOOLCLAD_SECRETS_FILE '{shown}' cannot be read: {e}"
        ))
    })?;
    let table: toml::Table = toml::from_str(&text).map_err(|e| {
        err(format!(
            "TOOLCLAD_SECRETS_FILE '{shown}' is not valid TOML: {e}"
        ))
    })?;
    let mut out = HashMap::with_capacity(table.len());
    for (k, v) in table {
        let toml::Value::String(v) = v else {
            return Err(err(format!(
                "TOOLCLAD_SECRETS_FILE '{shown}': value for '{k}' must be a string"
            )));
        };
        out.insert(k, v);
    }
    Ok(Some(out))
}

static SECRET_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\{_secret:([a-zA-Z0-9_]+)\}").unwrap());

/// Replace each `{_secret:name}` with its value from `secrets`.
fn inject_template_vars(
    template: &str,
    secrets: &mut SecretSource,
) -> Result<String, ToolCladError> {
    let mut result = template.to_string();
    for cap in SECRET_RE.captures_iter(template) {
        let val = secrets.lookup(&cap[1])?;
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

/// The literal host (authority minus userinfo and port) of a manifest
/// `http.url`. The scheme and host must not contain a placeholder: the host
/// is the SSRF boundary and stays manifest-controlled.
pub fn http_url_literal_host(url: &str) -> Result<String, ToolCladError> {
    let interp_err = || {
        ToolCladError::ManifestError(
            "http.url may not interpolate into the scheme or host".to_string(),
        )
    };
    let Some((scheme, rest)) = url.split_once("://") else {
        if url
            .split(['/', '?', '#'])
            .next()
            .unwrap_or("")
            .contains('{')
        {
            return Err(interp_err());
        }
        return Err(ToolCladError::ManifestError(format!(
            "http.url '{url}' must be an absolute http or https URL"
        )));
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if scheme.contains('{') || authority.contains('{') || authority.contains('}') {
        return Err(interp_err());
    }
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return Err(ToolCladError::ManifestError(format!(
            "http.url scheme '{scheme}' is not allowed (use http or https)"
        )));
    }
    let hostport = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = if hostport.starts_with('[') {
        hostport
            .find(']')
            .map_or(hostport, |i| &hostport[..=i])
            .to_string()
    } else {
        hostport
            .rsplit_once(':')
            .map_or(hostport, |(h, _)| h)
            .to_string()
    };
    if host.is_empty() {
        return Err(ToolCladError::ManifestError(format!(
            "http.url '{url}' has no host"
        )));
    }
    Ok(host)
}

/// Refuse an HTTP header name that is not an RFC 9110 token.
pub fn check_header_name(name: &str) -> Result<(), ToolCladError> {
    let tchar = |b: u8| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b);
    if name.is_empty() || !name.bytes().all(tchar) {
        return Err(ToolCladError::ManifestError(format!(
            "http header name '{}' is not a valid token",
            name.escape_default()
        )));
    }
    Ok(())
}

/// Percent-encode every byte outside the RFC 3986 `unreserved` set, so an
/// interpolated value can never add a `/`, `?`, `#`, `&`, `=` or `%` to the
/// URL's structure. Used for both path and query positions.
pub fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for &b in value.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Matches a `{name}` argument placeholder in an HTTP template.
static HTTP_PLACEHOLDER_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\{(\w+)\}").unwrap());

/// Substitute validated arguments into `template` in one left-to-right pass
/// (a value is never rescanned for placeholders), passing each value through
/// `encode`. A placeholder that names no validated argument is left as
/// written.
fn interpolate(
    template: &str,
    validated: &HashMap<String, String>,
    encode: impl Fn(&str) -> String,
) -> String {
    HTTP_PLACEHOLDER_RE
        .replace_all(template, |caps: &regex::Captures| {
            match validated.get(&caps[1]) {
                Some(v) => encode(v),
                None => caps[0].to_string(),
            }
        })
        .into_owned()
}

/// Build the URL, headers and body of an HTTP backend request.
///
/// Order matters: `{_secret:name}` references are expanded on the manifest
/// template FIRST, then validated arguments are interpolated. A value that
/// smuggles a `{_secret:…}` reference therefore lands after secret expansion
/// has already happened and stays a literal: it can never pull a secret into
/// an attacker-chosen URL, header or body. The `url` validator independently
/// rejects `{` and `}`; this ordering does not rely on that.
///
/// URL values are percent-encoded (path and query alike), header values are
/// refused when they contain CR, LF or NUL after interpolation, and body
/// values are JSON-escaped.
fn build_http_request(
    manifest: &Manifest,
    validated: &HashMap<String, String>,
) -> Result<HttpRequestParts, ToolCladError> {
    let http = manifest.http.as_ref().ok_or_else(|| {
        ToolCladError::ExecutionError("manifest has no [http] section".to_string())
    })?;
    // Also enforced at load; repeated for a manifest built in code.
    http_url_literal_host(&http.url)?;
    let mut secrets = SecretSource::default();

    // URL: secrets on the template, then percent-encoded arguments.
    let url_tmpl = inject_template_vars(&http.url, &mut secrets)?;
    let url = interpolate(&url_tmpl, validated, percent_encode);

    // Headers: same order for every value.
    let mut headers: Vec<(String, String)> = Vec::with_capacity(http.headers.len());
    for (hk, hv) in &http.headers {
        check_header_name(hk)?;
        let tmpl = inject_template_vars(hv, &mut secrets)?;
        let val = interpolate(&tmpl, validated, |v| v.to_string());
        if val.contains(['\r', '\n', '\0']) {
            return Err(ToolCladError::ValidationError(format!(
                "http header '{hk}' contains a CR, LF or NUL after interpolation"
            )));
        }
        headers.push((hk.clone(), val));
    }

    // Body: secrets on the template, then JSON-escaped arguments.
    let body = match http.body_template {
        Some(ref body_tmpl) => {
            let tmpl = inject_template_vars(body_tmpl, &mut secrets)?;
            Some(interpolate(&tmpl, validated, |v| {
                let quoted = serde_json::to_string(v).unwrap_or_default();
                quoted[1..quoted.len() - 1].to_string()
            }))
        }
        None => None,
    };

    Ok(HttpRequestParts { url, headers, body })
}

/// Execute an HTTP backend tool, returning an evidence envelope.
///
/// Redirects are never followed (an allowed host could otherwise 302 to an
/// internal address); a 3xx is reported as `redirect_blocked`. The body is
/// read up to `[output] max_bytes`.
fn execute_http(
    manifest: &Manifest,
    validated: &HashMap<String, String>,
) -> Result<EvidenceEnvelope, ToolCladError> {
    let http = manifest.http.as_ref().unwrap();
    let scan_id = new_scan_id();
    let timestamp = chrono::Utc::now().to_rfc3339();
    let start = Instant::now();

    let HttpRequestParts { url, headers, body } = build_http_request(manifest, validated)?;

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(
            manifest.tool.timeout_seconds,
        ))
        .redirect(reqwest::redirect::Policy::none())
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
    if let Some(b) = body {
        req = req.body(b);
    }

    let resp = req
        .send()
        .map_err(|e| ToolCladError::ExecutionError(format!("HTTP request failed: {e}")))?;

    let status_code = resp.status().as_u16();
    let location = resp
        .headers()
        .get(reqwest::header::LOCATION)
        .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned());
    let max = max_output_bytes(manifest);
    let mut bytes = Vec::new();
    resp.take(max as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| ToolCladError::ExecutionError(format!("failed to read response: {e}")))?;
    let truncated = bytes.len() > max;
    let resp_body = capped_text(bytes, max);

    let duration_ms = start.elapsed().as_millis() as u64;

    let output_hash = {
        let mut hasher = Sha256::new();
        hasher.update(resp_body.as_bytes());
        format!("sha256:{:x}", hasher.finalize())
    };
    let command = format!("{} {}", method_upper, http.url);

    if (300..400).contains(&status_code) {
        return Ok(EvidenceEnvelope {
            status: "redirect_blocked".to_string(),
            scan_id,
            tool: manifest.tool.name.clone(),
            command,
            duration_ms,
            timestamp,
            output_file: None,
            output_hash: Some(output_hash),
            exit_code: 1,
            stderr: String::new(),
            results: serde_json::json!({
                "location": location,
                "raw_output": resp_body,
                "http_status": status_code,
                "http_method": method_upper,
            }),
            output_truncated: truncated,
        });
    }

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

    let results = serde_json::json!({
        "raw_output": resp_body,
        "http_status": status_code,
        "http_method": method_upper,
    });

    Ok(EvidenceEnvelope {
        status: status_str,
        scan_id,
        tool: manifest.tool.name.clone(),
        command,
        duration_ms,
        timestamp,
        output_file: None,
        output_hash: Some(output_hash),
        exit_code: if is_success { 0 } else { 1 },
        stderr: String::new(),
        results,
        output_truncated: truncated,
    })
}

/// Execute an MCP proxy backend tool, returning a delegated evidence envelope.
fn execute_mcp_proxy(
    manifest: &Manifest,
    validated: &HashMap<String, String>,
) -> Result<EvidenceEnvelope, ToolCladError> {
    let mcp = manifest.mcp.as_ref().unwrap();
    let scan_id = new_scan_id();
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
        output_truncated: false,
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
    let paths = EvidencePaths::new(manifest, new_scan_id());
    build_argv_with(manifest, args, &paths)
}

/// [`build_command_argv`] with the injected evidence variables of one
/// invocation, so the argv and the directories created for it agree.
fn build_argv_with(
    manifest: &Manifest,
    args: &HashMap<String, String>,
    paths: &EvidencePaths,
) -> Result<Vec<String>, ToolCladError> {
    let tokens = compiled_exec(manifest)?;
    let resolved = resolve_vars(manifest, args, paths)?;
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
    paths: &EvidencePaths,
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
    vars.insert("_scan_id".to_string(), paths.scan_id.clone());
    vars.insert(
        "_evidence_dir".to_string(),
        path_string(&paths.evidence_dir),
    );
    vars.insert("_output_file".to_string(), path_string(&paths.output_file));

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
/// Input containing a `<!DOCTYPE` or `<!ENTITY` declaration is refused.
fn parse_xml_to_json(xml: &str) -> Result<serde_json::Value, ToolCladError> {
    let xml = xml.trim();
    if xml.is_empty() {
        return Ok(serde_json::json!({"raw_output": ""}));
    }
    // No DTDs: entity declarations are how entity-expansion attacks start, and
    // no tool output needs them.
    let lower = xml.to_ascii_lowercase();
    if lower.contains("<!doctype") || lower.contains("<!entity") {
        return Err(ToolCladError::ExecutionError(XML_DTD_REFUSED.to_string()));
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

/// The XML refusal message, shared by every runtime.
pub const XML_DTD_REFUSED: &str =
    "XML output contains a DOCTYPE or ENTITY declaration; refusing to parse";

/// `[output] max_bytes`, or the 8 MiB default when there is no `[output]`.
fn max_output_bytes(manifest: &Manifest) -> usize {
    manifest.output.as_ref().map_or(8_388_608, |o| o.max_bytes) as usize
}

/// Decode captured bytes, trimmed to at most `max` bytes on a character
/// boundary (lossy decoding can lengthen a cut multibyte sequence).
fn capped_text(mut bytes: Vec<u8>, max: usize) -> String {
    bytes.truncate(max);
    let mut text = String::from_utf8_lossy(&bytes).into_owned();
    if text.len() > max {
        let mut end = max;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
    }
    text
}

/// Parse `raw` and check it against `[output.schema]`, failing closed.
///
/// Returns the status override (`parse_error` / `schema_error`, or `None`)
/// and the results: the parsed object, or
/// `{"parse_error"|"schema_error": "<message>", "raw_output": "<raw>"}`.
fn checked_results(manifest: &Manifest, raw: &str) -> (Option<&'static str>, serde_json::Value) {
    let parsed = match parse_output(manifest, raw) {
        Ok(v) => v,
        Err(msg) => {
            return (
                Some("parse_error"),
                serde_json::json!({ "parse_error": msg, "raw_output": raw }),
            )
        }
    };
    let default_schema = serde_json::json!({"type": "object"});
    let schema = manifest
        .output
        .as_ref()
        .map_or(&default_schema, |o| &o.schema);
    match crate::schema::validate(schema, &parsed) {
        Ok(()) => (None, parsed),
        Err(msg) => (
            Some("schema_error"),
            serde_json::json!({ "schema_error": msg, "raw_output": raw }),
        ),
    }
}

/// Parse raw command output according to the manifest's output format/parser.
///
/// The result is always a JSON object: `builtin:jsonl` and `builtin:csv`
/// produce `{"parsed_output": [...]}`, `builtin:text` produces
/// `{"raw_output": "..."}`, and `builtin:json` passes an object through and
/// wraps anything else as `{"parsed_output": ...}`. An error is the parse
/// failure message.
fn parse_output(manifest: &Manifest, raw: &str) -> Result<serde_json::Value, String> {
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
        "builtin:json" => {
            let v: serde_json::Value =
                serde_json::from_str(raw).map_err(|e| format!("JSON parse failed: {e}"))?;
            Ok(if v.is_object() {
                v
            } else {
                serde_json::json!({ "parsed_output": v })
            })
        }
        "builtin:jsonl" => {
            let lines: Vec<serde_json::Value> = raw
                .lines()
                .filter(|l| !l.trim().is_empty())
                .map(serde_json::from_str)
                .collect::<Result<_, _>>()
                .map_err(|e| format!("JSONL parse failed: {e}"))?;
            Ok(serde_json::json!({ "parsed_output": lines }))
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
                Ok(serde_json::json!({ "parsed_output": rows }))
            } else {
                Ok(serde_json::json!({ "parsed_output": [] }))
            }
        }
        "builtin:xml" => parse_xml_to_json(raw).map_err(|e| match e {
            ToolCladError::ExecutionError(m) => m,
            other => other.to_string(),
        }),
        "builtin:text" => Ok(serde_json::json!({"raw_output": raw})),
        // Refused at load; repeated for a manifest built in code.
        other => Err(format!(
            "custom output parsers are not supported by the reference runtimes (parser = \"{other}\")"
        )),
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

/// The policy gate's verdict on one call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateDecision {
    Allow,
    Deny(String),
}

/// The policy gate seam: consulted after argument validation (it sees the
/// cleaned values) and before anything is spawned, any HTTP request is made
/// or any MCP envelope is built. A denial fails the call with
/// [`ToolCladError::PolicyDenied`] (`policy gate denied: <reason>`).
///
/// ToolClad does not evaluate policy. `[tool.cedar]` declares the resource
/// and action for an embedding runtime's Cedar evaluator; wiring that
/// evaluator into a gate passed to [`execute_with_gate`] is the embedder's
/// job.
pub type Gate<'a> = dyn Fn(&Manifest, &HashMap<String, String>) -> GateDecision + 'a;

/// Deny-by-default gate: refuses a manifest that sets `human_approval = true`
/// or has `risk_tier` `high` or `critical`; allows everything else.
pub fn default_gate(manifest: &Manifest, _validated: &HashMap<String, String>) -> GateDecision {
    if manifest.tool.human_approval {
        return GateDecision::Deny(
            "manifest requires human approval (human_approval = true)".to_string(),
        );
    }
    let tier = manifest.tool.risk_tier.as_str();
    if tier == "high" || tier == "critical" {
        return GateDecision::Deny(format!("risk_tier '{tier}' requires explicit approval"));
    }
    GateDecision::Allow
}

/// Allow-all gate, for a caller that has obtained approval itself.
pub fn approve_gate(_manifest: &Manifest, _validated: &HashMap<String, String>) -> GateDecision {
    GateDecision::Allow
}

/// Validate every declared argument (defaults included) for a call, refusing
/// undeclared names and missing required values. One routine for every
/// backend.
fn validate_call_args(
    manifest: &Manifest,
    args: &HashMap<String, String>,
) -> Result<HashMap<String, String>, ToolCladError> {
    check_declared_args(manifest, args)?;

    // `allow_whitespace` is honored only when the manifest declared `exec`
    // directly; a compiled template stays strict, and so does the `executor`
    // escape hatch (it takes precedence over exec/template and its argument
    // handling is opaque to us). A default is validated like a supplied value
    // (it was type-checked at load; the scope check can only run here).
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
    Ok(validated)
}

/// The declared, unexpanded command for the evidence envelope: the `exec`
/// array as written joined by single spaces, or a legacy `template` as
/// written. Executor-injected paths and argument values never appear.
fn declared_command(manifest: &Manifest) -> String {
    let cmd = &manifest.command;
    if !cmd.exec_was_declared {
        if let Some(ref t) = cmd.template {
            return t.clone();
        }
    }
    cmd.exec.as_ref().map(|e| e.join(" ")).unwrap_or_default()
}

/// Validate, consult [`default_gate`], execute, and return an evidence
/// envelope. A `human_approval` or high/critical-risk manifest is denied;
/// use [`execute_approved`] or [`execute_with_gate`] once approval exists.
pub fn execute(
    manifest: &Manifest,
    args: &HashMap<String, String>,
) -> Result<EvidenceEnvelope, ToolCladError> {
    execute_with_gate(manifest, args, &default_gate)
}

/// [`execute`] with the allow-all gate.
pub fn execute_approved(
    manifest: &Manifest,
    args: &HashMap<String, String>,
) -> Result<EvidenceEnvelope, ToolCladError> {
    execute_with_gate(manifest, args, &approve_gate)
}

/// Validate all arguments, consult `gate`, then build the command, execute
/// it, and return an evidence envelope.
pub fn execute_with_gate(
    manifest: &Manifest,
    args: &HashMap<String, String>,
    gate: &Gate<'_>,
) -> Result<EvidenceEnvelope, ToolCladError> {
    // Phase 1: Validate all arguments.
    let validated = validate_call_args(manifest, args)?;

    // Phase 1b: The policy gate, before any backend acts.
    if let GateDecision::Deny(reason) = gate(manifest, &validated) {
        return Err(ToolCladError::PolicyDenied(reason));
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

    let paths = EvidencePaths::new(manifest, new_scan_id());
    let timestamp = chrono::Utc::now().to_rfc3339();

    // Phase 2: Build the command, then prepare the evidence directories and
    // the per-invocation scratch directory the child runs in.
    let (program, argv_rest, extra_env, cmd_string) =
        if let Some(ref executor_path) = manifest.command.executor {
            // Escape hatch: run custom executor with env vars.
            // SECURITY: Args are passed as env vars, not interpolated into shell command.
            let mut env: Vec<(String, String)> = validated
                .iter()
                .map(|(k, v)| (format!("TOOLCLAD_ARG_{}", k.to_uppercase()), v.clone()))
                .collect();
            env.push(("TOOLCLAD_SCAN_ID".to_string(), paths.scan_id.clone()));
            env.push(("TOOLCLAD_TOOL_NAME".to_string(), manifest.tool.name.clone()));
            env.push((
                "TOOLCLAD_EVIDENCE_DIR".to_string(),
                path_string(&paths.evidence_dir),
            ));
            env.push((
                "TOOLCLAD_OUTPUT_DIR".to_string(),
                path_string(&paths.output_dir),
            ));
            let display = format!("{executor_path} (custom executor)");
            (executor_path.clone(), Vec::new(), env, display)
        } else {
            // Array-based command construction maps directly to execve. A
            // `template` was tokenized at load into the same array, so there is
            // no string→split round-trip anywhere on the spawn path.
            let mut argv = build_argv_with(manifest, &validated, &paths)?;
            let display = declared_command(manifest);
            let rest = argv.split_off(1);
            (argv.remove(0), rest, Vec::new(), display)
        };
    let program = resolve_program(&program)?;

    create_private_dir(&paths.evidence_dir, true)?;
    create_private_dir(&paths.output_dir, true)?;
    let work_dir = paths.work_dir();
    create_private_dir(&work_dir, false)?;

    let mut cmd = Command::new(&program);
    cmd.args(&argv_rest).current_dir(&work_dir);
    apply_child_env(&mut cmd, &extra_env);
    #[cfg(unix)]
    apply_child_limits(&mut cmd, manifest.tool.limits.as_ref());

    let start = Instant::now();
    let run = run_command_with_timeout(
        cmd,
        manifest.tool.timeout_seconds,
        max_output_bytes(manifest),
    );
    // Remove the scratch directory only when the tool left nothing in it: a
    // file there is evidence.
    let _ = std::fs::remove_dir(&work_dir);
    let RunOutput {
        stdout: stdout_text,
        stderr: stderr_text,
        exit_code,
        status: mut status_str,
        timed_out,
        truncated,
    } = run?;
    let scan_id = paths.scan_id;

    let duration_ms = start.elapsed().as_millis() as u64;

    // Phase 3: Hash output for evidence.
    let output_hash = {
        let mut hasher = Sha256::new();
        hasher.update(stdout_text.as_bytes());
        format!("sha256:{:x}", hasher.finalize())
    };

    // Phase 3b: Parse and schema-check the output, failing closed. A timed-out
    // run's output is partial, so it is returned raw rather than parsed. A
    // failed run keeps its error status; its results are still checked.
    let results = if timed_out {
        serde_json::json!({"raw_output": stdout_text})
    } else {
        let (override_status, results) = checked_results(manifest, &stdout_text);
        if let Some(st) = override_status {
            if status_str == "success" {
                status_str = st.to_string();
            }
        }
        results
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
        output_truncated: truncated,
    })
}

/// The fixed `PATH` every child gets and `argv[0]` is resolved against. Never
/// inherited: an inherited `PATH` is how a renamed binary earlier in the path
/// wins.
pub const CHILD_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// Parent variables copied into the child, only when set.
const CHILD_ENV_PASSTHROUGH: &[&str] = &["HOME", "LANG", "LC_ALL", "TZ", "TERM"];

/// Default `SIGTERM` → `SIGKILL` grace period, overridable with
/// `TOOLCLAD_KILL_GRACE_MS`.
const DEFAULT_KILL_GRACE_MS: u64 = 2000;

/// A fresh scan id: `<unix_seconds>-<32 hex chars>` (128 random bits from the
/// OS CSPRNG via `uuid`).
fn new_scan_id() -> String {
    format!(
        "{}-{}",
        chrono::Utc::now().timestamp(),
        uuid::Uuid::new_v4().simple()
    )
}

fn path_string(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

/// The evidence locations of one invocation.
#[derive(Debug, Clone)]
struct EvidencePaths {
    scan_id: String,
    /// `TOOLCLAD_EVIDENCE_DIR`, else `<tmpdir>/toolclad-evidence`.
    evidence_dir: PathBuf,
    /// `[tool.evidence] output_dir` with `{evidence_dir}`/`{scan_id}`
    /// substituted, else `<evidence_dir>/<scan_id>-<tool_name>`.
    output_dir: PathBuf,
    /// `<output_dir>/scan.<ext>`, `ext` from `output.format`.
    output_file: PathBuf,
}

impl EvidencePaths {
    fn new(manifest: &Manifest, scan_id: String) -> Self {
        let evidence_dir = std::env::var_os("TOOLCLAD_EVIDENCE_DIR")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| std::env::temp_dir().join("toolclad-evidence"));
        let output_dir = match manifest.tool.evidence.as_ref() {
            Some(ev) if !ev.output_dir.is_empty() => PathBuf::from(
                ev.output_dir
                    .replace("{evidence_dir}", &path_string(&evidence_dir))
                    .replace("{scan_id}", &scan_id),
            ),
            _ => evidence_dir.join(format!("{scan_id}-{}", manifest.tool.name)),
        };
        let ext = match manifest.output.as_ref().map(|o| o.format.as_str()) {
            Some("xml") => "xml",
            Some("json") => "json",
            Some("csv") => "csv",
            Some("jsonl") => "jsonl",
            _ => "txt",
        };
        let output_file = output_dir.join(format!("scan.{ext}"));
        Self {
            scan_id,
            evidence_dir,
            output_dir,
            output_file,
        }
    }

    /// The child's working directory: `<evidence_dir>/<scan_id>-work`.
    fn work_dir(&self) -> PathBuf {
        self.evidence_dir.join(format!("{}-work", self.scan_id))
    }
}

/// Create a directory with mode 0700 and refuse a symlink in its place.
///
/// `existing_ok` allows a directory that is already there (the evidence root,
/// a fixed `output_dir`); otherwise the directory must be new (the scratch
/// directory). The leaf is checked with `lstat`, so a symlink pre-planted in
/// a shared temp directory cannot redirect the tool's writes.
fn create_private_dir(path: &Path, existing_ok: bool) -> Result<(), ToolCladError> {
    let shown = path.display();
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(existing_ok);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path).map_err(|e| {
        ToolCladError::ExecutionError(format!("cannot create directory '{shown}': {e}"))
    })?;
    let meta = std::fs::symlink_metadata(path).map_err(|e| {
        ToolCladError::ExecutionError(format!("cannot inspect directory '{shown}': {e}"))
    })?;
    if !meta.file_type().is_dir() {
        return Err(ToolCladError::ExecutionError(format!(
            "refusing evidence directory '{shown}': it is a symlink or not a directory"
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: geteuid has no preconditions and cannot fail.
        let euid = unsafe { libc::geteuid() };
        if meta.uid() != euid {
            return Err(ToolCladError::ExecutionError(format!(
                "refusing evidence directory '{shown}': owned by uid {}, not the runtime's uid {euid}",
                meta.uid()
            )));
        }
    }
    Ok(())
}

/// Resolve `argv[0]` to the file that will be executed: as given when it
/// contains a `/`, otherwise the first executable regular file of that name
/// on [`CHILD_PATH`].
fn resolve_program(name: &str) -> Result<PathBuf, ToolCladError> {
    if name.contains('/') {
        return Ok(PathBuf::from(name));
    }
    if !name.is_empty() {
        for dir in CHILD_PATH.split(':') {
            let candidate = Path::new(dir).join(name);
            if let Ok(meta) = std::fs::metadata(&candidate) {
                #[cfg(unix)]
                let executable = {
                    use std::os::unix::fs::PermissionsExt;
                    meta.permissions().mode() & 0o111 != 0
                };
                #[cfg(not(unix))]
                let executable = true;
                if meta.is_file() && executable {
                    return Ok(candidate);
                }
            }
        }
    }
    Err(ToolCladError::ExecutionError(format!(
        "binary '{name}' not found on PATH ({CHILD_PATH})"
    )))
}

/// Clear the child's environment and rebuild it from the allowlist: the fixed
/// `PATH`, `HOME`/`LANG`/`LC_ALL`/`TZ`/`TERM` when set in the parent, and
/// `extra` (the executor hatch's `TOOLCLAD_*` variables). A
/// `TOOLCLAD_SECRET_*` name is dropped even if it reaches `extra`, so no edit
/// to the allowlist can hand a secret to a child.
fn apply_child_env(cmd: &mut Command, extra: &[(String, String)]) {
    cmd.env_clear();
    for (k, v) in child_env(extra) {
        cmd.env(k, v);
    }
}

fn child_env(extra: &[(String, String)]) -> Vec<(String, std::ffi::OsString)> {
    let mut env = vec![("PATH".to_string(), CHILD_PATH.into())];
    for name in CHILD_ENV_PASSTHROUGH {
        if let Some(v) = std::env::var_os(name) {
            env.push((name.to_string(), v));
        }
    }
    for (k, v) in extra {
        env.push((k.clone(), v.into()));
    }
    env.retain(|(k, _)| !k.starts_with("TOOLCLAD_SECRET_"));
    env
}

/// The rlimits applied to the child: core dumps off, `FSIZE` 1 GiB, `NOFILE`
/// 1024 (each overridable in `[tool.limits]`), plus `NPROC`, `AS` and `CPU`
/// only when declared. `RLIMIT_AS` stays off by default because it breaks
/// tools that reserve large virtual mappings. `RLIMIT_NPROC` stays off by
/// default because Linux counts it against every task the *user* owns, not
/// the tool's own tree: on a busy host any fixed default stops a threaded
/// tool from creating its first thread.
#[cfg(unix)]
fn child_rlimits(limits: Option<&ToolLimits>) -> Vec<(RlimitResource, libc::rlim_t)> {
    let l = limits.cloned().unwrap_or_default();
    let mut out: Vec<(RlimitResource, libc::rlim_t)> = vec![
        (libc::RLIMIT_CORE, 0),
        (
            libc::RLIMIT_FSIZE,
            l.fsize_bytes.unwrap_or(1 << 30) as libc::rlim_t,
        ),
        (
            libc::RLIMIT_NOFILE,
            l.nofile.unwrap_or(1024) as libc::rlim_t,
        ),
    ];
    if let Some(v) = l.nproc {
        out.push((libc::RLIMIT_NPROC, v as libc::rlim_t));
    }
    if let Some(v) = l.address_space_bytes {
        out.push((libc::RLIMIT_AS, v as libc::rlim_t));
    }
    if let Some(v) = l.cpu_seconds {
        out.push((libc::RLIMIT_CPU, v as libc::rlim_t));
    }
    out
}

/// The rlimit resource type differs between libcs (`c_uint` on glibc,
/// `c_int` elsewhere); take it from the constants themselves.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
type RlimitResource = libc::__rlimit_resource_t;
#[cfg(all(unix, not(all(target_os = "linux", target_env = "gnu"))))]
type RlimitResource = libc::c_int;

/// Set umask 0077 and the rlimits in the child between `fork` and `exec`.
#[cfg(unix)]
fn apply_child_limits(cmd: &mut Command, limits: Option<&ToolLimits>) {
    let rlimits = child_rlimits(limits);
    // SAFETY: the closure runs in the forked child before exec, where only
    // async-signal-safe operations are allowed. It reads a Vec built before
    // the fork (no allocation) and makes only umask/getrlimit/setrlimit
    // system calls; an error is reported from errno without allocating.
    unsafe {
        cmd.pre_exec(move || {
            libc::umask(0o077);
            for &(resource, value) in &rlimits {
                let mut cur = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                if libc::getrlimit(resource, &mut cur) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                // Never try to raise the hard limit (that needs privilege).
                let v = value.min(cur.rlim_max);
                let new = libc::rlimit {
                    rlim_cur: v,
                    rlim_max: v,
                };
                if libc::setrlimit(resource, &new) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
}

/// `TOOLCLAD_KILL_GRACE_MS` as a non-negative integer, else the default.
fn kill_grace() -> Duration {
    let ms = std::env::var("TOOLCLAD_KILL_GRACE_MS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(DEFAULT_KILL_GRACE_MS);
    Duration::from_millis(ms)
}

/// The outcome of one spawned run.
#[derive(Debug)]
struct RunOutput {
    stdout: String,
    stderr: String,
    exit_code: i32,
    status: String,
    timed_out: bool,
    /// stdout or stderr exceeded the cap.
    truncated: bool,
}

/// One captured pipe: the bytes kept (at most the cap) and whether more
/// arrived.
#[derive(Default)]
struct Capture {
    bytes: Vec<u8>,
    truncated: bool,
}

/// Read a pipe into a shared buffer, keeping at most `max` bytes, so partial
/// output stays available even if the reader never finishes; signal `done`
/// at EOF. Past the cap the pipe is drained and discarded, so the child never
/// blocks on a full pipe.
fn spawn_reader<R: Read + Send + 'static>(
    pipe: Option<R>,
    done: mpsc::Sender<()>,
    max: usize,
) -> Arc<Mutex<Capture>> {
    let buf = Arc::new(Mutex::new(Capture::default()));
    let sink = Arc::clone(&buf);
    std::thread::spawn(move || {
        if let Some(mut pipe) = pipe {
            let mut limited = (&mut pipe).take(max as u64 + 1);
            let mut chunk = [0u8; 8192];
            loop {
                match limited.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => {
                        let mut cap = sink.lock().unwrap_or_else(|e| e.into_inner());
                        let room = max.saturating_sub(cap.bytes.len());
                        if n > room {
                            cap.truncated = true;
                        }
                        cap.bytes.extend_from_slice(&chunk[..n.min(room)]);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => break,
                }
            }
            let _ = std::io::copy(&mut pipe, &mut std::io::sink());
        }
        let _ = done.send(());
    });
    buf
}

/// The captured text (capped) and whether the pipe overflowed.
fn take_text(buf: &Arc<Mutex<Capture>>, max: usize) -> (String, bool) {
    let cap = std::mem::take(&mut *buf.lock().unwrap_or_else(|e| e.into_inner()));
    (capped_text(cap.bytes, max), cap.truncated)
}

#[cfg(unix)]
fn signal_group(pid: u32, sig: libc::c_int) {
    // SAFETY: killpg only sends a signal; the child was started with
    // `process_group(0)`, so its pid is its process-group id. An error (the
    // group is already gone) is harmless.
    unsafe {
        libc::killpg(pid as libc::pid_t, sig);
    }
}

/// Spawn `cmd` with stdin on `/dev/null`, capture stdout/stderr, and enforce
/// the deadline.
///
/// The child leads a new process group. On the deadline the group gets
/// `SIGTERM`, then `SIGKILL` once the grace period (`TOOLCLAD_KILL_GRACE_MS`)
/// passes, and the run is reported as `"timeout"` with exit code -1 and the
/// output captured so far. The deadline also covers the pipes: a background
/// process that keeps stdout open after the tool exits cannot hold the call.
fn run_command_with_timeout(
    mut cmd: Command,
    timeout_seconds: u64,
    max_bytes: usize,
) -> Result<RunOutput, ToolCladError> {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    // SECURITY: Create a new process group so we can kill all children on timeout.
    #[cfg(unix)]
    cmd.process_group(0);

    let mut child = cmd
        .spawn()
        .map_err(|e| ToolCladError::ExecutionError(format!("failed to spawn process: {e}")))?;
    let pid = child.id();
    let wait_err = |e: std::io::Error| ToolCladError::ExecutionError(format!("wait error: {e}"));

    // Read stdout/stderr in separate threads to avoid pipe buffer deadlock.
    let (done_tx, done_rx) = mpsc::channel();
    let stdout_buf = spawn_reader(child.stdout.take(), done_tx.clone(), max_bytes);
    let stderr_buf = spawn_reader(child.stderr.take(), done_tx, max_bytes);

    let deadline = Instant::now() + Duration::from_secs(timeout_seconds);
    let poll = Duration::from_millis(20);
    let mut status = None;
    let mut readers_done = 0;

    // Wait for the tool to exit and both pipes to close, up to the deadline.
    while Instant::now() < deadline {
        if status.is_none() {
            status = child.try_wait().map_err(wait_err)?;
        }
        while done_rx.try_recv().is_ok() {
            readers_done += 1;
        }
        if status.is_some() && readers_done == 2 {
            break;
        }
        std::thread::sleep(poll);
    }
    let timed_out = !(status.is_some() && readers_done == 2);

    if timed_out {
        // Kill sequence: SIGTERM to the group, a grace period, then SIGKILL.
        // A child that calls setsid() leaves the group and escapes this in
        // every language, so this is cleanup rather than containment;
        // escape-proof cleanup needs a cgroup, which is out of scope.
        #[cfg(unix)]
        {
            signal_group(pid, libc::SIGTERM);
            let grace_end = Instant::now() + kill_grace();
            while Instant::now() < grace_end {
                if status.is_none() {
                    status = child.try_wait().map_err(wait_err)?;
                }
                while done_rx.try_recv().is_ok() {
                    readers_done += 1;
                }
                if status.is_some() && readers_done == 2 {
                    break;
                }
                std::thread::sleep(poll);
            }
            // The rest of the group may outlive the leader; kill it either way.
            signal_group(pid, libc::SIGKILL);
        }
        #[cfg(not(unix))]
        {
            let _ = pid;
            let _ = child.kill();
        }
        if status.is_none() {
            child.wait().map_err(wait_err)?;
        }
        // Give the readers a moment to drain what the pipes still hold; a
        // process that escaped the group may keep them open, so do not wait
        // for it.
        let drain_end = Instant::now() + Duration::from_millis(500);
        while readers_done < 2 && Instant::now() < drain_end {
            if done_rx.recv_timeout(poll).is_ok() {
                readers_done += 1;
            }
        }
        let (stdout, out_trunc) = take_text(&stdout_buf, max_bytes);
        let (stderr, err_trunc) = take_text(&stderr_buf, max_bytes);
        return Ok(RunOutput {
            stdout,
            stderr,
            exit_code: -1,
            status: "timeout".to_string(),
            timed_out: true,
            truncated: out_trunc || err_trunc,
        });
    }

    let status = status.expect("exit status present when not timed out");
    let (stdout, out_trunc) = take_text(&stdout_buf, max_bytes);
    let (stderr, err_trunc) = take_text(&stderr_buf, max_bytes);
    let exit_code = status.code().unwrap_or(-1);
    let status = if status.success() {
        "success".to_string()
    } else {
        format!("error (exit code: {exit_code}): {stderr}")
    };
    Ok(RunOutput {
        stdout,
        stderr,
        exit_code,
        status,
        timed_out: false,
        truncated: out_trunc || err_trunc,
    })
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

    /// Serializes tests that touch process-global environment variables
    /// (`TOOLCLAD_SECRET_*`, `TOOLCLAD_SECRETS_FILE`, `TOOLCLAD_EVIDENCE_DIR`,
    /// `TOOLCLAD_KILL_GRACE_MS`, the sentinels) or spawn a child.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn test_inject_template_vars_with_env() {
        let _guard = env_lock();
        std::env::set_var("TOOLCLAD_SECRET_API_KEY", "test-key-123");
        let result =
            inject_template_vars("Bearer {_secret:api_key}", &mut SecretSource::default()).unwrap();
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
            url: "https://api.example.com/{target}".to_string(),
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
        let _guard = env_lock();
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
        assert_eq!(
            parts.url,
            format!("https://api.example.com/{}", percent_encode(smuggle))
        );
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
        let _guard = env_lock();
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
        let _guard = env_lock();
        std::env::remove_var("TOOLCLAD_SECRET_MISSING");
        let result = inject_template_vars("token={_secret:missing}", &mut SecretSource::default());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("TOOLCLAD_SECRET_MISSING"));
    }

    #[test]
    fn test_inject_template_vars_no_secrets() {
        let result = inject_template_vars(
            "plain text with {normal} placeholders",
            &mut SecretSource::default(),
        )
        .unwrap();
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

    // ---- W6 / W8: spawn path and timeouts --------------------------------

    /// A per-test evidence root under the temp dir, with the env lock held.
    /// Sets `TOOLCLAD_EVIDENCE_DIR` and a short kill grace; undone on drop.
    struct SpawnEnv {
        root: PathBuf,
        _guard: std::sync::MutexGuard<'static, ()>,
    }

    impl SpawnEnv {
        fn new() -> Self {
            let guard = env_lock();
            let root = std::env::temp_dir().join(format!(
                "toolclad-spawn-test-{}",
                uuid::Uuid::new_v4().simple()
            ));
            std::fs::create_dir(&root).unwrap();
            std::env::set_var("TOOLCLAD_EVIDENCE_DIR", root.join("evidence"));
            std::env::set_var("TOOLCLAD_KILL_GRACE_MS", "200");
            Self {
                root,
                _guard: guard,
            }
        }

        fn evidence(&self) -> PathBuf {
            self.root.join("evidence")
        }
    }

    impl Drop for SpawnEnv {
        fn drop(&mut self) {
            std::env::remove_var("TOOLCLAD_EVIDENCE_DIR");
            std::env::remove_var("TOOLCLAD_KILL_GRACE_MS");
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn toml_str(s: &str) -> String {
        toml::Value::String(s.to_string()).to_string()
    }

    /// Load a manifest whose command is `exec`, with optional extra TOML
    /// appended to `[tool]` and to the document.
    fn spawn_manifest(binary: &str, exec: &[&str], tool_extra: &str, extra: &str) -> Manifest {
        let tool_extra = if tool_extra.contains("timeout_seconds") {
            tool_extra.to_string()
        } else {
            format!("timeout_seconds = 10\n{tool_extra}")
        };
        let exec: Vec<String> = exec.iter().map(|e| toml_str(e)).collect();
        crate::parse_manifest(&format!(
            "[tool]\nname = \"spawn_test\"\nversion = \"1.0.0\"\nbinary = {}\n\
             description = \"d\"\n{tool_extra}\n\n\
             [command]\nexec = [{}]\n\n[output]\nformat = \"text\"\n\n{extra}",
            toml_str(binary),
            exec.join(", ")
        ))
        .unwrap_or_else(|e| panic!("manifest should load: {e}"))
    }

    fn raw(env: &EvidenceEnvelope) -> String {
        env.results["raw_output"].as_str().unwrap().to_string()
    }

    fn env_names(output: &str) -> Vec<String> {
        output
            .lines()
            .filter_map(|l| l.split_once('=').map(|(k, _)| k.to_string()))
            .collect()
    }

    #[cfg(unix)]
    fn mode_of(p: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::symlink_metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn test_child_env_is_allowlisted() {
        let _env = SpawnEnv::new();
        std::env::set_var("TOOLCLAD_SECRET_LEAK", "sentinel");
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "sentinel2");
        std::env::set_var("LD_PRELOAD", "/tmp/x");
        let m = spawn_manifest("printenv", &["printenv"], "", "");
        let result = execute(&m, &HashMap::new());
        std::env::remove_var("TOOLCLAD_SECRET_LEAK");
        std::env::remove_var("AWS_SECRET_ACCESS_KEY");
        std::env::remove_var("LD_PRELOAD");
        let out = raw(&result.unwrap());
        assert!(!out.contains("sentinel"), "{out}");
        assert!(!out.contains("/tmp/x"), "{out}");
        assert!(
            out.lines().any(|l| l == format!("PATH={CHILD_PATH}")),
            "{out}"
        );
        for name in env_names(&out) {
            assert!(
                name == "PATH" || CHILD_ENV_PASSTHROUGH.contains(&name.as_str()),
                "unexpected child variable {name}"
            );
        }
    }

    #[test]
    fn test_executor_hatch_env_is_allowlisted() {
        let _env = SpawnEnv::new();
        std::env::set_var("TOOLCLAD_SECRET_LEAK", "sentinel");
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "sentinel2");
        std::env::set_var("LD_PRELOAD", "/tmp/x");
        let printenv = resolve_program("printenv").unwrap();
        let m = crate::parse_manifest(&format!(
            "[tool]\nname = \"hatch\"\nversion = \"1.0.0\"\nbinary = \"printenv\"\n\
             description = \"d\"\n\n[args.target]\nposition = 1\nrequired = true\n\
             type = \"string\"\ndescription = \"t\"\n\n\
             [command]\nexecutor = {}\n\n[output]\nformat = \"text\"\n",
            toml_str(&path_string(&printenv))
        ))
        .unwrap();
        let args = HashMap::from([("target".to_string(), "abc".to_string())]);
        let result = execute(&m, &args);
        std::env::remove_var("TOOLCLAD_SECRET_LEAK");
        std::env::remove_var("AWS_SECRET_ACCESS_KEY");
        std::env::remove_var("LD_PRELOAD");
        let out = raw(&result.unwrap());
        assert!(!out.contains("sentinel"), "{out}");
        assert!(!out.contains("/tmp/x"), "{out}");
        assert!(out.lines().any(|l| l == "TOOLCLAD_ARG_TARGET=abc"), "{out}");
        assert!(
            out.lines().any(|l| l == "TOOLCLAD_TOOL_NAME=hatch"),
            "{out}"
        );
        assert!(
            out.lines().any(|l| l == format!("PATH={CHILD_PATH}")),
            "{out}"
        );
        let hatch = [
            "TOOLCLAD_SCAN_ID",
            "TOOLCLAD_TOOL_NAME",
            "TOOLCLAD_EVIDENCE_DIR",
            "TOOLCLAD_OUTPUT_DIR",
        ];
        let names = env_names(&out);
        for h in hatch {
            assert!(names.iter().any(|n| n == h), "missing {h}: {out}");
        }
        for name in names {
            assert!(!name.starts_with("TOOLCLAD_SECRET_"), "{name}");
            assert!(
                name == "PATH"
                    || CHILD_ENV_PASSTHROUGH.contains(&name.as_str())
                    || hatch.contains(&name.as_str())
                    || name.starts_with("TOOLCLAD_ARG_"),
                "unexpected child variable {name}"
            );
        }
    }

    #[test]
    fn test_secret_names_are_filtered_from_child_env() {
        // The filter holds even if a future edit routes a secret into `extra`.
        let env = child_env(&[
            ("TOOLCLAD_SECRET_TOKEN".to_string(), "s".to_string()),
            ("TOOLCLAD_ARG_SECRET_NAME".to_string(), "ok".to_string()),
        ]);
        assert!(env.iter().all(|(k, _)| !k.starts_with("TOOLCLAD_SECRET_")));
        assert!(env.iter().any(|(k, _)| k == "TOOLCLAD_ARG_SECRET_NAME"));
        assert_eq!(env[0], ("PATH".to_string(), CHILD_PATH.into()));
    }

    #[cfg(unix)]
    fn write_secrets(dir: &Path, body: &str, mode: u32) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let p = dir.join(format!("secrets-{mode:o}.toml"));
        std::fs::write(&p, body).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
        p
    }

    #[cfg(unix)]
    #[test]
    fn test_secrets_file() {
        let env = SpawnEnv::new();
        let good = write_secrets(&env.root, "api_key = \"from-file\"\n", 0o600);
        std::env::set_var("TOOLCLAD_SECRETS_FILE", &good);
        std::env::set_var("TOOLCLAD_SECRET_API_KEY", "from-env");
        std::env::set_var("TOOLCLAD_SECRET_OTHER", "env-only");

        // The file wins over the environment variable for the same name, and
        // the environment still serves names the file does not define.
        let mut src = SecretSource::default();
        assert_eq!(
            inject_template_vars("{_secret:api_key}/{_secret:other}", &mut src).unwrap(),
            "from-file/env-only"
        );
        // Read once per call: the cached file serves later placeholders.
        std::fs::remove_file(&good).unwrap();
        assert_eq!(src.lookup("api_key").unwrap(), "from-file");

        // A missing secret is still an error.
        let err = inject_template_vars("{_secret:absent}", &mut src)
            .unwrap_err()
            .to_string();
        assert!(err.contains("TOOLCLAD_SECRET_ABSENT"), "{err}");

        // A group/world-readable file is refused, naming the mode.
        let loose = write_secrets(&env.root, "api_key = \"x\"\n", 0o644);
        std::env::set_var("TOOLCLAD_SECRETS_FILE", &loose);
        let err = inject_template_vars("{_secret:api_key}", &mut SecretSource::default())
            .unwrap_err()
            .to_string();
        assert!(err.contains("mode 0644"), "{err}");
        assert!(err.contains("chmod 600"), "{err}");

        // No placeholder, no file read.
        assert!(inject_template_vars("plain", &mut SecretSource::default()).is_ok());

        std::env::remove_var("TOOLCLAD_SECRETS_FILE");
        std::env::remove_var("TOOLCLAD_SECRET_API_KEY");
        std::env::remove_var("TOOLCLAD_SECRET_OTHER");
    }

    #[test]
    fn test_bare_argv0_resolves_against_fixed_path() {
        let _env = SpawnEnv::new();
        let echo = resolve_program("echo").unwrap();
        assert!(echo.is_absolute());
        assert!(CHILD_PATH
            .split(':')
            .any(|d| echo.parent() == Some(Path::new(d))));
        let m = spawn_manifest("echo", &["echo", "hi"], "", "");
        let env = execute(&m, &HashMap::new()).unwrap();
        assert_eq!(env.status, "success");
        assert_eq!(raw(&env), "hi\n");

        let err = resolve_program("toolclad-no-such-binary")
            .unwrap_err()
            .to_string();
        assert!(err.contains("'toolclad-no-such-binary'"), "{err}");
        assert!(err.contains(CHILD_PATH), "{err}");
    }

    #[test]
    fn test_stdin_is_dev_null() {
        let _env = SpawnEnv::new();
        let m = spawn_manifest("cat", &["cat"], "", "");
        let start = Instant::now();
        let env = execute(&m, &HashMap::new()).unwrap();
        assert!(start.elapsed() < Duration::from_secs(5));
        assert_eq!(env.status, "success");
        assert_eq!(raw(&env), "");
    }

    #[test]
    fn test_cwd_is_scratch_dir_removed_when_empty() {
        let env = SpawnEnv::new();
        let m = spawn_manifest("pwd", &["pwd"], "", "");
        let out = execute(&m, &HashMap::new()).unwrap();
        let work = env.evidence().join(format!("{}-work", out.scan_id));
        assert_eq!(raw(&out).trim_end(), path_string(&work));
        assert!(!work.exists(), "an empty scratch dir is removed");
    }

    #[cfg(unix)]
    #[test]
    fn test_scratch_dir_kept_when_written_with_private_modes() {
        let env = SpawnEnv::new();
        // `touch` writes a relative path: it lands in the scratch dir, which
        // is then evidence and kept. umask 0077 makes the file 0600.
        let m = spawn_manifest("touch", &["touch", "marker"], "", "");
        let out = execute(&m, &HashMap::new()).unwrap();
        assert_eq!(out.status, "success");
        let work = env.evidence().join(format!("{}-work", out.scan_id));
        assert_eq!(mode_of(&work), 0o700);
        assert_eq!(mode_of(&work.join("marker")), 0o600);
        assert_eq!(mode_of(&env.evidence()), 0o700);
    }

    #[test]
    fn test_evidence_paths_table() {
        let env = SpawnEnv::new();
        let mut m = minimal_manifest();
        let p = EvidencePaths::new(&m, "1-abc".to_string());
        assert_eq!(p.evidence_dir, env.evidence());
        assert_eq!(p.output_dir, env.evidence().join("1-abc-test_tool"));
        assert_eq!(p.output_file, p.output_dir.join("scan.txt"));
        for (format, ext) in [
            ("xml", "xml"),
            ("json", "json"),
            ("csv", "csv"),
            ("jsonl", "jsonl"),
            ("text", "txt"),
            ("other", "txt"),
        ] {
            m.output.as_mut().unwrap().format = format.to_string();
            let p = EvidencePaths::new(&m, "1-abc".to_string());
            assert_eq!(p.output_file, p.output_dir.join(format!("scan.{ext}")));
        }
        m.tool.evidence = Some(EvidenceMeta {
            output_dir: "{evidence_dir}/runs/{scan_id}".to_string(),
            capture: false,
            hash: "sha256".to_string(),
            screenshots: false,
        });
        let p = EvidencePaths::new(&m, "1-abc".to_string());
        assert_eq!(p.output_dir, env.evidence().join("runs").join("1-abc"));

        std::env::remove_var("TOOLCLAD_EVIDENCE_DIR");
        let p = EvidencePaths::new(&minimal_manifest(), "1-abc".to_string());
        assert_eq!(
            p.evidence_dir,
            std::env::temp_dir().join("toolclad-evidence")
        );
    }

    #[test]
    fn test_scan_id_shape_and_uniqueness() {
        let a = new_scan_id();
        let b = new_scan_id();
        assert_ne!(a, b);
        for id in [&a, &b] {
            let (secs, rand) = id.split_once('-').unwrap();
            assert!(secs.parse::<i64>().is_ok(), "{id}");
            assert_eq!(rand.len(), 32, "{id}");
            assert!(rand.bytes().all(|c| c.is_ascii_hexdigit()), "{id}");
        }
    }

    /// `RLIMIT_NPROC` counts every task of the user, not just the tool's, so
    /// the 512 default can stop a threaded `dd` (uutils) on a busy host. Lift
    /// it (capped at the hard limit) where the test is not about NPROC.
    const DD_LIMITS: &str = "[tool.limits]\nnproc = 4194304\n";

    #[cfg(unix)]
    #[test]
    fn test_output_dir_created_private_before_spawn() {
        let env = SpawnEnv::new();
        // The tool writes `{_output_file}` itself; that only works if the
        // directory exists before the spawn.
        let m = spawn_manifest(
            "dd",
            &[
                "dd",
                "if=/dev/zero",
                "of={_output_file}",
                "bs=16",
                "count=1",
            ],
            "",
            DD_LIMITS,
        );
        let first = execute(&m, &HashMap::new()).unwrap();
        assert_eq!(first.status, "success", "{}", first.stderr);
        let out_dir = env.evidence().join(format!("{}-spawn_test", first.scan_id));
        assert_eq!(mode_of(&out_dir), 0o700);
        assert_eq!(
            std::fs::metadata(out_dir.join("scan.txt")).unwrap().len(),
            16
        );

        let second = execute(&m, &HashMap::new()).unwrap();
        assert_ne!(first.scan_id, second.scan_id);

        // A declared [tool.evidence] output_dir is honored.
        let m = spawn_manifest(
            "dd",
            &[
                "dd",
                "if=/dev/zero",
                "of={_output_file}",
                "bs=16",
                "count=1",
            ],
            "",
            "[tool.limits]\nnproc = 4194304\n\n[tool.evidence]\noutput_dir = \"{evidence_dir}/custom/{scan_id}\"\n",
        );
        let env3 = execute(&m, &HashMap::new()).unwrap();
        let custom = env.evidence().join("custom").join(&env3.scan_id);
        assert_eq!(mode_of(&custom), 0o700);
        assert!(custom.join("scan.txt").exists());
    }

    #[cfg(unix)]
    #[test]
    fn test_symlinked_output_dir_is_refused() {
        let env = SpawnEnv::new();
        std::fs::create_dir_all(env.evidence()).unwrap();
        let elsewhere = env.root.join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, env.evidence().join("fixed")).unwrap();
        let m = spawn_manifest(
            "dd",
            &[
                "dd",
                "if=/dev/zero",
                "of={_output_file}",
                "bs=16",
                "count=1",
            ],
            "",
            "[tool.limits]\nnproc = 4194304\n\n[tool.evidence]\noutput_dir = \"{evidence_dir}/fixed\"\n",
        );
        let err = execute(&m, &HashMap::new()).unwrap_err().to_string();
        assert!(err.contains("symlink"), "{err}");
        assert!(std::fs::read_dir(&elsewhere).unwrap().next().is_none());
    }

    /// `/proc/self/limits` row for `name`: (soft, hard).
    #[cfg(target_os = "linux")]
    fn limit_row(limits: &str, name: &str) -> (String, String) {
        let line = limits
            .lines()
            .find(|l| l.starts_with(name))
            .unwrap_or_else(|| panic!("no {name} row in {limits}"));
        let mut cols = line[name.len()..].split_whitespace();
        (
            cols.next().unwrap().to_string(),
            cols.next().unwrap().to_string(),
        )
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_rlimits_and_umask_applied_in_child() {
        let _env = SpawnEnv::new();
        let m = spawn_manifest(
            "cat",
            &["cat", "/proc/self/limits", "/proc/self/status"],
            "",
            "[tool.limits]\nfsize_bytes = 4096\ncpu_seconds = 7\n",
        );
        let out = raw(&execute(&m, &HashMap::new()).unwrap());
        assert_eq!(limit_row(&out, "Max core file size").0, "0");
        assert_eq!(limit_row(&out, "Max file size").0, "4096");
        assert_eq!(limit_row(&out, "Max cpu time").0, "7");
        // Defaults, each capped at the inherited hard limit.
        let nofile: u64 = limit_row(&out, "Max open files").0.parse().unwrap();
        assert!(nofile <= 1024, "{nofile}");
        assert!(out.lines().any(|l| l == "Umask:\t0077"), "{out}");
    }

    #[cfg(unix)]
    #[test]
    fn test_fsize_limit_stops_oversized_write() {
        let env = SpawnEnv::new();
        let m = spawn_manifest(
            "dd",
            &[
                "dd",
                "if=/dev/zero",
                "of={_output_file}",
                "bs=1024",
                "count=8",
            ],
            "",
            "[tool.limits]\nfsize_bytes = 4096\nnproc = 4194304\n",
        );
        let out = execute(&m, &HashMap::new()).unwrap();
        assert_ne!(out.status, "success");
        let file = env
            .evidence()
            .join(format!("{}-spawn_test", out.scan_id))
            .join("scan.txt");
        assert!(std::fs::metadata(&file).unwrap().len() <= 4096);
    }

    #[test]
    fn test_kill_grace_parsing() {
        let _guard = env_lock();
        for (v, ms) in [
            ("150", 150),
            ("0", 0),
            ("-5", DEFAULT_KILL_GRACE_MS),
            ("abc", DEFAULT_KILL_GRACE_MS),
            ("", DEFAULT_KILL_GRACE_MS),
        ] {
            std::env::set_var("TOOLCLAD_KILL_GRACE_MS", v);
            assert_eq!(kill_grace(), Duration::from_millis(ms), "{v}");
        }
        std::env::remove_var("TOOLCLAD_KILL_GRACE_MS");
        assert_eq!(kill_grace(), Duration::from_millis(DEFAULT_KILL_GRACE_MS));
    }

    #[test]
    fn test_timeout_fires_with_timeout_envelope() {
        let _env = SpawnEnv::new();
        let m = spawn_manifest("sleep", &["sleep", "10"], "timeout_seconds = 1", "");
        let start = Instant::now();
        let out = execute(&m, &HashMap::new()).unwrap();
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "{:?}",
            start.elapsed()
        );
        assert_eq!(out.status, "timeout");
        assert_eq!(out.exit_code, -1);
    }

    /// Re-executed by `test_timeout_keeps_partial_output_and_kills_group` as
    /// the tool: prints its pid and a grandchild's pid, then sleeps past the
    /// deadline. Does nothing unless it runs in a ToolClad scratch directory,
    /// so `cargo test -- --ignored` stays fast.
    #[test]
    #[ignore]
    fn timeout_helper_print_then_sleep() {
        use std::io::Write;
        let in_scratch = std::env::current_dir()
            .ok()
            .and_then(|d| {
                d.file_name()
                    .map(|n| n.to_string_lossy().ends_with("-work"))
            })
            .unwrap_or(false);
        if !in_scratch {
            return;
        }
        let mut grandchild = Command::new("sleep").arg("30").spawn().unwrap();
        println!("partial-marker {} {}", std::process::id(), grandchild.id());
        std::io::stdout().flush().unwrap();
        std::thread::sleep(Duration::from_secs(30));
        let _ = grandchild.wait();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_timeout_keeps_partial_output_and_kills_group() {
        let _env = SpawnEnv::new();
        let exe = std::env::current_exe().unwrap();
        let exe = path_string(&exe);
        // The helper's test harness spawns threads; lift NPROC (capped at
        // the hard limit) so a busy host cannot make it fail to start.
        let m = spawn_manifest(
            &exe,
            &[
                &exe,
                "--exact",
                "executor::tests::timeout_helper_print_then_sleep",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ],
            "timeout_seconds = 1",
            "[tool.limits]\nnproc = 4194304\n",
        );
        let start = Instant::now();
        let out = execute(&m, &HashMap::new()).unwrap();
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "{:?}",
            start.elapsed()
        );
        assert_eq!(out.status, "timeout");
        assert_eq!(out.exit_code, -1);
        let text = raw(&out);
        // The helper's harness prints its own text on the same line first.
        let line = text
            .lines()
            .find_map(|l| l.split_once("partial-marker ").map(|(_, rest)| rest))
            .unwrap_or_else(|| panic!("partial output lost: {text:?} / {}", out.stderr));
        let pids: Vec<i32> = line
            .split_whitespace()
            .map(|p| p.parse().unwrap())
            .collect();
        // Both the tool and its grandchild are gone (the grandchild, now
        // orphaned, may linger as a zombie for a moment until init reaps it).
        for pid in pids {
            let gone = (0..50).any(|_| {
                // SAFETY: signal 0 only probes for existence.
                let alive = unsafe { libc::kill(pid, 0) } == 0
                    && !std::fs::read_to_string(format!("/proc/{pid}/stat"))
                        .map(|s| s.contains(") Z "))
                        .unwrap_or(true);
                if alive {
                    std::thread::sleep(Duration::from_millis(20));
                }
                !alive
            });
            assert!(gone, "pid {pid} survived the timeout");
        }
    }

    // ---- W7: policy gate -------------------------------------------------

    /// An `echo` manifest with a `target` argument; `tool_extra` lands in
    /// `[tool]`.
    fn gated_manifest(tool_extra: &str) -> Manifest {
        crate::parse_manifest(&format!(
            "[tool]\nname = \"gate_test\"\nversion = \"1.0.0\"\nbinary = \"echo\"\n\
             description = \"d\"\n{tool_extra}\n\n\
             [args.target]\nposition = 1\nrequired = true\ntype = \"string\"\n\
             description = \"t\"\n\n\
             [args.flag]\nposition = 2\nrequired = false\ntype = \"boolean\"\n\
             default = \"FALSE\"\ndescription = \"f\"\n\n\
             [command]\nexec = [\"echo\", \"{{target}}\", \"{{_output_file}}\"]\n\n\
             [output]\nformat = \"text\"\n"
        ))
        .unwrap_or_else(|e| panic!("manifest should load: {e}"))
    }

    fn target(v: &str) -> HashMap<String, String> {
        HashMap::from([("target".to_string(), v.to_string())])
    }

    #[test]
    fn test_gate_denies_human_approval_and_nothing_runs() {
        let env = SpawnEnv::new();
        let m = gated_manifest("human_approval = true");
        let err = execute(&m, &target("hello")).unwrap_err();
        assert!(matches!(err, ToolCladError::PolicyDenied(_)), "{err:?}");
        assert_eq!(
            err.to_string(),
            "policy gate denied: manifest requires human approval (human_approval = true)"
        );
        // Nothing was prepared or spawned: the evidence root was never created.
        assert!(!env.evidence().exists());
    }

    #[test]
    fn test_gate_risk_tiers() {
        for tier in ["high", "critical"] {
            let m = gated_manifest(&format!("risk_tier = \"{tier}\""));
            let err = execute(&m, &target("x")).unwrap_err().to_string();
            assert_eq!(
                err,
                format!("policy gate denied: risk_tier '{tier}' requires explicit approval")
            );
        }
        for tier in ["info", "low", "medium"] {
            let m = gated_manifest(&format!("risk_tier = \"{tier}\""));
            assert_eq!(default_gate(&m, &HashMap::new()), GateDecision::Allow);
        }
        let _env = SpawnEnv::new();
        let m = gated_manifest("risk_tier = \"medium\"");
        assert_eq!(execute(&m, &target("x")).unwrap().status, "success");
    }

    #[test]
    fn test_gate_approved_runs() {
        let _env = SpawnEnv::new();
        let m = gated_manifest("human_approval = true\nrisk_tier = \"critical\"");
        let out = execute_approved(&m, &target("hello")).unwrap();
        assert_eq!(out.status, "success");
        assert!(raw(&out).starts_with("hello "), "{}", raw(&out));
        let out = execute_with_gate(&m, &target("hello"), &approve_gate).unwrap();
        assert_eq!(out.status, "success");
    }

    #[test]
    fn test_custom_gate_sees_validated_values_and_its_reason_reaches_caller() {
        let _env = SpawnEnv::new();
        let m = gated_manifest("");
        let seen = Mutex::new(None);
        let gate = |_: &Manifest, v: &HashMap<String, String>| {
            *seen.lock().unwrap() = Some(v.clone());
            if v.get("target").map(String::as_str) == Some("forbidden") {
                GateDecision::Deny("target 'forbidden' is off limits".to_string())
            } else {
                GateDecision::Allow
            }
        };
        let err = execute_with_gate(&m, &target("forbidden"), &gate)
            .unwrap_err()
            .to_string();
        assert_eq!(err, "policy gate denied: target 'forbidden' is off limits");
        // The gate saw the cleaned values, default applied and normalized.
        let v = seen.lock().unwrap().take().unwrap();
        assert_eq!(v.get("flag").map(String::as_str), Some("false"));
        assert!(execute_with_gate(&m, &target("fine"), &gate).is_ok());
    }

    #[test]
    fn test_gate_runs_after_validation() {
        let m = gated_manifest("human_approval = true");
        let called = std::cell::Cell::new(false);
        let gate = |_: &Manifest, _: &HashMap<String, String>| {
            called.set(true);
            GateDecision::Deny("no".to_string())
        };
        let err = execute_with_gate(&m, &target("a;b"), &gate)
            .unwrap_err()
            .to_string();
        assert!(err.starts_with("validation error"), "{err}");
        assert!(!called.get());
        let err = execute(&m, &HashMap::new()).unwrap_err().to_string();
        assert!(err.contains("missing required argument"), "{err}");
    }

    #[test]
    fn test_gate_applies_to_http_and_mcp() {
        use crate::types::McpProxyDef;
        let mut m = minimal_manifest();
        m.tool.human_approval = true;
        m.mcp = Some(McpProxyDef {
            server: "s".to_string(),
            tool: "t".to_string(),
            field_map: HashMap::new(),
        });
        let err = execute(&m, &target("example.com")).unwrap_err();
        assert!(matches!(err, ToolCladError::PolicyDenied(_)), "{err:?}");

        // HTTP: denied before any request (the port would refuse anyway).
        let mut m = minimal_manifest();
        m.tool.risk_tier = "high".to_string();
        m.command = CommandDef::default();
        m.http = Some(HttpDef {
            method: "GET".to_string(),
            url: "http://127.0.0.1:1/{target}".to_string(),
            headers: HashMap::new(),
            body_template: None,
            success_status: vec![],
            error_status: vec![],
        });
        let err = execute(&m, &target("example.com")).unwrap_err();
        assert!(matches!(err, ToolCladError::PolicyDenied(_)), "{err:?}");
    }

    #[test]
    fn test_dry_run_is_not_gated() {
        let m = gated_manifest("human_approval = true\nrisk_tier = \"critical\"");
        let dry = dry_run(&m, &target("hello")).unwrap();
        assert!(dry.command.starts_with("echo hello "), "{}", dry.command);
    }

    // ---- W9: output caps, parsing and fail-closed schema ------------------

    /// An `echo` manifest printing `json_text` with output `[output]` extras.
    fn echo_manifest(json_text: &str, output: &str) -> Manifest {
        spawn_manifest(
            "echo",
            &["echo", &json_text.replace('{', "{{").replace('}', "}}")],
            "",
            "",
        )
        .with_output(output)
    }

    trait WithOutput {
        fn with_output(self, output: &str) -> Manifest;
    }

    impl WithOutput for Manifest {
        fn with_output(mut self, output: &str) -> Manifest {
            let o: OutputDef = toml::from_str(output).unwrap();
            self.output = Some(o);
            self
        }
    }

    #[test]
    fn test_output_cap_truncates_and_flags() {
        let _env = SpawnEnv::new();
        let m = spawn_manifest("seq", &["seq", "1", "5000"], "", "")
            .with_output("format = \"text\"\nmax_bytes = 1024");
        let start = Instant::now();
        let out = execute(&m, &HashMap::new()).unwrap();
        assert!(start.elapsed() < Duration::from_secs(5));
        assert_eq!(out.status, "success");
        assert!(out.output_truncated);
        assert_eq!(raw(&out).len(), 1024);
        assert!(raw(&out).starts_with("1\n2\n3\n"));
        let json = serde_json::to_value(&out).unwrap();
        assert_eq!(json["output_truncated"], true);

        // Under the cap: no flag, and the field is omitted.
        let m = spawn_manifest("seq", &["seq", "1", "5"], "", "");
        let out = execute(&m, &HashMap::new()).unwrap();
        assert!(!out.output_truncated);
        let json = serde_json::to_value(&out).unwrap();
        assert!(json.get("output_truncated").is_none());
    }

    #[test]
    fn test_capped_text_respects_char_boundaries() {
        let text = capped_text("\u{e9}\u{e9}".as_bytes().to_vec(), 3);
        assert_eq!(text, "\u{e9}");
        assert!(capped_text(vec![0xff, 0xff, 0xff], 2).len() <= 2);
    }

    #[test]
    fn test_fail_closed_schema_end_to_end() {
        let _env = SpawnEnv::new();
        let output = "format = \"json\"\n[schema]\ntype = \"object\"\nrequired = [\"ok\"]\n\
                      [schema.properties.ok]\ntype = \"boolean\"\n";

        let out = execute(&echo_manifest(r#"{"ok": "yes"}"#, output), &HashMap::new()).unwrap();
        assert_eq!(out.status, "schema_error");
        assert_eq!(
            out.results["schema_error"],
            "/ok: expected boolean, got string"
        );
        assert_eq!(out.results["raw_output"], "{\"ok\": \"yes\"}\n");
        assert_eq!(out.exit_code, 0);

        let out = execute(&echo_manifest(r#"{"ok": true}"#, output), &HashMap::new()).unwrap();
        assert_eq!(out.status, "success");
        assert_eq!(out.results, serde_json::json!({"ok": true}));

        let out = execute(&echo_manifest("not json", output), &HashMap::new()).unwrap();
        assert_eq!(out.status, "parse_error");
        assert!(
            out.results["parse_error"]
                .as_str()
                .unwrap()
                .starts_with("JSON parse failed"),
            "{}",
            out.results
        );
        assert_eq!(out.results["raw_output"], "not json\n");

        // No declared schema: the default {"type": "object"} still applies,
        // and a non-object JSON value is wrapped so it satisfies it.
        let out = execute(
            &echo_manifest("[1, 2]", "format = \"json\""),
            &HashMap::new(),
        )
        .unwrap();
        assert_eq!(out.status, "success");
        assert_eq!(out.results, serde_json::json!({"parsed_output": [1, 2]}));
    }

    #[test]
    fn test_xml_doctype_refused_plain_xml_parses() {
        let _env = SpawnEnv::new();
        let evil = r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY a "aaaa">]><foo>&a;</foo>"#;
        let out = execute(&echo_manifest(evil, "format = \"xml\""), &HashMap::new()).unwrap();
        assert_eq!(out.status, "parse_error");
        assert_eq!(out.results["parse_error"], XML_DTD_REFUSED);
        let lower = "<!entity a \"x\"><foo/>";
        assert!(parse_xml_to_json(lower).is_err());

        let out = execute(
            &echo_manifest(
                r#"<root><item name="a">t</item></root>"#,
                "format = \"xml\"",
            ),
            &HashMap::new(),
        )
        .unwrap();
        assert_eq!(out.status, "success");
        assert_eq!(out.results["root"]["item"]["@name"], "a");
    }

    #[test]
    fn test_jsonl_and_csv_results_are_objects() {
        let m = minimal_manifest().with_output("format = \"jsonl\"");
        assert_eq!(
            parse_output(&m, "{\"a\":1}\n\n{\"a\":2}\n").unwrap(),
            serde_json::json!({"parsed_output": [{"a": 1}, {"a": 2}]})
        );
        let m = minimal_manifest().with_output("format = \"csv\"");
        assert_eq!(
            parse_output(&m, "name,age,ok\nAlice,30,true\n").unwrap(),
            serde_json::json!({"parsed_output": [{"name": "Alice", "age": 30, "ok": true}]})
        );
        assert_eq!(
            parse_output(&m, "").unwrap(),
            serde_json::json!({"parsed_output": []})
        );
        let m = minimal_manifest().with_output("format = \"text\"");
        assert_eq!(
            parse_output(&m, "hi").unwrap(),
            serde_json::json!({"raw_output": "hi"})
        );
        // A custom parser on a manifest built in code fails rather than
        // passing output through unchecked.
        let m = minimal_manifest().with_output("format = \"json\"\nparser = \"x.py\"");
        assert!(parse_output(&m, "{}")
            .unwrap_err()
            .contains("not supported"));
    }

    // ---- W10: HTTP hardening and the declared envelope command -------------

    fn http_get_manifest(url: &str) -> Manifest {
        let mut m = minimal_manifest();
        m.args.get_mut("target").unwrap().type_name = "string".to_string();
        m.command = CommandDef::default();
        m.http = Some(HttpDef {
            method: "GET".to_string(),
            url: url.to_string(),
            headers: HashMap::new(),
            body_template: None,
            success_status: vec![],
            error_status: vec![],
        });
        m
    }

    #[test]
    fn test_http_path_values_are_percent_encoded() {
        let m = http_get_manifest("https://api.example.com/{target}");
        let parts = build_http_request(&m, &target("../admin?role=admin")).unwrap();
        assert_eq!(
            parts.url,
            "https://api.example.com/..%2Fadmin%3Frole%3Dadmin"
        );
        let rest = parts.url.strip_prefix("https://").unwrap();
        let (host, path) = rest.split_once('/').unwrap();
        assert_eq!(host, "api.example.com");
        assert!(!path.contains("/admin") && !path.contains('?'), "{path}");
    }

    #[test]
    fn test_http_query_values_are_percent_encoded() {
        let m = http_get_manifest("https://api.example.com/search?q={target}&limit=5");
        let parts = build_http_request(&m, &target("a&admin=true #x%")).unwrap();
        assert_eq!(
            parts.url,
            "https://api.example.com/search?q=a%26admin%3Dtrue%20%23x%25&limit=5"
        );
    }

    #[test]
    fn test_http_value_is_not_rescanned_for_placeholders() {
        let mut m = http_get_manifest("https://api.example.com/{target}/{other}");
        m.args.insert(
            "other".to_string(),
            ArgDef {
                type_name: "string".to_string(),
                ..Default::default()
            },
        );
        let v = HashMap::from([
            ("target".to_string(), "{other}".to_string()),
            ("other".to_string(), "x".to_string()),
        ]);
        let parts = build_http_request(&m, &v).unwrap();
        assert_eq!(parts.url, "https://api.example.com/%7Bother%7D/x");
    }

    #[test]
    fn test_http_url_host_placeholder_is_load_error() {
        for url in [
            "https://{host}/x",
            "{scheme}://example.com/x",
            "https://api.{host}.com/x",
            "https://user@{host}:8080/",
            "{base}/x",
        ] {
            let err = http_url_literal_host(url).unwrap_err().to_string();
            assert!(
                err.contains("http.url may not interpolate into the scheme or host"),
                "{url}: {err}"
            );
        }
        assert_eq!(
            http_url_literal_host("https://u@api.example.com:8443/{p}?q={q}").unwrap(),
            "api.example.com"
        );
        assert_eq!(http_url_literal_host("http://[::1]:80/").unwrap(), "[::1]");
        assert!(http_url_literal_host("ftp://example.com/").is_err());
    }

    #[test]
    fn test_http_header_crlf_and_bad_name_refused() {
        let mut m = http_get_manifest("https://api.example.com/");
        m.http
            .as_mut()
            .unwrap()
            .headers
            .insert("X-Echo".to_string(), "v={target}".to_string());
        let err = build_http_request(&m, &target("a\r\nX-Admin: 1"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("CR, LF or NUL"), "{err}");

        let mut m = http_get_manifest("https://api.example.com/");
        m.http
            .as_mut()
            .unwrap()
            .headers
            .insert("Bad Name".to_string(), "v".to_string());
        let err = build_http_request(&m, &target("a"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("not a valid token"), "{err}");
    }

    /// A one-thread HTTP responder on 127.0.0.1: answers every connection
    /// with `response(path)` and records the request paths. Stops after
    /// `stop` is set.
    struct TestServer {
        port: u16,
        paths: Arc<Mutex<Vec<String>>>,
        stop: Arc<std::sync::atomic::AtomicBool>,
        handle: Option<std::thread::JoinHandle<()>>,
    }

    impl TestServer {
        fn start(response: fn(&str, u16) -> String) -> Self {
            use std::io::Write;
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let port = listener.local_addr().unwrap().port();
            let paths = Arc::new(Mutex::new(Vec::new()));
            let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let (p, st) = (Arc::clone(&paths), Arc::clone(&stop));
            let handle = std::thread::spawn(move || {
                while !st.load(std::sync::atomic::Ordering::SeqCst) {
                    let Ok((mut sock, _)) = listener.accept() else {
                        std::thread::sleep(Duration::from_millis(10));
                        continue;
                    };
                    sock.set_nonblocking(false).unwrap();
                    sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                    let mut req = Vec::new();
                    let mut buf = [0u8; 1024];
                    while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                        match sock.read(&mut buf) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => req.extend_from_slice(&buf[..n]),
                        }
                    }
                    let text = String::from_utf8_lossy(&req).into_owned();
                    let path = text.split_whitespace().nth(1).unwrap_or("").to_string();
                    p.lock().unwrap().push(path.clone());
                    let _ = sock.write_all(response(&path, port).as_bytes());
                }
            });
            Self {
                port,
                paths,
                stop,
                handle: Some(handle),
            }
        }

        fn finish(mut self) -> Vec<String> {
            std::thread::sleep(Duration::from_millis(100));
            self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
            self.handle.take().unwrap().join().unwrap();
            self.paths.lock().unwrap().clone()
        }
    }

    fn http_toml(port: u16, url_path: &str, output_extra: &str) -> Manifest {
        crate::parse_manifest(&format!(
            "[tool]\nname = \"http_test\"\nversion = \"1.0.0\"\nbinary = \"http\"\n\
             description = \"d\"\ntimeout_seconds = 5\n\n\
             [http]\nmethod = \"GET\"\nurl = \"http://127.0.0.1:{port}{url_path}\"\n\n\
             [output]\nformat = \"text\"\n{output_extra}"
        ))
        .unwrap_or_else(|e| panic!("manifest should load: {e}"))
    }

    #[test]
    fn test_http_redirect_is_not_followed() {
        let server = TestServer::start(|path, port| {
            if path == "/start" {
                format!(
                    "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{port}/followed\r\n\
                     Content-Length: 5\r\nConnection: close\r\n\r\nmoved"
                )
            } else {
                "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_string()
            }
        });
        let m = http_toml(server.port, "/start", "");
        let out = execute(&m, &HashMap::new());
        let port = server.port;
        let paths = server.finish();
        let out = out.unwrap();
        assert_eq!(out.status, "redirect_blocked");
        assert_eq!(
            out.results["location"],
            format!("http://127.0.0.1:{port}/followed")
        );
        assert_eq!(out.results["raw_output"], "moved");
        assert_eq!(
            paths,
            vec!["/start".to_string()],
            "a second request was made"
        );
    }

    #[test]
    fn test_http_body_is_capped_and_command_is_declared() {
        let _guard = env_lock();
        std::env::set_var("TOOLCLAD_SECRET_HTTP_TOK", "tok-value-123");
        let server = TestServer::start(|_, _| {
            let body = "x".repeat(4096);
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
        });
        let m = http_toml(
            server.port,
            "/x?key={_secret:http_tok}",
            "max_bytes = 1024\n",
        );
        let out = execute(&m, &HashMap::new());
        std::env::remove_var("TOOLCLAD_SECRET_HTTP_TOK");
        let paths = server.finish();
        let out = out.unwrap();
        assert_eq!(out.status, "success");
        assert!(out.output_truncated);
        assert_eq!(out.results["raw_output"].as_str().unwrap().len(), 1024);
        // The secret reached the server but not the envelope.
        assert_eq!(paths, vec!["/x?key=tok-value-123".to_string()]);
        assert!(
            out.command.contains("{_secret:http_tok}"),
            "{}",
            out.command
        );
        assert!(!out.command.contains("tok-value-123"));
        assert!(!serde_json::to_string(&out)
            .unwrap()
            .contains("tok-value-123"));
    }

    #[test]
    fn test_oneshot_envelope_command_is_declared_form() {
        let env = SpawnEnv::new();
        let m = gated_manifest("");
        let out = execute(&m, &target("hello")).unwrap();
        assert_eq!(out.command, "echo {target} {_output_file}");
        let evidence = path_string(&env.evidence());
        assert!(!out.command.contains(&evidence));
        assert!(raw(&out).contains(&evidence), "the tool still got the path");

        // A legacy template is reported as written.
        let mut m = minimal_manifest();
        m.command.exec = Some(tokenize_template("echo {target}").unwrap());
        let out = execute(&m, &target("example.com")).unwrap();
        assert_eq!(out.command, "echo {target}");

        // The dry run keeps the resolved argv.
        let dry = dry_run(&m, &target("example.com")).unwrap();
        assert_eq!(dry.command, "echo example.com");
    }
}
