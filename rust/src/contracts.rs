//! Common reference-execution checks. These checks do not provide a sandbox.
use crate::types::{Manifest, ToolCladError};
use crate::validator::validate_arg;
use regex::Regex;
use std::collections::HashMap;

pub const MAX_REQUEST_BYTES: usize = 1024 * 1024;
pub const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

fn invalid(message: impl Into<String>) -> ToolCladError {
    ToolCladError::ValidationError(message.into())
}

pub(crate) fn value_string(value: &toml::Value) -> String {
    match value {
        toml::Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Validate supplied arguments and defaults, refusing unknown and reserved names.
pub fn validate_arguments(
    manifest: &Manifest,
    args: &HashMap<String, String>,
) -> Result<HashMap<String, String>, ToolCladError> {
    for name in args.keys() {
        if !manifest.args.contains_key(name) {
            return Err(invalid(format!("unknown argument: {name}")));
        }
    }
    let name_pattern = Regex::new(r"^[A-Za-z][A-Za-z0-9_]*$").unwrap();
    let mut result = HashMap::new();
    for (name, definition) in &manifest.args {
        if !name_pattern.is_match(name) {
            return Err(invalid(format!("invalid argument name: {name}")));
        }
        let fallback_value = definition
            .default
            .as_ref()
            .or_else(|| manifest.command.defaults.as_ref().and_then(|d| d.get(name)));
        if !args.contains_key(name)
            && definition.type_name == "literal_text"
            && fallback_value.is_some_and(|v| !v.is_str())
        {
            return Err(invalid(format!(
                "literal_text default must be a string: {name}"
            )));
        }
        let fallback = fallback_value.map(value_string);
        let value = args.get(name).or(fallback.as_ref());
        let Some(value) = value else {
            if definition.required {
                return Err(invalid(format!("missing required argument: {name}")));
            }
            continue;
        };
        if value.contains('\0')
            || (definition.required
                && definition.type_name != "literal_text"
                && value.trim().is_empty())
        {
            return Err(invalid(format!("invalid empty or NUL argument: {name}")));
        }
        result.insert(name.clone(), validate_arg(name, definition, value)?);
    }
    if result.values().map(String::len).sum::<usize>() > MAX_REQUEST_BYTES {
        return Err(invalid("arguments exceed 1 MiB"));
    }
    Ok(result)
}

pub(crate) fn check_execution(m: &Manifest, dry_run: bool) -> Result<(), ToolCladError> {
    if !(1..=3600).contains(&m.tool.timeout_seconds) {
        return Err(invalid("timeout_seconds must be between 1 and 3600"));
    }
    let backends = [
        m.command.exec.is_some() || m.command.template.is_some(),
        m.command.executor.is_some(),
        m.http.is_some(),
        m.mcp.is_some(),
        m.session.is_some(),
        m.browser.is_some(),
    ];
    if backends.into_iter().filter(|v| *v).count() > 1 {
        return Err(invalid("ambiguous execution backends"));
    }
    if dry_run {
        return Ok(());
    }
    if m.tool.dispatch != "exec"
        || m.tool.human_approval
        || m.tool.cedar.is_some()
        || m.args.values().any(|a| a.scope_check)
    {
        return Err(invalid("execution requires an embedding runtime for dispatch, approval, Cedar or scope enforcement"));
    }
    if let Some(output) = &m.output {
        if !matches!(
            output.parser.as_deref().unwrap_or(""),
            "" | "builtin:json" | "builtin:xml" | "builtin:csv" | "builtin:jsonl" | "builtin:text"
        ) {
            return Err(invalid(
                "custom output parsers require an embedding runtime",
            ));
        }
    }
    Ok(())
}

pub(crate) fn child_environment(cmd: &mut std::process::Command) {
    cmd.env_clear();
    for name in ["PATH", "LANG", "LC_ALL", "SYSTEMROOT"] {
        if let Some(value) = std::env::var_os(name) {
            cmd.env(name, value);
        }
    }
}

pub(crate) fn interpolate(template: &str, args: &HashMap<String, String>) -> String {
    Regex::new(r"\{(\w+)\}")
        .unwrap()
        .replace_all(template, |c: &regex::Captures| {
            args.get(&c[1]).cloned().unwrap_or_else(|| c[0].to_string())
        })
        .into_owned()
}

pub(crate) fn http_url(
    template: &str,
    args: &HashMap<String, String>,
) -> Result<String, ToolCladError> {
    let authority = Regex::new(r"^(https?)://([^/?#]+)").unwrap();
    let matched = authority
        .captures(template)
        .ok_or_else(|| invalid("HTTP URL requires a fixed http(s) authority"))?;
    if matched[2].contains(['{', '}', '@', '\\']) || template.contains("{_secret:") {
        return Err(invalid(
            "HTTP URL requires a fixed authority without credentials or secrets",
        ));
    }
    let value = interpolate(template, args);
    let parsed = reqwest::Url::parse(&value).map_err(|_| invalid("invalid HTTP URL"))?;
    if authority.find(&value).map(|m| m.as_str()) != Some(&matched[0])
        || parsed.fragment().is_some()
        || value.chars().any(|c| c <= ' ' || c == '\\')
    {
        return Err(invalid("invalid HTTP URL or changed authority"));
    }
    Ok(value)
}

pub(crate) fn http_template(
    template: &str,
    args: &HashMap<String, String>,
    dry_run: bool,
    json_string: bool,
) -> Result<String, ToolCladError> {
    let mut failure = None;
    let value = Regex::new(r"\{(_secret:[A-Za-z0-9_]+|\w+)\}")
        .unwrap()
        .replace_all(template, |c: &regex::Captures| {
            let value = if let Some(name) = c[1].strip_prefix("_secret:") {
                if dry_run {
                    "[REDACTED]".to_string()
                } else {
                    let key = format!("TOOLCLAD_SECRET_{}", name.to_uppercase());
                    std::env::var(&key).unwrap_or_else(|_| {
                        failure = Some(invalid(format!(
                            "missing secret environment variable: {key}"
                        )));
                        String::new()
                    })
                }
            } else {
                args.get(&c[1]).cloned().unwrap_or_else(|| c[0].to_string())
            };
            if json_string {
                let encoded = serde_json::to_string(&value).unwrap();
                encoded[1..encoded.len() - 1].to_string()
            } else {
                value
            }
        })
        .into_owned();
    if let Some(error) = failure {
        return Err(error);
    }
    Ok(value)
}
