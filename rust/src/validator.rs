use crate::types::{ArgDef, ToolCladError};
use regex::Regex;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::LazyLock;

/// Supported argument types for validation.
pub const SUPPORTED_TYPES: &[&str] = &[
    "string",
    "integer",
    "port",
    "boolean",
    "enum",
    "scope_target",
    "url",
    "path",
    "ip_address",
    "cidr",
];

/// Shell metacharacters that are rejected by injection sanitization.
const SHELL_METACHARACTERS: &[char] = &[
    '\n', '\r', ';', '|', '&', '$', '`', '(', ')', '{', '}', '[', ']', '<', '>', '!',
];

/// Compiled regex for IP address formats.
static IPV4_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$").unwrap());
static CIDR_V4_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(\d{1,2})$").unwrap());
static HOSTNAME_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$",
    )
    .unwrap()
});
static URL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^https?://[a-zA-Z0-9\-\.]+(/[^\s]*)?$").unwrap());

/// Validate a single argument value against its definition.
///
/// Returns the (possibly transformed) value on success, or a validation error.
pub fn validate_arg(name: &str, def: &ArgDef, value: &str) -> Result<String, ToolCladError> {
    let val = value.trim();

    // Apply injection sanitization if requested or for types that require it.
    match def.type_name.as_str() {
        "string" => validate_string(name, def, val, true),
        "integer" => validate_integer(name, def, val),
        "port" => validate_port(name, val),
        "boolean" => validate_boolean(name, val),
        "enum" => validate_enum(name, def, val),
        "scope_target" => validate_scope_target(name, val),
        "url" => validate_url(name, val),
        "path" => validate_path(name, val),
        "ip_address" => validate_ip_address(name, val),
        "cidr" => validate_cidr(name, val),
        _ => Err(ToolCladError::ValidationError(format!(
            "unknown argument type '{}' for '{}'",
            def.type_name, name
        ))),
    }
}

/// Check that a value contains no shell metacharacters.
fn reject_injection(name: &str, val: &str) -> Result<(), ToolCladError> {
    for ch in SHELL_METACHARACTERS {
        if val.contains(*ch) {
            return Err(ToolCladError::ValidationError(format!(
                "argument '{name}' contains disallowed shell metacharacter '{ch}'"
            )));
        }
    }
    Ok(())
}

fn validate_string(
    name: &str,
    def: &ArgDef,
    val: &str,
    injection_check: bool,
) -> Result<String, ToolCladError> {
    if injection_check || def.sanitize.is_some() {
        reject_injection(name, val)?;
    }
    if let Some(ref pat) = def.pattern {
        let re = Regex::new(pat).map_err(|e| {
            ToolCladError::ManifestError(format!("invalid pattern for '{name}': {e}"))
        })?;
        if !re.is_match(val) {
            return Err(ToolCladError::ValidationError(format!(
                "argument '{name}' does not match pattern '{pat}'"
            )));
        }
    }
    Ok(val.to_string())
}

fn validate_integer(name: &str, def: &ArgDef, val: &str) -> Result<String, ToolCladError> {
    let mut n: i64 = val.parse().map_err(|_| {
        ToolCladError::ValidationError(format!("argument '{name}' is not a valid integer"))
    })?;

    if let Some(min) = def.min {
        if n < min {
            if def.clamp {
                n = min;
            } else {
                return Err(ToolCladError::ValidationError(format!(
                    "argument '{name}' value {n} is below minimum {min}"
                )));
            }
        }
    }
    if let Some(max) = def.max {
        if n > max {
            if def.clamp {
                n = max;
            } else {
                return Err(ToolCladError::ValidationError(format!(
                    "argument '{name}' value {n} is above maximum {max}"
                )));
            }
        }
    }
    Ok(n.to_string())
}

fn validate_port(name: &str, val: &str) -> Result<String, ToolCladError> {
    let n: u16 = val.parse().map_err(|_| {
        ToolCladError::ValidationError(format!("argument '{name}' is not a valid port number"))
    })?;
    if n == 0 {
        return Err(ToolCladError::ValidationError(format!(
            "argument '{name}' port must be 1-65535"
        )));
    }
    Ok(n.to_string())
}

fn validate_boolean(name: &str, val: &str) -> Result<String, ToolCladError> {
    match val {
        "true" | "false" => Ok(val.to_string()),
        _ => Err(ToolCladError::ValidationError(format!(
            "argument '{name}' must be exactly 'true' or 'false'"
        ))),
    }
}

fn validate_enum(name: &str, def: &ArgDef, val: &str) -> Result<String, ToolCladError> {
    let allowed = def.allowed.as_ref().ok_or_else(|| {
        ToolCladError::ManifestError(format!(
            "argument '{name}' is type 'enum' but has no 'allowed' list"
        ))
    })?;
    if allowed.iter().any(|a| a == val) {
        Ok(val.to_string())
    } else {
        Err(ToolCladError::ValidationError(format!(
            "argument '{name}' value '{val}' is not in allowed list: [{}]",
            allowed.join(", ")
        )))
    }
}

fn validate_scope_target(name: &str, val: &str) -> Result<String, ToolCladError> {
    reject_injection(name, val)?;
    if val.contains('*') {
        return Err(ToolCladError::ValidationError(format!(
            "argument '{name}' scope_target must not contain wildcards"
        )));
    }
    // Accept valid IPs, CIDRs, or hostnames.
    if IPV4_RE.is_match(val)
        || val.parse::<Ipv6Addr>().is_ok()
        || CIDR_V4_RE.is_match(val)
        || HOSTNAME_RE.is_match(val)
    {
        Ok(val.to_string())
    } else {
        Err(ToolCladError::ValidationError(format!(
            "argument '{name}' is not a valid scope target (IP, CIDR, or hostname)"
        )))
    }
}

fn validate_url(name: &str, val: &str) -> Result<String, ToolCladError> {
    reject_injection(name, val)?;
    if URL_RE.is_match(val) {
        Ok(val.to_string())
    } else {
        Err(ToolCladError::ValidationError(format!(
            "argument '{name}' is not a valid URL"
        )))
    }
}

fn validate_path(name: &str, val: &str) -> Result<String, ToolCladError> {
    reject_injection(name, val)?;
    if val.contains("../") || val.contains("..\\") {
        return Err(ToolCladError::ValidationError(format!(
            "argument '{name}' path must not contain traversal sequences (../)"
        )));
    }
    // Block absolute paths to prevent access to system files
    if val.starts_with('/') || (val.len() >= 2 && val.as_bytes()[1] == b':') {
        return Err(ToolCladError::ValidationError(format!(
            "argument '{name}' must be a relative path, not absolute"
        )));
    }
    Ok(val.to_string())
}

fn validate_ip_address(name: &str, val: &str) -> Result<String, ToolCladError> {
    if val.parse::<Ipv4Addr>().is_ok() || val.parse::<Ipv6Addr>().is_ok() {
        Ok(val.to_string())
    } else {
        Err(ToolCladError::ValidationError(format!(
            "argument '{name}' is not a valid IP address"
        )))
    }
}

fn validate_cidr(name: &str, val: &str) -> Result<String, ToolCladError> {
    if let Some(caps) = CIDR_V4_RE.captures(val) {
        let ip_part = &caps[1];
        let prefix: u8 = caps[2].parse().map_err(|_| {
            ToolCladError::ValidationError(format!("argument '{name}' has invalid CIDR prefix"))
        })?;
        if ip_part.parse::<Ipv4Addr>().is_err() {
            return Err(ToolCladError::ValidationError(format!(
                "argument '{name}' has invalid IPv4 address in CIDR"
            )));
        }
        if prefix > 32 {
            return Err(ToolCladError::ValidationError(format!(
                "argument '{name}' CIDR prefix must be 0-32"
            )));
        }
        Ok(val.to_string())
    } else {
        Err(ToolCladError::ValidationError(format!(
            "argument '{name}' is not valid CIDR notation (e.g. 10.0.0.0/24)"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_arg(type_name: &str) -> ArgDef {
        ArgDef {
            type_name: type_name.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn test_string_passes() {
        let def = make_arg("string");
        assert!(validate_arg("test", &def, "hello-world").is_ok());
    }

    #[test]
    fn test_string_metacharacters_rejected_by_default() {
        // String type should reject shell metacharacters by default,
        // even without explicit sanitize = ["injection"].
        let def = make_arg("string");
        assert!(validate_arg("test", &def, "hello; rm -rf /").is_err());
        assert!(validate_arg("test", &def, "$(whoami)").is_err());
        assert!(validate_arg("test", &def, "foo|bar").is_err());
    }

    #[test]
    fn test_unknown_type_rejected() {
        let def = make_arg("foobar");
        assert!(validate_arg("test", &def, "anything").is_err());
        let err = validate_arg("test", &def, "anything")
            .unwrap_err()
            .to_string();
        assert!(err.contains("unknown argument type"));
    }

    #[test]
    fn test_string_injection_rejected() {
        let mut def = make_arg("string");
        def.sanitize = Some(vec!["injection".to_string()]);
        assert!(validate_arg("test", &def, "hello; rm -rf /").is_err());
        assert!(validate_arg("test", &def, "$(whoami)").is_err());
        assert!(validate_arg("test", &def, "foo|bar").is_err());
        assert!(validate_arg("test", &def, "a&b").is_err());
        assert!(validate_arg("test", &def, "x`y`").is_err());
    }

    #[test]
    fn test_string_pattern() {
        let mut def = make_arg("string");
        def.pattern = Some("^[a-z]+$".to_string());
        assert!(validate_arg("test", &def, "hello").is_ok());
        assert!(validate_arg("test", &def, "Hello123").is_err());
    }

    #[test]
    fn test_integer_valid() {
        let def = make_arg("integer");
        assert_eq!(validate_arg("n", &def, "42").unwrap(), "42");
    }

    #[test]
    fn test_integer_invalid() {
        let def = make_arg("integer");
        assert!(validate_arg("n", &def, "abc").is_err());
    }

    #[test]
    fn test_integer_range() {
        let mut def = make_arg("integer");
        def.min = Some(1);
        def.max = Some(64);
        assert!(validate_arg("n", &def, "0").is_err());
        assert!(validate_arg("n", &def, "65").is_err());
        assert!(validate_arg("n", &def, "32").is_ok());
    }

    #[test]
    fn test_integer_clamp() {
        let mut def = make_arg("integer");
        def.min = Some(1);
        def.max = Some(64);
        def.clamp = true;
        assert_eq!(validate_arg("n", &def, "0").unwrap(), "1");
        assert_eq!(validate_arg("n", &def, "100").unwrap(), "64");
    }

    #[test]
    fn test_port_valid() {
        let def = make_arg("port");
        assert_eq!(validate_arg("p", &def, "443").unwrap(), "443");
        assert_eq!(validate_arg("p", &def, "65535").unwrap(), "65535");
    }

    #[test]
    fn test_port_invalid() {
        let def = make_arg("port");
        assert!(validate_arg("p", &def, "0").is_err());
        assert!(validate_arg("p", &def, "70000").is_err());
        assert!(validate_arg("p", &def, "abc").is_err());
    }

    #[test]
    fn test_boolean() {
        let def = make_arg("boolean");
        assert!(validate_arg("b", &def, "true").is_ok());
        assert!(validate_arg("b", &def, "false").is_ok());
        assert!(validate_arg("b", &def, "yes").is_err());
        assert!(validate_arg("b", &def, "1").is_err());
    }

    #[test]
    fn test_enum_valid() {
        let mut def = make_arg("enum");
        def.allowed = Some(vec![
            "ping".to_string(),
            "service".to_string(),
            "syn".to_string(),
        ]);
        assert!(validate_arg("scan", &def, "ping").is_ok());
        assert!(validate_arg("scan", &def, "service").is_ok());
    }

    #[test]
    fn test_enum_invalid() {
        let mut def = make_arg("enum");
        def.allowed = Some(vec!["ping".to_string(), "service".to_string()]);
        assert!(validate_arg("scan", &def, "aggressive").is_err());
    }

    #[test]
    fn test_scope_target_valid() {
        let def = make_arg("scope_target");
        assert!(validate_arg("t", &def, "10.0.1.1").is_ok());
        assert!(validate_arg("t", &def, "10.0.1.0/24").is_ok());
        assert!(validate_arg("t", &def, "example.com").is_ok());
    }

    #[test]
    fn test_scope_target_rejects_wildcards() {
        let def = make_arg("scope_target");
        assert!(validate_arg("t", &def, "*.example.com").is_err());
    }

    #[test]
    fn test_scope_target_rejects_injection() {
        let def = make_arg("scope_target");
        assert!(validate_arg("t", &def, "10.0.1.1; rm -rf /").is_err());
    }

    #[test]
    fn test_url_valid() {
        let def = make_arg("url");
        assert!(validate_arg("u", &def, "http://example.com/path").is_ok());
        assert!(validate_arg("u", &def, "https://test.org").is_ok());
    }

    #[test]
    fn test_url_invalid() {
        let def = make_arg("url");
        assert!(validate_arg("u", &def, "ftp://evil.com").is_err());
        assert!(validate_arg("u", &def, "not a url").is_err());
    }

    #[test]
    fn test_path_no_traversal() {
        let def = make_arg("path");
        assert!(validate_arg("p", &def, "config/settings.toml").is_ok());
        assert!(validate_arg("p", &def, "../../../etc/passwd").is_err());
        assert!(validate_arg("p", &def, "/etc/shadow").is_err()); // absolute paths blocked
        assert!(validate_arg("p", &def, "C:\\Windows\\system32").is_err()); // Windows absolute blocked
    }

    #[test]
    fn test_ip_address() {
        let def = make_arg("ip_address");
        assert!(validate_arg("ip", &def, "192.168.1.1").is_ok());
        assert!(validate_arg("ip", &def, "::1").is_ok());
        assert!(validate_arg("ip", &def, "not-an-ip").is_err());
    }

    #[test]
    fn test_cidr() {
        let def = make_arg("cidr");
        assert!(validate_arg("c", &def, "10.0.0.0/24").is_ok());
        assert!(validate_arg("c", &def, "10.0.0.0/33").is_err());
        assert!(validate_arg("c", &def, "10.0.0.0").is_err());
    }
}
