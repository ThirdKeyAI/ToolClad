use crate::types::{ArgDef, ToolCladError};
use regex::Regex;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::LazyLock;

/// Supported argument types for validation.
pub const SUPPORTED_TYPES: &[&str] = &[
    "string",
    "integer",
    "number",
    "port",
    "boolean",
    "enum",
    "scope_target",
    "url",
    "path",
    "ip_address",
    "cidr",
    "msf_options",
    "credential_file",
    "duration",
    "regex_match",
];

/// Shell metacharacters that are rejected by injection sanitization.
const SHELL_METACHARACTERS: &[char] = &[
    '\n', '\r', ';', '|', '&', '$', '`', '(', ')', '{', '}', '[', ']', '<', '>', '!',
];

/// Compiled regex for IP address formats. Canonical IPv4/IPv6 are validated by
/// strict `std::net` parsers; this regex only frames CIDR notation.
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

    // Network-shaped types (hostname, URL, IP, CIDR) reject leading/trailing
    // whitespace at the source: RFC 1035 / RFC 5891 don't permit terminal
    // whitespace in labels, and silently trimming would let "example.com "
    // through to validators that already passed structural checks.
    let strict_no_whitespace = matches!(
        def.type_name.as_str(),
        "scope_target" | "url" | "ip_address" | "cidr"
    );
    if strict_no_whitespace && val.len() != value.len() {
        return Err(ToolCladError::ValidationError(format!(
            "argument '{name}' must not contain leading or trailing whitespace"
        )));
    }

    // Apply injection sanitization if requested or for types that require it.
    match def.type_name.as_str() {
        "string" => validate_string(name, def, val, true),
        "integer" => validate_integer(name, def, val),
        "number" => validate_number(name, def, val),
        "port" => validate_port(name, val),
        "boolean" => validate_boolean(name, val),
        "enum" => validate_enum(name, def, val),
        "scope_target" => validate_scope_target(name, def, val),
        "url" => validate_url(name, def, val),
        "path" => validate_path(name, val),
        "ip_address" => validate_ip_address(name, val),
        "cidr" => validate_cidr(name, val),
        "msf_options" => validate_msf_options(name, def, val),
        "credential_file" => validate_credential_file(name, def, val),
        "duration" => validate_duration(name, def, val),
        "regex_match" => validate_regex_match(name, def, val),
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

fn validate_number(name: &str, def: &ArgDef, val: &str) -> Result<String, ToolCladError> {
    let mut n: f64 = val.parse().map_err(|_| {
        ToolCladError::ValidationError(format!("argument '{name}' is not a valid number"))
    })?;
    if !n.is_finite() {
        return Err(ToolCladError::ValidationError(format!(
            "argument '{name}' must be a finite number (no NaN or infinity)"
        )));
    }

    let min = def.min_float.or_else(|| def.min.map(|m| m as f64));
    let max = def.max_float.or_else(|| def.max.map(|m| m as f64));

    if let Some(lo) = min {
        if n < lo {
            if def.clamp {
                n = lo;
            } else {
                return Err(ToolCladError::ValidationError(format!(
                    "argument '{name}' value {n} is below minimum {lo}"
                )));
            }
        }
    }
    if let Some(hi) = max {
        if n > hi {
            if def.clamp {
                n = hi;
            } else {
                return Err(ToolCladError::ValidationError(format!(
                    "argument '{name}' value {n} is above maximum {hi}"
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

/// RFC 1035 §2.3.4 caps a fully-qualified domain name at 253 octets
/// (255 wire bytes minus the leading length byte and trailing root label).
/// IPv6 textual form maxes out at 45 chars. We use 253 as the upper bound
/// for any `scope_target` shape: hostnames, IPv4, IPv6, and CIDRs all fit
/// well below it, and rejecting anything longer is defense-in-depth
/// against buffer-pathological payloads.
const SCOPE_TARGET_MAX_LEN: usize = 253;

fn validate_scope_target(name: &str, def: &ArgDef, val: &str) -> Result<String, ToolCladError> {
    reject_injection(name, val)?;
    if val.is_empty() {
        return Err(ToolCladError::ValidationError(format!(
            "argument '{name}' scope_target must not be empty"
        )));
    }
    if val.len() > SCOPE_TARGET_MAX_LEN {
        return Err(ToolCladError::ValidationError(format!(
            "argument '{name}' scope_target exceeds {SCOPE_TARGET_MAX_LEN}-character limit (RFC 1035 §2.3.4)"
        )));
    }
    if val.contains('*') {
        return Err(ToolCladError::ValidationError(format!(
            "argument '{name}' scope_target must not contain wildcards"
        )));
    }

    // Specific failure modes — surface before the generic regex catch-all so that
    // forensic triage and per-fence bite-rate analysis can distinguish attack
    // shapes (traversal vs. escape sequences vs. malformed hostnames vs. IDN bypass).
    if val.contains("../") || val.contains("..\\") || val.contains("/..") {
        return Err(ToolCladError::ValidationError(format!(
            "argument '{name}' scope_target must not contain path traversal sequences"
        )));
    }
    if val.contains('/') && !CIDR_V4_RE.is_match(val) && val.parse::<std::net::IpAddr>().is_err() {
        return Err(ToolCladError::ValidationError(format!(
            "argument '{name}' scope_target must not contain '/' (use CIDR notation for ranges)"
        )));
    }
    if val.contains('\\') {
        return Err(ToolCladError::ValidationError(format!(
            "argument '{name}' scope_target must not contain backslash escape sequences"
        )));
    }
    if !val.is_ascii() {
        return Err(ToolCladError::ValidationError(format!(
            "argument '{name}' scope_target must be ASCII (non-ASCII hostnames including IDN homoglyphs are rejected; gate IDN registration upstream if needed)"
        )));
    }

    // Defense-in-depth against IDN homoglyph bypass via punycode: an attacker who
    // registers a Cyrillic-homoglyph domain (e.g. exаmple.com) and supplies its
    // ASCII punycode form (xn--example-9c.com) would otherwise satisfy the
    // ASCII-strict hostname regex below. Reject any label starting with `xn--`.
    if has_punycode_label(val) {
        return Err(ToolCladError::ValidationError(format!(
            "argument '{name}' scope_target must not contain punycode (xn--) labels — IDN/IDNA hostnames are rejected to prevent homoglyph bypass; gate IDN registration upstream if needed"
        )));
    }

    // Per-label DNS length: RFC 1035 §2.3.4 caps each label at 63 octets. The
    // total-length check above does not bound an individual label.
    if val.split('.').any(|label| label.len() > 63) {
        return Err(ToolCladError::ValidationError(format!(
            "argument '{name}' scope_target has a DNS label exceeding 63 octets (RFC 1035 §2.3.4)"
        )));
    }

    // Canonical IP literals only. Rust's parsers accept ONLY dotted-quad IPv4
    // and standard IPv6, so integer/hex/octal/shorthand encodings (2130706433,
    // 0x7f000001, 0177.0.0.1, 127.1 — all of which a libc resolver would expand
    // to 127.0.0.1) fail here and are rejected as non-canonical literals below.
    if let Some(ip) = parse_canonical_ip(val) {
        enforce_ip_policy(name, &ip, def.block_internal)?;
        return Ok(val.to_string());
    }

    // CIDR ranges. Range-check the base address under policy.
    if let Some(caps) = CIDR_V4_RE.captures(val) {
        if let Ok(base) = caps[1].parse::<Ipv4Addr>() {
            enforce_ip_policy(name, &IpAddr::V4(base), def.block_internal)?;
            return Ok(val.to_string());
        }
    }

    // A non-canonical IP-literal encoding must not slip through as a "hostname":
    // a downstream resolver would expand it to an address. No legitimate hostname
    // is all-numeric labels or a 0x-prefixed hex literal.
    if looks_like_ip_literal(val) {
        return Err(ToolCladError::ValidationError(format!(
            "argument '{name}' scope_target looks like a non-canonical IP literal; use dotted-quad IPv4 or standard IPv6"
        )));
    }

    // Hostname: structural regex plus a non-numeric rightmost label — no valid
    // TLD is all digits (RFC 3696 §2), which also rejects dotted-decimal IPs.
    if HOSTNAME_RE.is_match(val) && tld_not_all_numeric(val) {
        Ok(val.to_string())
    } else {
        Err(ToolCladError::ValidationError(format!(
            "argument '{name}' is not a valid scope target (IP, CIDR, or hostname)"
        )))
    }
}

/// Parse only canonical IP text (dotted-quad IPv4 / standard IPv6). Rejects
/// integer, hex, octal, and shorthand encodings by construction.
fn parse_canonical_ip(val: &str) -> Option<IpAddr> {
    val.parse::<Ipv4Addr>()
        .map(IpAddr::V4)
        .or_else(|_| val.parse::<Ipv6Addr>().map(IpAddr::V6))
        .ok()
}

/// True if `val` is an attempt at an IP literal in a non-canonical encoding:
/// a `0x…` hex form, or every dot-separated label is all ASCII digits
/// (integer / dotted-decimal / octal / shorthand). Canonical IPs are handled
/// earlier and never reach here.
fn looks_like_ip_literal(val: &str) -> bool {
    let lower = val.to_ascii_lowercase();
    if lower.starts_with("0x") {
        return true;
    }
    val.split('.')
        .all(|label| !label.is_empty() && label.bytes().all(|b| b.is_ascii_digit()))
}

/// True if the rightmost DNS label is not entirely numeric (a real TLD is never
/// all digits). Rejects e.g. `example.123` and dotted-decimal IPs.
fn tld_not_all_numeric(val: &str) -> bool {
    match val.rsplit('.').next() {
        Some(tld) => !tld.is_empty() && !tld.bytes().all(|b| b.is_ascii_digit()),
        None => false,
    }
}

/// Reason if `ip` must be blocked regardless of policy: link-local
/// (169.254.0.0/16, fe80::/10), which includes the cloud-metadata endpoint
/// 169.254.169.254. No agent tool has a legitimate reason to reach these, and
/// the blast radius (instance-credential theft) is maximal — so block always,
/// even when `block_internal` is off. v4-mapped IPv6 is unwrapped.
fn always_blocked_ip_reason(ip: &IpAddr) -> Option<&'static str> {
    let v4 = match ip {
        IpAddr::V4(a) => Some(*a),
        IpAddr::V6(a) => a.to_ipv4_mapped(),
    };
    if let Some(a) = v4 {
        return a
            .is_link_local()
            .then_some("is a link-local / cloud-metadata address (169.254.0.0/16) — always blocked");
    }
    if let IpAddr::V6(a) = ip {
        if (a.segments()[0] & 0xffc0) == 0xfe80 {
            return Some("is an IPv6 link-local address (fe80::/10) — always blocked");
        }
    }
    None
}

/// Enforce the egress policy for a resolved target IP: link-local / metadata is
/// always blocked; the remaining non-public ranges are blocked only under the
/// opt-in `block_internal` policy.
fn enforce_ip_policy(name: &str, ip: &IpAddr, block_internal: bool) -> Result<(), ToolCladError> {
    if let Some(reason) = always_blocked_ip_reason(ip) {
        return Err(ToolCladError::ValidationError(format!(
            "argument '{name}' target {reason}"
        )));
    }
    if block_internal {
        if let Some(reason) = non_public_ip_reason(ip) {
            return Err(ToolCladError::ValidationError(format!(
                "argument '{name}' target {reason} (blocked by block_internal policy)"
            )));
        }
    }
    Ok(())
}

/// Returns a reason string if `ip` is a non-public address that SSRF defenses
/// should block: loopback, private, link-local (incl. cloud metadata), etc.
/// IPv6 v4-mapped addresses are unwrapped so `::ffff:127.0.0.1` is caught.
fn non_public_ip_reason(ip: &IpAddr) -> Option<&'static str> {
    let v4 = match ip {
        IpAddr::V4(a) => Some(*a),
        IpAddr::V6(a) => a.to_ipv4_mapped(),
    };
    if let Some(a) = v4 {
        return if a.is_loopback() {
            Some("resolves to a loopback address")
        } else if a.is_private() {
            Some("resolves to a private address")
        } else if a.is_link_local() {
            Some("resolves to a link-local address (e.g. cloud metadata 169.254.169.254)")
        } else if a.is_unspecified() {
            Some("is the unspecified address 0.0.0.0")
        } else if a.is_broadcast() {
            Some("is the broadcast address")
        } else if a.is_documentation() {
            Some("is a documentation-range address")
        } else {
            None
        };
    }
    if let IpAddr::V6(a) = ip {
        if a.is_loopback() {
            return Some("resolves to the IPv6 loopback ::1");
        }
        if a.is_unspecified() {
            return Some("is the IPv6 unspecified address ::");
        }
        let first = a.segments()[0];
        if (first & 0xfe00) == 0xfc00 {
            return Some("is an IPv6 unique-local address (fc00::/7)");
        }
        if (first & 0xffc0) == 0xfe80 {
            return Some("is an IPv6 link-local address (fe80::/10)");
        }
    }
    None
}

/// Returns true if any DNS label in `host` is an A-label (`xn--…`).
/// Comparison is case-insensitive per IDNA: `XN--`, `Xn--`, `xN--` all count.
fn has_punycode_label(host: &str) -> bool {
    host.split('.')
        .any(|label| label.len() >= 4 && label.as_bytes()[..4].eq_ignore_ascii_case(b"xn--"))
}

fn validate_url(name: &str, def: &ArgDef, val: &str) -> Result<String, ToolCladError> {
    reject_injection(name, val)?;
    if !URL_RE.is_match(val) {
        return Err(ToolCladError::ValidationError(format!(
            "argument '{name}' is not a valid URL"
        )));
    }
    // Apply the same host hygiene as scope_target — curl/wget-style fetchers are
    // the prime SSRF vector. URL_RE guarantees `scheme://host[/path]` with a
    // simple host (no port/userinfo/brackets), so the host is everything between
    // "://" and the first "/".
    let host = val
        .split_once("://")
        .map(|(_, rest)| rest.split('/').next().unwrap_or(""))
        .unwrap_or("");
    if has_punycode_label(host) {
        return Err(ToolCladError::ValidationError(format!(
            "argument '{name}' URL host must not contain punycode (xn--) labels"
        )));
    }
    if let Some(ip) = parse_canonical_ip(host) {
        enforce_ip_policy(name, &ip, def.block_internal)?;
    } else if looks_like_ip_literal(host) {
        return Err(ToolCladError::ValidationError(format!(
            "argument '{name}' URL host looks like a non-canonical IP literal; use dotted-quad IPv4 or a hostname"
        )));
    }
    Ok(val.to_string())
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

fn validate_msf_options(name: &str, _def: &ArgDef, val: &str) -> Result<String, ToolCladError> {
    let msf_key_re = Regex::new(r"^[A-Z][A-Z0-9_]*$").unwrap();
    for pair in val.split(';') {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        let parts: Vec<&str> = pair.splitn(2, ' ').collect();
        if parts.len() != 2 {
            return Err(ToolCladError::ValidationError(format!(
                "argument '{name}' msf_options: invalid pair '{pair}' (expected 'KEY VALUE')"
            )));
        }
        if !msf_key_re.is_match(parts[0]) {
            return Err(ToolCladError::ValidationError(format!(
                "argument '{name}' msf_options: invalid key '{}' (must be uppercase alphanumeric)",
                parts[0]
            )));
        }
        // Check value for injection (excluding ; which is the delimiter)
        for ch in &[
            '\n', '\r', '|', '&', '$', '`', '(', ')', '{', '}', '[', ']', '<', '>', '!',
        ] {
            if parts[1].contains(*ch) {
                return Err(ToolCladError::ValidationError(format!(
                    "argument '{name}' msf_options: value contains disallowed character '{ch}'"
                )));
            }
        }
    }
    Ok(val.to_string())
}

fn validate_credential_file(name: &str, _def: &ArgDef, val: &str) -> Result<String, ToolCladError> {
    reject_injection(name, val)?;
    if val.starts_with('/') || (val.len() >= 2 && val.as_bytes()[1] == b':') {
        return Err(ToolCladError::ValidationError(format!(
            "argument '{name}' must be a relative path"
        )));
    }
    if val.contains("../") || val.contains("..\\") {
        return Err(ToolCladError::ValidationError(format!(
            "argument '{name}' path must not contain traversal sequences"
        )));
    }
    let path = std::path::Path::new(val);
    if !path.exists() {
        return Err(ToolCladError::ValidationError(format!(
            "argument '{name}' credential file not found: {val}"
        )));
    }
    if !path.is_file() {
        return Err(ToolCladError::ValidationError(format!(
            "argument '{name}' is not a file: {val}"
        )));
    }
    Ok(val.to_string())
}

fn validate_duration(name: &str, _def: &ArgDef, val: &str) -> Result<String, ToolCladError> {
    // Try plain integer (seconds)
    if val.parse::<u64>().is_ok() {
        return Ok(val.to_string());
    }
    // Parse duration suffixes: ms, s, m, h
    let duration_re = Regex::new(r"^(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?(?:(\d+)ms)?$").unwrap();
    if !duration_re.is_match(val) {
        return Err(ToolCladError::ValidationError(format!(
            "argument '{name}' is not a valid duration (e.g. '30', '5m', '2h', '1h30m', '500ms')"
        )));
    }
    Ok(val.to_string())
}

fn validate_regex_match(name: &str, def: &ArgDef, val: &str) -> Result<String, ToolCladError> {
    reject_injection(name, val)?;
    let pat = def.pattern.as_ref().ok_or_else(|| {
        ToolCladError::ManifestError(format!(
            "argument '{name}' is type 'regex_match' but has no 'pattern' field"
        ))
    })?;
    let re = Regex::new(pat)
        .map_err(|e| ToolCladError::ManifestError(format!("invalid pattern for '{name}': {e}")))?;
    if !re.is_match(val) {
        return Err(ToolCladError::ValidationError(format!(
            "argument '{name}' does not match required pattern '{pat}'"
        )));
    }
    Ok(val.to_string())
}

/// Validate an argument using custom type definitions.
/// If the arg type matches a custom type, create a synthetic ArgDef from the custom type
/// and delegate to the base type validator.
pub fn validate_arg_with_custom_types(
    name: &str,
    def: &ArgDef,
    value: &str,
    custom_types: &std::collections::HashMap<String, crate::types::CustomTypeDef>,
) -> Result<String, ToolCladError> {
    // Check if the type is a custom type
    if let Some(custom) = custom_types.get(&def.type_name) {
        // Verify the base type is valid
        if !SUPPORTED_TYPES.contains(&custom.base.as_str()) {
            return Err(ToolCladError::ManifestError(format!(
                "custom type '{}' has invalid base type '{}'",
                def.type_name, custom.base
            )));
        }
        // Create a synthetic ArgDef with the custom type's constraints merged
        let mut synthetic = def.clone();
        synthetic.type_name = custom.base.clone();
        if let Some(ref allowed) = custom.allowed {
            synthetic.allowed = Some(allowed.clone());
        }
        if let Some(ref pattern) = custom.pattern {
            synthetic.pattern = Some(pattern.clone());
        }
        if let Some(min) = custom.min {
            synthetic.min = Some(min);
        }
        if let Some(max) = custom.max {
            synthetic.max = Some(max);
        }
        if let Some(min_f) = custom.min_float {
            synthetic.min_float = Some(min_f);
        }
        if let Some(max_f) = custom.max_float {
            synthetic.max_float = Some(max_f);
        }
        return validate_arg(name, &synthetic, value);
    }

    // Not a custom type, use standard validation
    validate_arg(name, def, value)
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
    fn test_scope_target_rejects_trailing_whitespace() {
        // RFC 1035 / RFC 5891 don't permit terminal whitespace in hostname
        // labels. Trimming silently was hiding malformed input.
        let def = make_arg("scope_target");
        let err = validate_arg("t", &def, "example.com ")
            .unwrap_err()
            .to_string();
        assert!(err.contains("whitespace"), "unexpected message: {}", err);
        assert!(validate_arg("t", &def, " example.com").is_err());
        assert!(validate_arg("t", &def, "\texample.com").is_err());
        assert!(validate_arg("t", &def, "example.com\n").is_err());
    }

    #[test]
    fn test_scope_target_rejects_overlong() {
        // RFC 1035 §2.3.4 caps FQDN length at 253 octets. 254+ should refuse.
        let def = make_arg("scope_target");
        let too_long = "a".repeat(254);
        let err = validate_arg("t", &def, &too_long).unwrap_err().to_string();
        assert!(err.contains("253"), "unexpected message: {}", err);
        // 4096-char buffer-pathological payload from cross-impl test harness.
        let pathological = "a".repeat(4096);
        assert!(validate_arg("t", &def, &pathological).is_err());
    }

    #[test]
    fn test_scope_target_rejects_empty() {
        let def = make_arg("scope_target");
        assert!(validate_arg("t", &def, "").is_err());
    }

    #[test]
    fn test_scope_target_rejects_punycode() {
        // Defense-in-depth against IDN homoglyph bypass: an attacker who
        // registers exаmple.com (Cyrillic а) and supplies its punycode form
        // xn--example-9c.com would otherwise satisfy the ASCII-only regex.
        let def = make_arg("scope_target");
        let err = validate_arg("t", &def, "xn--example-9c.com")
            .unwrap_err()
            .to_string();
        assert!(err.contains("punycode"));
        // Mid-label and mixed-case forms are also caught.
        assert!(validate_arg("t", &def, "sub.xn--80ak6aa92e.com").is_err());
        assert!(validate_arg("t", &def, "XN--example-9c.com").is_err());
    }

    #[test]
    fn test_scope_target_rejects_non_ascii() {
        let def = make_arg("scope_target");
        let err = validate_arg("t", &def, "exаmple.com")
            .unwrap_err()
            .to_string();
        assert!(err.contains("ASCII"));
    }

    #[test]
    fn test_scope_target_rejects_obfuscated_ip_literals() {
        // A libc resolver expands all of these to 127.0.0.1 — they must not
        // pass as canonical IPs or sneak through as "hostnames".
        let def = make_arg("scope_target");
        for v in [
            "2130706433",  // decimal integer
            "0x7f000001",  // hex
            "0177.0.0.1",  // octal-leading
            "127.1",       // shorthand
            "010.0.0.1",   // leading-zero octet
        ] {
            assert!(validate_arg("t", &def, v).is_err(), "should reject {v}");
        }
        // Canonical forms still pass (no block_internal policy here).
        assert!(validate_arg("t", &def, "127.0.0.1").is_ok());
        assert!(validate_arg("t", &def, "93.184.216.34").is_ok());
        assert!(validate_arg("t", &def, "::1").is_ok());
    }

    #[test]
    fn test_scope_target_rejects_overlong_label() {
        // RFC 1035 §2.3.4: a single label may not exceed 63 octets, even when
        // the whole name is under the 253-octet cap.
        let def = make_arg("scope_target");
        let label64 = format!("{}.com", "a".repeat(64));
        let err = validate_arg("t", &def, &label64).unwrap_err().to_string();
        assert!(err.contains("63"), "unexpected message: {err}");
        // 63 is allowed.
        assert!(validate_arg("t", &def, &format!("{}.com", "a".repeat(63))).is_ok());
    }

    #[test]
    fn test_scope_target_rejects_numeric_tld() {
        let def = make_arg("scope_target");
        assert!(validate_arg("t", &def, "example.123").is_err());
    }

    fn blocking_arg() -> ArgDef {
        ArgDef {
            type_name: "scope_target".to_string(),
            block_internal: true,
            ..Default::default()
        }
    }

    #[test]
    fn test_scope_target_block_internal_off_allows_internal_by_default() {
        // Default policy is permissive for loopback/private — tools that
        // legitimately target internal hosts keep working without opt-in.
        let def = make_arg("scope_target");
        assert!(validate_arg("t", &def, "127.0.0.1").is_ok());
        assert!(validate_arg("t", &def, "10.0.0.5").is_ok());
        assert!(validate_arg("t", &def, "::1").is_ok());
        // ...but link-local / cloud metadata is blocked UNCONDITIONALLY.
        assert!(validate_arg("t", &def, "169.254.169.254").is_err());
    }

    #[test]
    fn test_scope_target_blocks_metadata_unconditionally() {
        let def = make_arg("scope_target"); // block_internal = false
        for v in ["169.254.169.254", "169.254.0.1", "::ffff:169.254.169.254", "fe80::1"] {
            let err = validate_arg("t", &def, v).unwrap_err().to_string();
            assert!(err.contains("always blocked"), "{v} -> {err}");
        }
    }

    #[test]
    fn test_scope_target_block_internal_on_rejects_non_public() {
        let def = blocking_arg();
        for v in [
            "127.0.0.1",
            "10.0.0.5",
            "192.168.1.1",
            "169.254.169.254",  // IMDS (always-block path)
            "0.0.0.0",
            "::1",
            "::ffff:127.0.0.1", // v4-mapped loopback must be unwrapped
            "fe80::1",          // IPv6 link-local
            "fc00::1",          // IPv6 unique-local
        ] {
            assert!(validate_arg("t", &def, v).is_err(), "{v} should be blocked");
        }
        // Public addresses and hostnames still pass under the policy.
        assert!(validate_arg("t", &def, "93.184.216.34").is_ok());
        assert!(validate_arg("t", &def, "example.com").is_ok());
        // CIDR with an internal base is blocked too.
        assert!(validate_arg("t", &def, "10.0.0.0/24").is_err());
    }

    #[test]
    fn test_url_host_hardening() {
        let public = make_arg("url");
        // valid public URL passes
        assert!(validate_arg("u", &public, "https://example.com/path").is_ok());
        assert!(validate_arg("u", &public, "http://93.184.216.34/x").is_ok());
        // cloud metadata blocked unconditionally, even without block_internal
        assert!(validate_arg("u", &public, "http://169.254.169.254/latest/meta-data/").is_err());
        // obfuscated IP hosts rejected
        assert!(validate_arg("u", &public, "http://0x7f000001/").is_err());
        assert!(validate_arg("u", &public, "http://2130706433/").is_err());
        // punycode host rejected
        assert!(validate_arg("u", &public, "http://xn--example-9c.com/").is_err());
        // loopback allowed only when block_internal is off
        assert!(validate_arg("u", &public, "http://127.0.0.1/").is_ok());
        let blocking = ArgDef { type_name: "url".to_string(), block_internal: true, ..Default::default() };
        assert!(validate_arg("u", &blocking, "http://127.0.0.1/").is_err());
        assert!(validate_arg("u", &blocking, "http://10.0.0.5/x").is_err());
    }

    #[test]
    fn test_scope_target_specific_traversal_message() {
        // ../../etc/passwd previously collapsed into the generic
        // "is not a valid scope target" — make sure the specific reason wins.
        let def = make_arg("scope_target");
        let err = validate_arg("t", &def, "../../etc/passwd")
            .unwrap_err()
            .to_string();
        assert!(err.contains("traversal"));
    }

    #[test]
    fn test_scope_target_specific_slash_message() {
        let def = make_arg("scope_target");
        let err = validate_arg("t", &def, "/etc/passwd")
            .unwrap_err()
            .to_string();
        assert!(err.contains("'/'"));
    }

    #[test]
    fn test_scope_target_specific_backslash_message() {
        let def = make_arg("scope_target");
        let err = validate_arg("t", &def, "example.com\\nINJECTED")
            .unwrap_err()
            .to_string();
        assert!(err.contains("backslash"));
    }

    #[test]
    fn test_number_basic() {
        let def = make_arg("number");
        assert_eq!(validate_arg("n", &def, "0.5").unwrap(), "0.5");
        assert!(validate_arg("n", &def, "abc").is_err());
        assert!(validate_arg("n", &def, "NaN").is_err());
        assert!(validate_arg("n", &def, "inf").is_err());
    }

    #[test]
    fn test_number_min_max() {
        let mut def = make_arg("number");
        def.min_float = Some(0.0);
        def.max_float = Some(1.0);
        assert!(validate_arg("conf", &def, "0.5").is_ok());
        assert!(validate_arg("conf", &def, "-0.1").is_err());
        assert!(validate_arg("conf", &def, "1.5").is_err());
    }

    #[test]
    fn test_number_min_max_falls_back_to_int_bounds() {
        let mut def = make_arg("number");
        def.min = Some(1);
        def.max = Some(10);
        assert!(validate_arg("n", &def, "5.5").is_ok());
        assert!(validate_arg("n", &def, "0.5").is_err());
        assert!(validate_arg("n", &def, "11.0").is_err());
    }

    #[test]
    fn test_number_clamp() {
        let mut def = make_arg("number");
        def.min_float = Some(0.0);
        def.max_float = Some(1.0);
        def.clamp = true;
        assert_eq!(validate_arg("n", &def, "-5").unwrap(), "0");
        assert_eq!(validate_arg("n", &def, "5").unwrap(), "1");
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

    #[test]
    fn test_msf_options_valid() {
        let def = make_arg("msf_options");
        assert!(validate_arg("opts", &def, "RHOSTS 10.0.1.1;RPORT 445").is_ok());
    }

    #[test]
    fn test_msf_options_invalid_key() {
        let def = make_arg("msf_options");
        assert!(validate_arg("opts", &def, "rhosts 10.0.1.1").is_err()); // lowercase
    }

    #[test]
    fn test_msf_options_injection() {
        let def = make_arg("msf_options");
        assert!(validate_arg("opts", &def, "RHOSTS $(whoami)").is_err());
    }

    #[test]
    fn test_credential_file_rejects_absolute() {
        let def = make_arg("credential_file");
        assert!(validate_arg("f", &def, "/etc/shadow").is_err());
    }

    #[test]
    fn test_credential_file_rejects_traversal() {
        let def = make_arg("credential_file");
        assert!(validate_arg("f", &def, "../../../etc/passwd").is_err());
    }

    #[test]
    fn test_duration_plain_seconds() {
        let def = make_arg("duration");
        assert_eq!(validate_arg("t", &def, "30").unwrap(), "30");
    }

    #[test]
    fn test_duration_with_suffix() {
        let def = make_arg("duration");
        assert!(validate_arg("t", &def, "5m").is_ok());
        assert!(validate_arg("t", &def, "2h").is_ok());
        assert!(validate_arg("t", &def, "1h30m").is_ok());
        assert!(validate_arg("t", &def, "500ms").is_ok());
    }

    #[test]
    fn test_duration_invalid() {
        let def = make_arg("duration");
        assert!(validate_arg("t", &def, "abc").is_err());
    }

    #[test]
    fn test_regex_match_valid() {
        let mut def = make_arg("regex_match");
        def.pattern = Some(r"^\d{3}-\d{4}$".to_string());
        assert!(validate_arg("code", &def, "123-4567").is_ok());
    }

    #[test]
    fn test_regex_match_invalid() {
        let mut def = make_arg("regex_match");
        def.pattern = Some(r"^\d{3}-\d{4}$".to_string());
        assert!(validate_arg("code", &def, "abc").is_err());
    }

    #[test]
    fn test_regex_match_no_pattern() {
        let def = make_arg("regex_match");
        assert!(validate_arg("code", &def, "anything").is_err()); // missing pattern
    }
}
