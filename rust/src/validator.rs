use crate::hostpolicy::{
    enforce_cidr_policy, enforce_hostname_policy, enforce_ip_policy, has_punycode_label,
    looks_like_ip_literal, parse_canonical_ip, parse_cidr,
};
use crate::types::{ArgDef, ToolCladError};
use regex::Regex;
use std::net::{IpAddr, Ipv6Addr};
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

/// Hostname grammar: LDH labels, no leading or trailing hyphen, no empty
/// label, no trailing dot. IP literals and CIDRs are parsed by the strict
/// `crate::hostpolicy` parsers before a value is matched against this.
static HOSTNAME_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$",
    )
    .unwrap()
});
/// Schemes a `url` argument accepts when the manifest sets no `schemes`.
const DEFAULT_URL_SCHEMES: &[&str] = &["http", "https"];

/// Schemes a `url` argument never accepts, even when a manifest lists one in
/// `schemes`: each is either a non-network scheme a fetcher would turn into
/// local file or code access, or a protocol-smuggling vector (gopher and dict
/// speak raw bytes to an arbitrary port).
const DENIED_URL_SCHEMES: &[&str] = &[
    "javascript",
    "data",
    "file",
    "blob",
    "about",
    "gopher",
    "dict",
    "ftp",
    "ldap",
    "jar",
    "netdoc",
    "mailto",
    "ws",
    "wss",
];

/// Types whose value is user text handed to the target binary more or less
/// verbatim. They get the W1.5 hygiene rules (NUL, control characters,
/// quotes/backslash, whitespace, leading dash) before any type parsing.
pub const STRING_DERIVED_TYPES: &[&str] = &[
    "string",
    "path",
    "credential_file",
    "regex_match",
    "url",
    "scope_target",
    "duration",
    "msf_options",
];

/// Validate a single argument value against its definition.
///
/// Returns the (possibly transformed) value on success, or a validation error.
///
/// This is the strict (template-mode) entry point: `allow_whitespace` is not
/// honored. Use [`validate_arg_mode`] to validate for a manifest that declared
/// `command.exec` directly.
pub fn validate_arg(name: &str, def: &ArgDef, value: &str) -> Result<String, ToolCladError> {
    validate_arg_mode(name, def, value, false)
}

/// Validate a single argument value, stating whether the manifest's command
/// form is a declared `exec` array (`exec_mode = true`).
///
/// `exec_mode` only affects `allow_whitespace`: an `exec` element is one argv
/// entry that is never re-split, so whitespace inside it is safe to opt into.
/// A `template` — even one compiled to exec at load — stays strict.
pub fn validate_arg_mode(
    name: &str,
    def: &ArgDef,
    value: &str,
    exec_mode: bool,
) -> Result<String, ToolCladError> {
    // Rule 1 applies to every type, enum and numerics included.
    if value.contains('\0') {
        return Err(ToolCladError::ValidationError(format!(
            "argument '{name}' must not contain NUL bytes"
        )));
    }

    let type_name = def.type_name.as_str();
    if STRING_DERIVED_TYPES.contains(&type_name) {
        // Hygiene runs on the raw value: nothing is trimmed away first.
        check_value_hygiene(name, def, value, exec_mode)?;
        return match type_name {
            "string" => validate_string(name, def, value, true),
            "scope_target" => validate_scope_target(name, def, value),
            "url" => validate_url(name, def, value),
            "path" => validate_path(name, value),
            "msf_options" => validate_msf_options(name, def, value),
            "credential_file" => validate_credential_file(name, def, value),
            "duration" => validate_duration(name, def, value),
            "regex_match" => validate_regex_match(name, def, value),
            _ => unreachable!("string-derived type dispatch is exhaustive"),
        };
    }

    let val = value.trim();

    // IP and CIDR literals reject leading/trailing whitespace at the source;
    // silently trimming would let "10.0.0.1 " through to validators that
    // already passed structural checks.
    let strict_no_whitespace = matches!(type_name, "ip_address" | "cidr");
    if strict_no_whitespace && val.len() != value.len() {
        return Err(ToolCladError::ValidationError(format!(
            "argument '{name}' must not contain leading or trailing whitespace"
        )));
    }

    match type_name {
        // Numeric types apply the leading-dash rule to the output, after
        // range checks and clamping, so `-5` with `clamp` and `min = 1`
        // yields `1` and passes while a bare `-1` is refused.
        "integer" => validate_integer(name, def, val)
            .and_then(|out| reject_leading_dash(name, def, &out).map(|_| out)),
        "number" => validate_number(name, def, val)
            .and_then(|out| reject_leading_dash(name, def, &out).map(|_| out)),
        "port" => validate_port(name, val)
            .and_then(|out| reject_leading_dash(name, def, &out).map(|_| out)),
        "boolean" => validate_boolean(name, val),
        "enum" => validate_enum(name, def, val),
        "ip_address" => validate_ip_address(name, def, val),
        "cidr" => validate_cidr(name, def, val),
        _ => Err(ToolCladError::ValidationError(format!(
            "unknown argument type '{}' for '{}'",
            def.type_name, name
        ))),
    }
}

/// True for C0 control characters (U+0000–U+001F), DEL (U+007F), and the C1
/// range (U+0080–U+009F). Tab, newline, carriage return, vertical tab and form
/// feed are all included: a tool argument never needs a control byte, and
/// `\r`/`\n` are the line-injection characters.
fn is_control_char(c: char) -> bool {
    let cp = c as u32;
    cp < 0x20 || (0x7f..=0x9f).contains(&cp)
}

/// Reject a value that starts with `-` or `+` unless the arg opts in with
/// `allow_leading_dash = true`. Such a value would otherwise be parsed by the
/// target binary as an option.
fn reject_leading_dash(name: &str, def: &ArgDef, value: &str) -> Result<(), ToolCladError> {
    if !def.allow_leading_dash && (value.starts_with('-') || value.starts_with('+')) {
        return Err(ToolCladError::ValidationError(format!(
            "argument '{name}' must not start with '-' or '+' (set allow_leading_dash = true to permit)"
        )));
    }
    Ok(())
}

/// W1.5 string-derived value hygiene, checked in order before any
/// type-specific parsing: control characters, quotes/backslash, whitespace,
/// leading dash. (NUL is checked by the caller for every type.)
fn check_value_hygiene(
    name: &str,
    def: &ArgDef,
    value: &str,
    exec_mode: bool,
) -> Result<(), ToolCladError> {
    let type_name = def.type_name.as_str();
    // `msf_options` needs the space as its `KEY VALUE` separator. A `url`
    // never contains whitespace, opt-in or not. Everything else may opt in
    // only when the command form is a declared exec array. Either way the
    // only whitespace ever admitted is the ASCII space U+0020: a tab or a
    // newline is line injection, and a non-breaking or ideographic space is a
    // homoglyph, not a separator.
    let space_allowed =
        type_name == "msf_options" || (def.allow_whitespace && exec_mode && type_name != "url");

    // Rule 2 is unconditional; `allow_whitespace` never relaxes it.
    if value.chars().any(is_control_char) {
        return Err(ToolCladError::ValidationError(format!(
            "argument '{name}' must not contain control characters"
        )));
    }

    if type_name == "scope_target" && value.contains('\\') {
        return Err(ToolCladError::ValidationError(format!(
            "argument '{name}' scope_target must not contain backslash escape sequences"
        )));
    }
    if value.contains(['\'', '"', '\\']) {
        return Err(ToolCladError::ValidationError(format!(
            "argument '{name}' must not contain quote or backslash characters"
        )));
    }

    if value
        .chars()
        .any(|c| c.is_whitespace() && !(space_allowed && c == ' '))
    {
        return Err(ToolCladError::ValidationError(format!(
            "argument '{name}' must not contain whitespace"
        )));
    }

    reject_leading_dash(name, def, value)
}

/// Anchor a user-supplied pattern so it must match the whole value: strip one
/// leading `^` and one trailing unescaped `$`, then wrap as `^(?:<pat>)$`.
/// Without this, `pattern = "[a-z]+"` would accept `abc123`.
pub fn anchor_pattern(pat: &str) -> String {
    let inner = pat.strip_prefix('^').unwrap_or(pat);
    let inner = match inner.strip_suffix('$') {
        Some(stripped) if !stripped.ends_with('\\') => stripped,
        _ => inner,
    };
    format!("^(?:{inner})$")
}

/// Compile an arg's `pattern`, anchored, surfacing a bad pattern as a
/// manifest error.
fn compile_anchored(name: &str, pat: &str) -> Result<Regex, ToolCladError> {
    Regex::new(&anchor_pattern(pat))
        .map_err(|e| ToolCladError::ManifestError(format!("invalid pattern for '{name}': {e}")))
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
        let re = compile_anchored(name, pat)?;
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
    if val.contains('/') && parse_cidr(val).is_none() {
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

    // CIDR ranges (IPv4 or IPv6, strictly framed): the whole range is tested
    // for overlap with the blocked prefixes, not just its base address.
    if let Some(net) = parse_cidr(val) {
        enforce_cidr_policy(name, &net, def.block_internal)?;
        return Ok(val.to_string());
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
    if !(HOSTNAME_RE.is_match(val) && tld_not_all_numeric(val)) {
        return Err(ToolCladError::ValidationError(format!(
            "argument '{name}' is not a valid scope target (IP, CIDR, or hostname)"
        )));
    }

    // A well-formed name: internal-name denylist (always), embedded IP
    // literal (treated as that address), and under `block_internal` DNS
    // resolution with the range policy applied to every answer.
    enforce_hostname_policy(name, val, def.block_internal)?;
    Ok(val.to_string())
}

/// True if the rightmost DNS label is not entirely numeric (a real TLD is never
/// all digits). Rejects e.g. `example.123` and dotted-decimal IPs.
fn tld_not_all_numeric(val: &str) -> bool {
    match val.rsplit('.').next() {
        Some(tld) => !tld.is_empty() && !tld.bytes().all(|b| b.is_ascii_digit()),
        None => false,
    }
}

/// The host part of a URL authority, split from its optional port.
#[derive(Debug, PartialEq, Eq)]
struct UrlHost<'a> {
    host: &'a str,
    /// Validated port, when one was written.
    port: Option<u16>,
    /// Set when the host was a bracketed IPv6 literal, already parsed.
    bracketed_v6: Option<Ipv6Addr>,
}

/// Split a URL authority (everything between `://` and the first `/`, `?` or
/// `#`, with userinfo already refused) into host and port. A bracketed IPv6
/// literal is unwrapped; an unbracketed one is ambiguous with a port and
/// refused. A written port must be 1–65535 in plain decimal digits.
fn split_url_authority<'a>(name: &str, authority: &'a str) -> Result<UrlHost<'a>, ToolCladError> {
    let malformed_v6 = || {
        ToolCladError::ValidationError(format!(
            "argument '{name}' URL has a malformed bracketed IPv6 host"
        ))
    };

    let (host, port_text, bracketed_v6) = if let Some(after_open) = authority.strip_prefix('[') {
        let (inner, after_close) = after_open.split_once(']').ok_or_else(malformed_v6)?;
        let port_text = match after_close {
            "" => None,
            p => Some(p.strip_prefix(':').ok_or_else(malformed_v6)?),
        };
        let v6 = inner.parse::<Ipv6Addr>().map_err(|_| {
            ToolCladError::ValidationError(format!(
                "argument '{name}' URL bracketed host is not a valid IPv6 literal"
            ))
        })?;
        (inner, port_text, Some(v6))
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h, Some(p), None),
            None => (authority, None, None),
        }
    };

    if host.is_empty() {
        return Err(ToolCladError::ValidationError(format!(
            "argument '{name}' URL has an empty host"
        )));
    }
    if bracketed_v6.is_none() && host.contains(':') {
        return Err(ToolCladError::ValidationError(format!(
            "argument '{name}' URL IPv6 host must be enclosed in brackets"
        )));
    }

    let port = match port_text {
        None => None,
        Some(p) => {
            // Plain decimal only: `u16::from_str` would accept a leading `+`.
            let parsed = if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) {
                p.parse::<u16>().ok().filter(|n| *n >= 1)
            } else {
                None
            };
            Some(parsed.ok_or_else(|| {
                ToolCladError::ValidationError(format!(
                    "argument '{name}' URL port must be 1-65535"
                ))
            })?)
        }
    };

    Ok(UrlHost {
        host,
        port,
        bracketed_v6,
    })
}

/// The `url` validator, in order: the string-derived hygiene has already run
/// (whitespace is never admitted for a `url`, opt-in or not); then the shell
/// metacharacter blocklist, which rejects `{` and `}` and therefore any
/// `{_secret:…}` reference; then a structural parse — `scheme://`, the scheme
/// allowlist, the scheme denylist, no userinfo, host extraction with an
/// optional port — and finally the host policy of `crate::hostpolicy`.
///
/// This is deliberately not a WHATWG / RFC 3986 normalizer. The fetcher
/// downstream will parse the value again with its own rules, so anything a
/// human reviewer of the manifest could misread is refused here rather than
/// normalized away.
fn validate_url(name: &str, def: &ArgDef, val: &str) -> Result<String, ToolCladError> {
    reject_injection(name, val)?;

    // Step 2: `scheme://rest`.
    let Some((scheme, rest)) = val.split_once("://") else {
        return Err(ToolCladError::ValidationError(format!(
            "argument '{name}' is not a valid URL (expected scheme://host)"
        )));
    };
    let scheme = scheme.to_ascii_lowercase();

    // Step 3: allowlist — the manifest's `schemes` when set, else http/https.
    let allowed: Vec<String> = if def.schemes.is_empty() {
        DEFAULT_URL_SCHEMES.iter().map(|s| s.to_string()).collect()
    } else {
        def.schemes.iter().map(|s| s.to_ascii_lowercase()).collect()
    };
    if !allowed.contains(&scheme) {
        return Err(ToolCladError::ValidationError(format!(
            "argument '{name}' URL scheme '{scheme}' is not permitted (allowed: {})",
            allowed.join(", ")
        )));
    }

    // Step 4: explicit denial, even when a manifest lists the scheme.
    if DENIED_URL_SCHEMES.contains(&scheme.as_str()) {
        return Err(ToolCladError::ValidationError(format!(
            "argument '{name}' URL scheme '{scheme}' is never permitted for a url argument"
        )));
    }

    // Step 5: the authority ends at the first `/`, `?` or `#`. An `@` before
    // that is userinfo, which hides the real host from a reviewer.
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    if authority.contains('@') {
        return Err(ToolCladError::ValidationError(format!(
            "argument '{name}' URL must not contain userinfo (user:pass@host)"
        )));
    }

    // Step 6: host and optional port.
    let UrlHost {
        host,
        port: _,
        bracketed_v6,
    } = split_url_authority(name, authority)?;

    // Step 7: host policy — the same checks as `scope_target`, since curl and
    // wget-style fetchers are the prime SSRF vector.
    if has_punycode_label(host) {
        return Err(ToolCladError::ValidationError(format!(
            "argument '{name}' URL host must not contain punycode (xn--) labels"
        )));
    }
    let ip = bracketed_v6
        .map(IpAddr::V6)
        .or_else(|| parse_canonical_ip(host));
    match ip {
        Some(ip) => enforce_ip_policy(name, &ip, def.block_internal)?,
        None => {
            if !host.is_ascii() {
                return Err(ToolCladError::ValidationError(format!(
                    "argument '{name}' URL host must be ASCII (IDN hostnames are rejected to prevent homoglyph bypass)"
                )));
            }
            if looks_like_ip_literal(host) {
                return Err(ToolCladError::ValidationError(format!(
                    "argument '{name}' URL host looks like a non-canonical IP literal; use dotted-quad IPv4 or a hostname"
                )));
            }
            if host.len() > SCOPE_TARGET_MAX_LEN || host.split('.').any(|label| label.len() > 63) {
                return Err(ToolCladError::ValidationError(format!(
                    "argument '{name}' URL host exceeds DNS length limits (RFC 1035 §2.3.4)"
                )));
            }
            if !HOSTNAME_RE.is_match(host) {
                return Err(ToolCladError::ValidationError(format!(
                    "argument '{name}' URL host is not a valid hostname or IP literal"
                )));
            }
            // The same name rules as `scope_target`: internal-name denylist
            // (always), embedded IP literal (treated as that address), and
            // under `block_internal` DNS resolution of every answer.
            enforce_hostname_policy(name, host, def.block_internal)?;
        }
    }

    // Step 8 — SCOPE HOOK: when `def.scope_check` is set, the scope checker
    // (a later wave) is consulted here with `host`. Not implemented yet; the
    // flag is parsed and carried so manifests can already declare it.

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

/// A canonical IPv4 or IPv6 literal, under the same egress policy as every
/// other address-carrying type: link-local is always refused, the rest of the
/// non-public table under `block_internal`.
fn validate_ip_address(name: &str, def: &ArgDef, val: &str) -> Result<String, ToolCladError> {
    match parse_canonical_ip(val) {
        Some(ip) => {
            enforce_ip_policy(name, &ip, def.block_internal)?;
            Ok(val.to_string())
        }
        None => Err(ToolCladError::ValidationError(format!(
            "argument '{name}' is not a valid IP address"
        ))),
    }
}

/// A strictly framed IPv4 or IPv6 CIDR (canonical base, plain decimal prefix
/// within the family's bound). The whole range is tested for overlap with
/// every blocked prefix: link-local always, the rest under `block_internal`.
fn validate_cidr(name: &str, def: &ArgDef, val: &str) -> Result<String, ToolCladError> {
    match parse_cidr(val) {
        Some(net) => {
            enforce_cidr_policy(name, &net, def.block_internal)?;
            Ok(val.to_string())
        }
        None => Err(ToolCladError::ValidationError(format!(
            "argument '{name}' is not valid CIDR notation (e.g. 10.0.0.0/24 or 2001:db8::/32)"
        ))),
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
    let re = compile_anchored(name, pat)?;
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
///
/// Strict (template-mode) entry point; see [`validate_arg_with_custom_types_mode`].
pub fn validate_arg_with_custom_types(
    name: &str,
    def: &ArgDef,
    value: &str,
    custom_types: &std::collections::HashMap<String, crate::types::CustomTypeDef>,
) -> Result<String, ToolCladError> {
    validate_arg_with_custom_types_mode(name, def, value, custom_types, false)
}

/// [`validate_arg_with_custom_types`] with an explicit command-form mode;
/// `exec_mode` has the same meaning as in [`validate_arg_mode`].
pub fn validate_arg_with_custom_types_mode(
    name: &str,
    def: &ArgDef,
    value: &str,
    custom_types: &std::collections::HashMap<String, crate::types::CustomTypeDef>,
    exec_mode: bool,
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
        return validate_arg_mode(name, &synthetic, value, exec_mode);
    }

    // Not a custom type, use standard validation
    validate_arg_mode(name, def, value, exec_mode)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::CustomTypeDef;
    use std::collections::HashMap;

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
            "2130706433", // decimal integer
            "0x7f000001", // hex
            "0177.0.0.1", // octal-leading
            "127.1",      // shorthand
            "010.0.0.1",  // leading-zero octet
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
        for v in [
            "169.254.169.254",
            "169.254.0.1",
            "::ffff:169.254.169.254",
            "fe80::1",
        ] {
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
            "169.254.169.254", // IMDS (always-block path)
            "0.0.0.0",
            "::1",
            "::ffff:127.0.0.1", // v4-mapped loopback must be unwrapped
            "fe80::1",          // IPv6 link-local
            "fc00::1",          // IPv6 unique-local
        ] {
            assert!(validate_arg("t", &def, v).is_err(), "{v} should be blocked");
        }
        // Public literals still pass under the policy. A public *name* now
        // needs DNS resolution, so the positive cases stay literal and the
        // name path is covered by the `.invalid` fail-closed test.
        assert!(validate_arg("t", &def, "93.184.216.34").is_ok());
        assert!(validate_arg("t", &def, "2606:4700::1111").is_ok());
        // A CIDR overlapping an internal range is blocked too.
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
        let blocking = ArgDef {
            type_name: "url".to_string(),
            block_internal: true,
            ..Default::default()
        };
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
        assert!(validate_arg("c", &def, "2606:4700::/32").is_ok());
        assert!(validate_arg("c", &def, "10.0.0.0/33").is_err());
        assert!(validate_arg("c", &def, "10.0.0.0").is_err());
        for v in [
            "2606:4700::/129",
            "10.0.0.0/024",
            "10.0.0.0/+24",
            "2606:4700::",
            "[2606:4700::]/32",
            "0x0a000000/8",
        ] {
            let err = validate_arg("c", &def, v).unwrap_err().to_string();
            assert!(err.contains("not valid CIDR notation"), "{v}: {err}");
        }
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

    // ---- W1.5 string-derived value hygiene ------------------------------

    #[test]
    fn test_tc1_payloads_rejected() {
        // Quote break-out into extra curl options.
        let s = make_arg("string");
        assert!(validate_arg("h", &s, "' -d @/etc/passwd").is_err());
        assert!(validate_arg("h", &s, "X: y' -d @/etc/passwd -H 'Z: w").is_err());
        let u = make_arg("url");
        assert!(validate_arg(
            "u",
            &u,
            "https://attacker.example/ -o /root/.ssh/authorized_keys"
        )
        .is_err());
        assert!(validate_arg("u", &u, "https://attacker.example/ -o /tmp/pwned").is_err());

        // exec mode with allow_whitespace does not rescue any of them: quotes
        // are banned outright and a url never admits whitespace.
        let mut s2 = make_arg("string");
        s2.allow_whitespace = true;
        assert!(validate_arg_mode("h", &s2, "' -d @/etc/passwd", true).is_err());
        assert!(validate_arg_mode("h", &s2, "X: y' -d @/etc/passwd -H 'Z: w", true).is_err());
        let mut u2 = make_arg("url");
        u2.allow_whitespace = true;
        assert!(
            validate_arg_mode("u", &u2, "https://attacker.example/ -o /tmp/pwned", true).is_err()
        );
    }

    #[test]
    fn test_tc2_payloads_rejected() {
        // Option smuggling through a free-text "extra flags" string.
        let payloads = [
            "-iL /etc/passwd",
            "--script=/tmp/evil.nse",
            "--script http-fetch --script-args http-fetch.destination=/tmp/d",
        ];
        let s = make_arg("string");
        for v in payloads {
            assert!(
                validate_arg("extra_flags", &s, v).is_err(),
                "should reject {v:?}"
            );
        }
        // Even with whitespace permitted in exec mode, the leading dash holds.
        let mut s2 = make_arg("string");
        s2.allow_whitespace = true;
        for v in payloads {
            let err = validate_arg_mode("extra_flags", &s2, v, true)
                .unwrap_err()
                .to_string();
            assert!(
                err.contains("must not start with '-' or '+'"),
                "{v:?}: {err}"
            );
        }
    }

    #[test]
    fn test_tc3_leading_dash_rejected() {
        let err = validate_arg("p", &make_arg("path"), "-rf")
            .unwrap_err()
            .to_string();
        assert!(
            err.contains(
                "must not start with '-' or '+' (set allow_leading_dash = true to permit)"
            ),
            "unexpected: {err}"
        );
        assert!(validate_arg("s", &make_arg("string"), "--output=/etc/cron.d/x").is_err());
        assert!(validate_arg("n", &make_arg("integer"), "-1").is_err());
        assert!(validate_arg("s", &make_arg("string"), "+short").is_err());
        assert!(validate_arg("f", &make_arg("number"), "-0.5").is_err());

        // Numeric types apply the rule to the output: clamping rescues a
        // negative input, and a leading '+' that parses away is fine.
        let mut n = make_arg("integer");
        n.min = Some(1);
        n.clamp = true;
        assert_eq!(validate_arg("n", &n, "-5").unwrap(), "1");
        let mut f = make_arg("number");
        f.min_float = Some(0.0);
        f.clamp = true;
        assert_eq!(validate_arg("f", &f, "-2.5").unwrap(), "0");
        assert_eq!(validate_arg("n", &make_arg("integer"), "+7").unwrap(), "7");
    }

    #[test]
    fn test_tc3_allow_leading_dash_opt_in() {
        let mut s = make_arg("string");
        s.allow_leading_dash = true;
        assert_eq!(validate_arg("s", &s, "-v").unwrap(), "-v");
        // The opt-in is independent of the command form.
        assert_eq!(validate_arg_mode("s", &s, "-v", true).unwrap(), "-v");
        let mut n = make_arg("integer");
        n.allow_leading_dash = true;
        assert_eq!(validate_arg("n", &n, "-1").unwrap(), "-1");
        // Without the opt-in, exec mode does not help.
        assert!(validate_arg_mode("s", &make_arg("string"), "-v", true).is_err());
    }

    #[test]
    fn test_nul_rejected_for_every_type() {
        for t in SUPPORTED_TYPES {
            let mut d = make_arg(t);
            if *t == "enum" {
                // Only the NUL rule can refuse this: the value is in `allowed`.
                d.allowed = Some(vec!["a\0b".to_string()]);
            }
            if *t == "regex_match" {
                d.pattern = Some(".*".to_string());
            }
            let err = validate_arg("x", &d, "a\0b").unwrap_err().to_string();
            assert!(err.contains("must not contain NUL bytes"), "{t}: {err}");
        }
    }

    #[test]
    fn test_control_chars_quotes_whitespace_rejected() {
        let s = make_arg("string");
        let err = validate_arg("s", &s, "a\x01b").unwrap_err().to_string();
        assert!(err.contains("must not contain control characters"), "{err}");
        assert!(validate_arg("s", &s, "a\x7fb").is_err());
        assert!(validate_arg("s", &s, "a\tb").is_err());
        assert!(validate_arg("s", &s, "a\nb").is_err());
        // C1 range (U+0080–U+009F) counts as control too.
        let err = validate_arg("s", &s, "a\u{85}b").unwrap_err().to_string();
        assert!(err.contains("must not contain control characters"), "{err}");
        assert!(validate_arg("s", &s, "a\u{80}b").is_err());
        assert!(validate_arg("s", &s, "a\u{9f}b").is_err());

        let err = validate_arg("s", &s, "a'b").unwrap_err().to_string();
        assert!(
            err.contains("must not contain quote or backslash characters"),
            "{err}"
        );
        assert!(validate_arg("s", &s, "a\"b").is_err());
        assert!(validate_arg("s", &s, "a\\b").is_err());

        let err = validate_arg("s", &s, "a b").unwrap_err().to_string();
        assert!(err.contains("must not contain whitespace"), "{err}");
        assert!(validate_arg("s", &s, "a\u{a0}b").is_err()); // non-ASCII whitespace
        assert!(validate_arg("s", &s, " a").is_err()); // raw value, never trimmed

        // The rules cover every string-derived type.
        for t in STRING_DERIVED_TYPES {
            let mut d = make_arg(t);
            if *t == "regex_match" {
                d.pattern = Some(".*".to_string());
            }
            assert!(
                validate_arg("x", &d, "a'b").is_err(),
                "{t} should reject a quote"
            );
            assert!(
                validate_arg("x", &d, "a\x01b").is_err(),
                "{t} should reject a control char"
            );
        }

        // scope_target keeps its more specific backslash message.
        let err = validate_arg("t", &make_arg("scope_target"), "a\\b")
            .unwrap_err()
            .to_string();
        assert!(err.contains("backslash escape sequences"), "{err}");

        // enum is exempt from rules 2–5: allowed values are manifest text.
        let mut e = make_arg("enum");
        e.allowed = Some(vec!["-sV".to_string(), "a b".to_string()]);
        assert_eq!(validate_arg("e", &e, "-sV").unwrap(), "-sV");
        assert_eq!(validate_arg("e", &e, "a b").unwrap(), "a b");
    }

    #[test]
    fn test_allow_whitespace_only_in_exec_mode() {
        let mut s = make_arg("string");
        s.allow_whitespace = true;
        assert!(validate_arg("s", &s, "a b").is_err()); // public default is strict
        assert!(validate_arg_mode("s", &s, "a b", false).is_err());
        assert_eq!(validate_arg_mode("s", &s, "a b", true).unwrap(), "a b");
        assert_eq!(
            validate_arg_mode("s", &s, "X-Trace: abc def", true).unwrap(),
            "X-Trace: abc def"
        );
        // The opt-in admits ONLY the ASCII space U+0020. Control whitespace is
        // still a control character (rule 2 is unconditional) and every other
        // Unicode space is a homoglyph, not a separator.
        for v in ["a\tb", "a\nb", "a\rb", "a\x0bb", "a\x0cb"] {
            let err = validate_arg_mode("s", &s, v, true).unwrap_err().to_string();
            assert!(
                err.contains("must not contain control characters"),
                "{v:?}: {err}"
            );
        }
        for v in [
            "a\u{a0}b",
            "a\u{2000}b",
            "a\u{200a}b",
            "a\u{2028}b",
            "a\u{2029}b",
            "a\u{3000}b",
        ] {
            let err = validate_arg_mode("s", &s, v, true).unwrap_err().to_string();
            assert!(err.contains("must not contain whitespace"), "{v:?}: {err}");
        }
        assert!(validate_arg_mode("s", &s, "a\x01b", true).is_err());
        // Without the opt-in, exec mode is still strict.
        assert!(validate_arg_mode("s", &make_arg("string"), "a b", true).is_err());
        // msf_options keeps its space separator in every mode, and only U+0020.
        assert!(validate_arg("m", &make_arg("msf_options"), "RHOSTS 10.0.1.1").is_ok());
        assert!(validate_arg("m", &make_arg("msf_options"), "RHOSTS\t10.0.1.1").is_err());
        assert!(validate_arg("m", &make_arg("msf_options"), "RHOSTS\u{a0}10.0.1.1").is_err());
        assert!(validate_arg("m", &make_arg("msf_options"), "RHOSTS 'x'").is_err());
        assert!(validate_arg("m", &make_arg("msf_options"), "-RHOSTS x").is_err());
    }

    #[test]
    fn test_pattern_is_anchored() {
        let mut s = make_arg("string");
        s.pattern = Some("[a-z]+".to_string());
        assert!(validate_arg("s", &s, "abc").is_ok());
        assert!(validate_arg("s", &s, "abc123").is_err());
        assert!(validate_arg("s", &s, "123abc").is_err());
        let mut r = make_arg("regex_match");
        r.pattern = Some("[a-z]+".to_string());
        assert!(validate_arg("r", &r, "abc").is_ok());
        assert!(validate_arg("r", &r, "abc123").is_err());

        assert_eq!(anchor_pattern("[a-z]+"), "^(?:[a-z]+)$");
        assert_eq!(anchor_pattern("^[a-z]+$"), "^(?:[a-z]+)$");
        assert_eq!(anchor_pattern(r"a\$"), r"^(?:a\$)$");

        // Custom types go through the same anchoring.
        let custom = HashMap::from([(
            "slug".to_string(),
            CustomTypeDef {
                base: "string".to_string(),
                allowed: None,
                pattern: Some("[a-z]+".to_string()),
                min: None,
                max: None,
                min_float: None,
                max_float: None,
            },
        )]);
        assert!(validate_arg_with_custom_types("s", &make_arg("slug"), "abc123", &custom).is_err());
        assert!(validate_arg_with_custom_types("s", &make_arg("slug"), "abc", &custom).is_ok());
        // ...and the custom-type path honors the mode flag the same way.
        let mut spaced = make_arg("slug");
        spaced.allow_whitespace = true;
        let custom_any = HashMap::from([(
            "slug".to_string(),
            CustomTypeDef {
                base: "string".to_string(),
                allowed: None,
                pattern: Some("[a-z ]+".to_string()),
                min: None,
                max: None,
                min_float: None,
                max_float: None,
            },
        )]);
        assert!(validate_arg_with_custom_types("s", &spaced, "a b", &custom_any).is_err());
        assert!(
            validate_arg_with_custom_types_mode("s", &spaced, "a b", &custom_any, true).is_ok()
        );
    }

    // ---- url validator (W3) and host policy (W4) ----

    fn url_arg(block_internal: bool, schemes: &[&str]) -> ArgDef {
        ArgDef {
            type_name: "url".to_string(),
            block_internal,
            schemes: schemes.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn test_url_injection_vectors_inline() {
        // Mirrors every `url-*` vector in tests/injection_vectors.json; a
        // later wave reads the file directly.
        struct Vector {
            id: &'static str,
            value: &'static str,
            block_internal: bool,
            schemes: &'static [&'static str],
            accept: bool,
        }
        let vectors = [
            Vector {
                id: "url-space-option-injection",
                value: "https://attacker.example/ -o /root/.ssh/authorized_keys",
                block_internal: false,
                schemes: &[],
                accept: false,
            },
            Vector {
                id: "url-space-write-tmp",
                value: "https://attacker.example/ -o /tmp/pwned",
                block_internal: false,
                schemes: &[],
                accept: false,
            },
            Vector {
                id: "url-secret-smuggling",
                value: "https://attacker.example/?k={_secret:api_key}",
                block_internal: false,
                schemes: &[],
                accept: false,
            },
            Vector {
                id: "url-javascript-scheme",
                value: "javascript:alert(1)",
                block_internal: false,
                schemes: &[],
                accept: false,
            },
            Vector {
                id: "url-file-scheme",
                value: "file:///etc/passwd",
                block_internal: false,
                schemes: &[],
                accept: false,
            },
            Vector {
                id: "url-data-scheme",
                value: "data:text/html,<script>1</script>",
                block_internal: false,
                schemes: &[],
                accept: false,
            },
            Vector {
                id: "url-gopher-redis",
                value: "gopher://127.0.0.1:6379/_FLUSHALL",
                block_internal: false,
                schemes: &[],
                accept: false,
            },
            Vector {
                id: "url-dict-scheme",
                value: "dict://127.0.0.1:11211/stat",
                block_internal: false,
                schemes: &[],
                accept: false,
            },
            Vector {
                id: "url-userinfo",
                value: "http://user:pw@example.com/",
                block_internal: false,
                schemes: &[],
                accept: false,
            },
            Vector {
                id: "url-metacharacter",
                value: "https://attacker.example/;id",
                block_internal: false,
                schemes: &[],
                accept: false,
            },
            Vector {
                id: "url-scheme-not-in-list",
                value: "http://example.com/",
                block_internal: false,
                schemes: &["https"],
                accept: false,
            },
            Vector {
                id: "url-imds-always-blocked",
                value: "http://169.254.169.254/latest/meta-data/",
                block_internal: false,
                schemes: &[],
                accept: false,
            },
            Vector {
                id: "url-docker-socket-block-internal",
                value: "http://127.0.0.1:2375/containers/json",
                block_internal: true,
                schemes: &[],
                accept: false,
            },
            Vector {
                id: "url-ipv6-loopback-block-internal",
                value: "http://[::1]:8080/",
                block_internal: true,
                schemes: &[],
                accept: false,
            },
            Vector {
                id: "url-accept",
                value: "https://example.com/path",
                block_internal: false,
                schemes: &[],
                accept: true,
            },
            Vector {
                id: "url-accept-public-ip-block-internal",
                value: "https://93.184.216.34/x",
                block_internal: true,
                schemes: &[],
                accept: true,
            },
        ];
        for v in &vectors {
            let def = url_arg(v.block_internal, v.schemes);
            let result = validate_arg("u", &def, v.value);
            assert_eq!(result.is_ok(), v.accept, "{}: {result:?}", v.id);
        }
    }

    #[test]
    fn test_url_honors_schemes_list() {
        // The regression this wave closes: Rust ignored `schemes` entirely.
        let https_only = url_arg(false, &["https"]);
        let err = validate_arg("u", &https_only, "http://example.com/")
            .unwrap_err()
            .to_string();
        assert!(err.contains("scheme 'http' is not permitted"), "{err}");
        assert!(validate_arg("u", &https_only, "https://example.com/").is_ok());
        // Case-insensitive on both sides.
        assert!(validate_arg("u", &https_only, "HTTPS://example.com/").is_ok());
        assert!(validate_arg("u", &url_arg(false, &["HTTPS"]), "https://example.com/").is_ok());
        // A custom scheme can be allowed when it is not on the denylist, and
        // listing it drops the defaults.
        let custom = url_arg(false, &["custom"]);
        assert!(validate_arg("u", &custom, "custom://example.com/").is_ok());
        assert!(validate_arg("u", &custom, "https://example.com/").is_err());
        // Unset means http + https.
        let def = make_arg("url");
        assert!(validate_arg("u", &def, "http://example.com/").is_ok());
        assert!(validate_arg("u", &def, "https://example.com/").is_ok());
        let err = validate_arg("u", &def, "custom://example.com/")
            .unwrap_err()
            .to_string();
        assert!(err.contains("allowed: http, https"), "{err}");
    }

    #[test]
    fn test_url_denied_schemes_even_when_listed() {
        for scheme in [
            "javascript",
            "data",
            "file",
            "blob",
            "about",
            "gopher",
            "dict",
            "ftp",
            "ldap",
            "jar",
            "netdoc",
            "mailto",
            "ws",
            "wss",
        ] {
            let def = url_arg(false, &[scheme]);
            let value = format!("{scheme}://example.com/x");
            let err = validate_arg("u", &def, &value).unwrap_err().to_string();
            assert!(err.contains("never permitted"), "{scheme}: {err}");
            // Mixed case does not slip past the denylist.
            let upper = format!("{}://example.com/x", scheme.to_ascii_uppercase());
            assert!(validate_arg("u", &def, &upper).is_err(), "{upper}");
        }
        // Not listed: the ordinary allowlist message applies.
        let err = validate_arg("u", &make_arg("url"), "file:///etc/passwd")
            .unwrap_err()
            .to_string();
        assert!(err.contains("not permitted"), "{err}");
    }

    #[test]
    fn test_url_structure() {
        let def = make_arg("url");
        // No scheme separator.
        let err = validate_arg("u", &def, "example.com/path")
            .unwrap_err()
            .to_string();
        assert!(err.contains("expected scheme://host"), "{err}");
        assert!(validate_arg("u", &def, "javascript:alert(1)").is_err());
        // Userinfo hides the real host from a reviewer.
        let err = validate_arg("u", &def, "http://user:pw@example.com/")
            .unwrap_err()
            .to_string();
        assert!(err.contains("userinfo"), "{err}");
        assert!(validate_arg("u", &def, "http://evil.example@example.com/").is_err());
        // An `@` after the authority is just path or query data.
        assert!(validate_arg("u", &def, "https://example.com/@handle").is_ok());
        assert!(validate_arg("u", &def, "https://example.com/?to=a@b").is_ok());
        // Empty host.
        for v in ["http:///path", "http://", "http://:8080/", "http://?q=1"] {
            let err = validate_arg("u", &def, v).unwrap_err().to_string();
            assert!(err.contains("empty host"), "{v}: {err}");
        }
        // Query or fragment directly after the host, and no path at all.
        assert!(validate_arg("u", &def, "https://example.com").is_ok());
        assert!(validate_arg("u", &def, "https://example.com?q=1").is_ok());
        assert!(validate_arg("u", &def, "https://example.com#frag").is_ok());
        // Unbracketed IPv6 is ambiguous with a port.
        let err = validate_arg("u", &def, "http://::1/")
            .unwrap_err()
            .to_string();
        assert!(err.contains("enclosed in brackets"), "{err}");
        assert!(validate_arg("u", &def, "https://example.com:80:80/").is_err());
        // Host character set and DNS limits.
        assert!(validate_arg("u", &def, "http://exa_mple.com/").is_err());
        assert!(validate_arg("u", &def, "http://-example.com/").is_err());
        assert!(validate_arg("u", &def, "http://exa%41mple.com/").is_err());
        let err = validate_arg("u", &def, "http://exämple.com/")
            .unwrap_err()
            .to_string();
        assert!(err.contains("ASCII"), "{err}");
        let long_label = format!("http://{}.com/", "a".repeat(64));
        assert!(validate_arg("u", &def, &long_label).is_err());
        assert!(validate_arg("u", &def, &format!("http://{}.com/", "a".repeat(63))).is_ok());
        // Whitespace is never admitted, even in exec mode with the opt-in.
        let mut lenient = make_arg("url");
        lenient.allow_whitespace = true;
        assert!(validate_arg_mode("u", &lenient, "https://example.com/ -o x", true).is_err());
    }

    #[test]
    fn test_url_ports() {
        let def = make_arg("url");
        for v in [
            "https://example.com:8443/x",
            "https://example.com:8443",
            "https://example.com:1/",
            "https://example.com:65535/",
            "http://93.184.216.34:8080/x",
        ] {
            assert!(validate_arg("u", &def, v).is_ok(), "{v}");
        }
        for v in [
            "https://example.com:0/x",
            "https://example.com:99999/x",
            "https://example.com:65536/",
            "https://example.com:/x",
            "https://example.com:+80/",
            "https://example.com:8a/",
        ] {
            let err = validate_arg("u", &def, v).unwrap_err().to_string();
            assert!(err.contains("port must be 1-65535"), "{v}: {err}");
        }
    }

    #[test]
    fn test_url_authority_split_unwraps_bracketed_ipv6() {
        // `[` and `]` are shell metacharacters, so a bracketed literal never
        // reaches the structural parse through validate_arg; the splitter is
        // exercised directly so the unwrap stays correct.
        let h = split_url_authority("u", "[::1]:8080").unwrap();
        assert_eq!(h.host, "::1");
        assert_eq!(h.port, Some(8080));
        assert_eq!(h.bracketed_v6, Some(Ipv6Addr::LOCALHOST));
        let h = split_url_authority("u", "[2001:db8::1]").unwrap();
        assert_eq!(h.port, None);
        assert_eq!(h.bracketed_v6, Some("2001:db8::1".parse().unwrap()));
        assert_eq!(
            split_url_authority("u", "example.com:8443").unwrap(),
            UrlHost {
                host: "example.com",
                port: Some(8443),
                bracketed_v6: None,
            }
        );
        assert_eq!(
            split_url_authority("u", "example.com").unwrap(),
            UrlHost {
                host: "example.com",
                port: None,
                bracketed_v6: None,
            }
        );
        for bad in [
            "[::1",
            "[::1]x",
            "[::1]:",
            "[::1]:0",
            "[]",
            "[example.com]",
            "[::1]]",
            "",
            ":80",
        ] {
            assert!(split_url_authority("u", bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn test_url_block_internal_policy() {
        let blocking = url_arg(true, &[]);
        for v in [
            "http://127.0.0.1/",
            "http://127.0.0.1:2375/containers/json",
            "http://[::1]:8080/",
            "http://10.0.0.5/x",
            "http://192.168.1.1/",
            "http://172.16.0.1/",
            "http://100.64.0.1/",
            "http://0.0.0.0/",
            "http://198.18.0.1/",
            "http://240.0.0.1/",
            "http://192.0.2.1/",
            "http://255.255.255.255/",
        ] {
            let err = validate_arg("u", &blocking, v).unwrap_err().to_string();
            assert!(
                err.contains("block_internal") || err.contains("metacharacter"),
                "{v}: {err}"
            );
        }
        assert!(validate_arg("u", &blocking, "https://93.184.216.34/x").is_ok());
        assert!(validate_arg("u", &blocking, "https://8.8.8.8:8443/").is_ok());
        // Off by default: internal literals pass, except the always-blocked
        // tier.
        let open = make_arg("url");
        for v in [
            "http://127.0.0.1/",
            "http://10.0.0.5/x",
            "http://100.64.0.1/",
            "http://198.18.0.1/",
            "http://240.0.0.1/",
        ] {
            assert!(validate_arg("u", &open, v).is_ok(), "{v}");
        }
    }

    #[test]
    fn test_url_imds_blocked_in_both_modes() {
        for block_internal in [false, true] {
            let def = url_arg(block_internal, &[]);
            for v in [
                "http://169.254.169.254/latest/meta-data/",
                "http://169.254.169.254:80/",
                "http://169.254.0.1/",
            ] {
                let err = validate_arg("u", &def, v).unwrap_err().to_string();
                assert!(err.contains("always blocked"), "{v}: {err}");
            }
            // The v4-mapped spelling needs brackets in a URL, which the
            // metacharacter rule refuses first; the policy itself is checked
            // on the literal directly.
            assert!(validate_arg("u", &def, "http://[::ffff:169.254.169.254]/").is_err());
            let mapped: IpAddr = "::ffff:169.254.169.254".parse().unwrap();
            let err = enforce_ip_policy("u", &mapped, block_internal)
                .unwrap_err()
                .to_string();
            assert!(err.contains("always blocked"), "{err}");
        }
    }

    #[test]
    fn test_scope_target_block_internal_full_table() {
        let def = blocking_arg();
        for v in [
            "10.0.0.5",
            "192.168.1.1",
            "172.16.0.1",
            "0.0.0.0",
            "0.1.2.3",
            "::1",
            "::",
            "fc00::1",
            "::ffff:127.0.0.1",
            "100.64.0.1",
            "198.18.0.1",
            "240.0.0.1",
            "255.255.255.255",
            "192.0.2.1",
            "198.51.100.1",
            "203.0.113.1",
            "2001:db8::1",
            "100.64.0.0/10",
            "198.18.0.0/15",
        ] {
            let err = validate_arg("t", &def, v).unwrap_err().to_string();
            assert!(
                err.contains("blocked by block_internal policy"),
                "{v}: {err}"
            );
        }
        assert!(validate_arg("t", &def, "93.184.216.34").is_ok());
        assert!(validate_arg("t", &def, "2606:2800:220:1:248:1893:25c8:1946").is_ok());
        assert!(validate_arg("t", &def, "8.8.8.0/24").is_ok());
        // The newly covered ranges stay open without the policy.
        let open = make_arg("scope_target");
        for v in [
            "100.64.0.1",
            "198.18.0.1",
            "240.0.0.1",
            "2001:db8::1",
            "0.1.2.3",
        ] {
            assert!(validate_arg("t", &open, v).is_ok(), "{v}");
        }
    }

    #[test]
    fn test_ip_address_and_cidr_apply_host_policy() {
        let open_ip = make_arg("ip_address");
        assert!(validate_arg("ip", &open_ip, "10.0.0.1").is_ok());
        let err = validate_arg("ip", &open_ip, "169.254.169.254")
            .unwrap_err()
            .to_string();
        assert!(err.contains("always blocked"), "{err}");
        assert!(validate_arg("ip", &open_ip, "fe80::1").is_err());
        let block_ip = ArgDef {
            type_name: "ip_address".to_string(),
            block_internal: true,
            ..Default::default()
        };
        for v in [
            "10.0.0.1",
            "127.0.0.1",
            "::1",
            "::ffff:192.168.0.1",
            "100.64.1.1",
        ] {
            let err = validate_arg("ip", &block_ip, v).unwrap_err().to_string();
            assert!(err.contains("block_internal"), "{v}: {err}");
        }
        assert!(validate_arg("ip", &block_ip, "93.184.216.34").is_ok());

        let open_cidr = make_arg("cidr");
        assert!(validate_arg("c", &open_cidr, "10.0.0.0/24").is_ok());
        assert!(validate_arg("c", &open_cidr, "169.254.0.0/16").is_err());
        let block_cidr = ArgDef {
            type_name: "cidr".to_string(),
            block_internal: true,
            ..Default::default()
        };
        assert!(validate_arg("c", &block_cidr, "10.0.0.0/24").is_err());
        assert!(validate_arg("c", &block_cidr, "198.18.0.0/15").is_err());
        assert!(validate_arg("c", &block_cidr, "8.8.8.0/24").is_ok());
    }

    // ---- W4 hostname rules: denylist, embedded literal, overlap, DNS ----

    #[test]
    fn test_internal_names_always_blocked() {
        const MSG: &str = "resolves to an internal name — always blocked";
        let names = [
            "localhost",
            "api.localhost",
            "printer.local",
            "metadata.google.internal",
            "db.internal",
            "x.home.arpa",
            "nas.lan",
            "wiki.intranet",
            "fs.corp",
            "vpn.private",
            "LOCALHOST",
            "Metadata.Google.Internal",
        ];
        for block_internal in [false, true] {
            let target = ArgDef {
                type_name: "scope_target".to_string(),
                block_internal,
                ..Default::default()
            };
            let url = url_arg(block_internal, &[]);
            for h in names {
                let err = validate_arg("t", &target, h).unwrap_err().to_string();
                assert_eq!(
                    err,
                    format!("validation error: argument 't' target {MSG}"),
                    "{h}"
                );
                let err = validate_arg("u", &url, &format!("http://{h}/x"))
                    .unwrap_err()
                    .to_string();
                assert_eq!(
                    err,
                    format!("validation error: argument 'u' target {MSG}"),
                    "{h}"
                );
                let err = validate_arg("u", &url, &format!("https://{h}:8443/"))
                    .unwrap_err()
                    .to_string();
                assert!(err.contains(MSG), "{h}: {err}");
            }
        }
        // A public name that merely contains a listed word is not on the list.
        let open = make_arg("scope_target");
        for h in [
            "localhost.com",
            "internal.example.com",
            "local.example.com",
            "corp.example.com",
        ] {
            assert!(validate_arg("t", &open, h).is_ok(), "{h}");
        }
    }

    #[test]
    fn test_embedded_ip_literal_in_hostname() {
        let open = make_arg("scope_target");
        let blocking = blocking_arg();
        // Link-local spelled into a wildcard-DNS name: refused without the policy.
        let err = validate_arg("t", &open, "169.254.169.254.nip.io")
            .unwrap_err()
            .to_string();
        assert!(err.contains("always blocked"), "{err}");
        let err = validate_arg(
            "u",
            &url_arg(false, &[]),
            "http://169.254.169.254.nip.io/latest/meta-data/",
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("always blocked"), "{err}");
        // Loopback / private spelled dotted or dashed: refused with the policy
        // and open without it, exactly like the literal they spell.
        for h in [
            "127.0.0.1.nip.io",
            "10-0-0-1.nip.io",
            "192-168-1-1.sslip.io",
            "0.0.0.0.nip.io",
            "100-64-0-1.nip.io",
        ] {
            let err = validate_arg("t", &blocking, h).unwrap_err().to_string();
            assert!(
                err.contains("blocked by block_internal policy"),
                "{h}: {err}"
            );
            let err = validate_arg("u", &url_arg(true, &[]), &format!("http://{h}:8080/"))
                .unwrap_err()
                .to_string();
            assert!(
                err.contains("blocked by block_internal policy"),
                "{h}: {err}"
            );
            assert!(validate_arg("t", &open, h).is_ok(), "{h}");
        }
        // A public embedded address is not refused for its shape; it is taken
        // as the address the name spells, so no lookup is needed.
        for h in [
            "93-184-216-34.example.com",
            "93.184.216.34.nip.io",
            "8-8-8-8.sslip.io",
        ] {
            assert!(validate_arg("t", &blocking, h).is_ok(), "{h}");
            assert!(
                validate_arg("u", &url_arg(true, &[]), &format!("https://{h}/")).is_ok(),
                "{h}"
            );
        }
    }

    #[test]
    fn test_scope_target_and_cidr_overlap_policy() {
        let blocking = blocking_arg();
        let block_cidr = ArgDef {
            type_name: "cidr".to_string(),
            block_internal: true,
            ..Default::default()
        };
        for def in [&blocking, &block_cidr] {
            // The supernet from the review: public base, contains 10.0.0.0/8.
            let err = validate_arg("t", def, "8.0.0.0/5").unwrap_err().to_string();
            assert!(
                err.contains("overlaps 10.0.0.0/8") && err.contains("block_internal"),
                "{err}"
            );
            let err = validate_arg("t", def, "10.0.0.0/24")
                .unwrap_err()
                .to_string();
            assert!(err.contains("overlaps 10.0.0.0/8"), "{err}");
            assert!(validate_arg("t", def, "93.184.216.0/24").is_ok());
            // IPv6 CIDRs are values of both types.
            let err = validate_arg("t", def, "2001:db8::/32")
                .unwrap_err()
                .to_string();
            assert!(err.contains("overlaps 2001:db8::/32"), "{err}");
            assert!(validate_arg("t", def, "2606:4700::/32").is_ok());
            assert!(validate_arg("t", def, "2000::/3").is_err()); // holds 2001:db8::/32
                                                                  // The whole address space is always blocked (it holds link-local).
            assert!(validate_arg("t", def, "0.0.0.0/0").is_err());
            assert!(validate_arg("t", def, "::/0").is_err());
        }
        // Without the policy only the always-blocked tier is tested — still
        // by overlap.
        for def in [make_arg("scope_target"), make_arg("cidr")] {
            assert!(validate_arg("t", &def, "8.0.0.0/5").is_ok());
            assert!(validate_arg("t", &def, "2001:db8::/32").is_ok());
            let err = validate_arg("t", &def, "169.0.0.0/8")
                .unwrap_err()
                .to_string();
            assert!(
                err.contains("overlaps 169.254.0.0/16") && err.contains("always blocked"),
                "{err}"
            );
            let err = validate_arg("t", &def, "0.0.0.0/0")
                .unwrap_err()
                .to_string();
            assert!(err.contains("always blocked"), "{err}");
            let err = validate_arg("t", &def, "fe00::/7").unwrap_err().to_string();
            assert!(err.contains("overlaps fe80::/10"), "{err}");
        }
    }

    #[test]
    fn test_ipv6_cidr_is_framed_strictly() {
        // Base must be canonical IPv6 and the prefix plain decimal 0-128; a
        // malformed range is "not a CIDR", so it fails the slash rule.
        let open = make_arg("scope_target");
        assert!(validate_arg("t", &open, "2606:4700::/32").is_ok());
        for v in [
            "2606:4700::/129",
            "2606:4700::/032",
            "2606:4700::/+32",
            "2606:4700::/",
            "2606:4700:/32",
            "2606:4700::/32/",
            "10.0.0.0/33",
            "10.0.0.0/024",
        ] {
            let err = validate_arg("t", &open, v).unwrap_err().to_string();
            assert!(err.contains("'/'"), "{v}: {err}");
        }
    }

    #[test]
    fn test_block_internal_resolution_fails_closed() {
        // RFC 2606 reserves `.invalid`; the name never resolves. This is the
        // one lookup the suite performs and it exercises the refusal path.
        const HOST: &str = "no-such-host.invalid";
        let err = validate_arg("t", &blocking_arg(), HOST)
            .unwrap_err()
            .to_string();
        assert_eq!(
            err,
            format!("validation error: argument 't' could not resolve host '{HOST}' to verify it is public (block_internal)")
        );
        let err = validate_arg("u", &url_arg(true, &[]), &format!("https://{HOST}/path"))
            .unwrap_err()
            .to_string();
        assert_eq!(
            err,
            format!("validation error: argument 'u' could not resolve host '{HOST}' to verify it is public (block_internal)")
        );
        // Without the policy no resolution is attempted: the name is accepted
        // on structure alone.
        assert!(validate_arg("t", &make_arg("scope_target"), HOST).is_ok());
        assert!(validate_arg("u", &make_arg("url"), &format!("https://{HOST}/path")).is_ok());
    }
}
