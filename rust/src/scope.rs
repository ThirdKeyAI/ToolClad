//! Scope enforcement: the project allowlist an argument with
//! `scope_check = true` is checked against.
//!
//! The scope file is `scope/scope.toml`:
//!
//! ```toml
//! [scope]
//! allowed_domains = ["example.com", "*.example.com"]
//! allowed_cidrs   = ["10.0.1.0/24"]
//! blocked_domains = []
//! blocked_cidrs   = []
//! ```
//!
//! Discovery ([`discover_scope`]): the path in `TOOLCLAD_SCOPE_FILE` when set
//! (an unreadable file is an error, not a fallback), else `scope/scope.toml`
//! searched upward from the manifest's directory (or the process cwd for a
//! manifest parsed from a string) to the filesystem root.
//!
//! Matching ([`check_scope`]): blocked rules first, and they always win; a
//! domain rule is exact (`example.com`) or a strict-subdomain wildcard
//! (`*.example.com`, which matches neither the apex nor `evil-example.com`);
//! an IP matches a CIDR rule that contains it, and a CIDR matches only when it
//! is fully contained in an allowed range. No match is a refusal, and a scope
//! with empty allowed lists puts nothing in scope. Enforcement is fail
//! closed: `scope_check = true` with no scope file refuses every value.

use crate::hostpolicy::{parse_canonical_ip, parse_cidr, v4_overlaps, v6_overlaps, IpNet};
use crate::types::ToolCladError;
use std::ffi::OsStr;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

/// Environment variable naming the scope file explicitly.
pub const SCOPE_FILE_ENV: &str = "TOOLCLAD_SCOPE_FILE";

/// Argument types on which `scope_check = true` is honored.
pub const SCOPE_CHECK_TYPES: &[&str] = &["scope_target", "url", "ip_address", "cidr"];

/// Keys the `[scope]` table accepts.
const SCOPE_KEYS: &[&str] = &[
    "allowed_domains",
    "allowed_cidrs",
    "blocked_domains",
    "blocked_cidrs",
];

/// A loaded scope definition.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScopeDef {
    /// Domain rules (`example.com` or `*.example.com`), lowercase.
    pub allowed_domains: Vec<String>,
    pub allowed_cidrs: Vec<IpNet>,
    pub blocked_domains: Vec<String>,
    pub blocked_cidrs: Vec<IpNet>,
    /// The file this scope was read from, when it came from a file.
    pub source: Option<PathBuf>,
}

fn scope_err(msg: String) -> ToolCladError {
    ToolCladError::ManifestError(msg)
}

/// Check a domain rule's syntax: `[a-z0-9.-]` labels, no empty label, and an
/// optional leading `*.` (a `*` anywhere else is refused).
fn check_domain_rule(rule: &str) -> Result<(), String> {
    let body = rule.strip_prefix("*.").unwrap_or(rule);
    let well_formed = !body.is_empty()
        && body
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
        && body.split('.').all(|label| !label.is_empty());
    if well_formed {
        Ok(())
    } else {
        Err(format!(
            "invalid domain rule '{rule}' (expected lowercase [a-z0-9.-] labels with an optional leading '*.')"
        ))
    }
}

/// Parse a scope file's contents. Unknown keys, a malformed CIDR and a
/// malformed domain rule are each load errors.
pub fn parse_scope(content: &str) -> Result<ScopeDef, ToolCladError> {
    let doc: toml::Table = toml::from_str(content)
        .map_err(|e| scope_err(format!("TOML parse error in scope file: {e}")))?;

    let mut unknown: Vec<String> = doc
        .keys()
        .filter(|k| k.as_str() != "scope")
        .cloned()
        .collect();
    let empty = toml::Table::new();
    let table = match doc.get("scope") {
        None => &empty,
        Some(toml::Value::Table(t)) => t,
        Some(_) => return Err(scope_err("scope file: 'scope' must be a table".into())),
    };
    unknown.extend(
        table
            .keys()
            .filter(|k| !SCOPE_KEYS.contains(&k.as_str()))
            .map(|k| format!("scope.{k}")),
    );
    if !unknown.is_empty() {
        unknown.sort();
        return Err(scope_err(
            unknown
                .iter()
                .map(|k| format!("unknown key '{k}' in scope file"))
                .collect::<Vec<_>>()
                .join("; "),
        ));
    }

    let strings = |key: &str| -> Result<Vec<String>, ToolCladError> {
        match table.get(key) {
            None => Ok(Vec::new()),
            Some(toml::Value::Array(items)) => items
                .iter()
                .map(|v| {
                    v.as_str().map(str::to_string).ok_or_else(|| {
                        scope_err(format!("scope file: '{key}' must be an array of strings"))
                    })
                })
                .collect(),
            Some(_) => Err(scope_err(format!(
                "scope file: '{key}' must be an array of strings"
            ))),
        }
    };
    let domains = |key: &str| -> Result<Vec<String>, ToolCladError> {
        let rules = strings(key)?;
        for rule in &rules {
            check_domain_rule(rule).map_err(|m| scope_err(format!("scope file: {key}: {m}")))?;
        }
        Ok(rules)
    };
    let cidrs = |key: &str| -> Result<Vec<IpNet>, ToolCladError> {
        strings(key)?
            .iter()
            .map(|c| {
                parse_cidr(c)
                    .ok_or_else(|| scope_err(format!("scope file: {key}: invalid CIDR '{c}'")))
            })
            .collect()
    };

    Ok(ScopeDef {
        allowed_domains: domains("allowed_domains")?,
        allowed_cidrs: cidrs("allowed_cidrs")?,
        blocked_domains: domains("blocked_domains")?,
        blocked_cidrs: cidrs("blocked_cidrs")?,
        source: None,
    })
}

/// Read and parse a scope file.
pub fn load_scope_file<P: AsRef<Path>>(path: P) -> Result<ScopeDef, ToolCladError> {
    let path = path.as_ref();
    let content = std::fs::read_to_string(path).map_err(|e| {
        scope_err(format!(
            "failed to read scope file '{}': {e}",
            path.display()
        ))
    })?;
    let mut scope = parse_scope(&content)
        .map_err(|e| scope_err(format!("{} ({})", strip_kind(&e), path.display())))?;
    scope.source = Some(path.to_path_buf());
    Ok(scope)
}

fn strip_kind(e: &ToolCladError) -> String {
    match e {
        ToolCladError::ManifestError(m) => m.clone(),
        other => other.to_string(),
    }
}

/// Locate and load the scope file for a manifest in `manifest_dir` (`None`
/// for a manifest parsed from a string: the search starts at the cwd).
///
/// Returns `Ok(None)` when no scope file exists anywhere; the validator then
/// fails closed on every `scope_check` argument. A `TOOLCLAD_SCOPE_FILE` that
/// cannot be read, or a scope file that does not parse, is an error.
pub fn discover_scope(manifest_dir: Option<&Path>) -> Result<Option<ScopeDef>, ToolCladError> {
    let env = std::env::var_os(SCOPE_FILE_ENV);
    discover_scope_with(env.as_deref(), manifest_dir)
}

/// [`discover_scope`] with the `TOOLCLAD_SCOPE_FILE` value passed explicitly
/// (an empty value counts as unset).
pub fn discover_scope_with(
    env_file: Option<&OsStr>,
    manifest_dir: Option<&Path>,
) -> Result<Option<ScopeDef>, ToolCladError> {
    if let Some(file) = env_file.filter(|f| !f.is_empty()) {
        return load_scope_file(Path::new(file)).map(Some);
    }
    let cwd = std::env::current_dir()
        .map_err(|e| scope_err(format!("cannot determine current directory: {e}")))?;
    let start = match manifest_dir {
        Some(dir) if dir.is_absolute() => dir.to_path_buf(),
        Some(dir) => cwd.join(dir),
        None => cwd,
    };
    for dir in start.ancestors() {
        let candidate = dir.join("scope").join("scope.toml");
        if candidate.is_file() {
            return load_scope_file(&candidate).map(Some);
        }
    }
    Ok(None)
}

/// True if `host` matches the domain rule `pattern`, case-insensitively.
/// `example.com` matches only that host; `*.example.com` matches any strict
/// subdomain at any depth, on a label boundary — never the apex and never
/// `evil-example.com`.
pub fn host_matches_rule(host: &str, pattern: &str) -> bool {
    let host = host.to_ascii_lowercase();
    let pattern = pattern.to_ascii_lowercase();
    match pattern.strip_prefix("*.") {
        Some(suffix) => {
            host.len() > suffix.len() + 1
                && host.ends_with(suffix)
                && host.as_bytes()[host.len() - suffix.len() - 1] == b'.'
        }
        None => host == pattern,
    }
}

/// True if `ip` lies inside `net` (same address family only).
pub fn ip_in_net(ip: &IpAddr, net: &IpNet) -> bool {
    match (ip, net.addr) {
        (IpAddr::V4(a), IpAddr::V4(b)) => v4_overlaps(*a, 32, b, net.prefix),
        (IpAddr::V6(a), IpAddr::V6(b)) => v6_overlaps(*a, 128, b, net.prefix),
        _ => false,
    }
}

/// String form of [`ip_in_net`]: false when either side does not parse.
pub fn ip_in_cidr(ip: &str, cidr: &str) -> bool {
    match (parse_canonical_ip(ip), parse_cidr(cidr)) {
        (Some(ip), Some(net)) => ip_in_net(&ip, &net),
        _ => false,
    }
}

/// True if `inner` is fully contained in `outer`.
pub fn net_contains(outer: &IpNet, inner: &IpNet) -> bool {
    if inner.prefix < outer.prefix {
        return false;
    }
    match (inner.addr, outer.addr) {
        (IpAddr::V4(a), IpAddr::V4(b)) => v4_overlaps(a, inner.prefix, b, outer.prefix),
        (IpAddr::V6(a), IpAddr::V6(b)) => v6_overlaps(a, inner.prefix, b, outer.prefix),
        _ => false,
    }
}

/// True if the two prefixes share any address (same family only).
fn nets_overlap(a: &IpNet, b: &IpNet) -> bool {
    match (a.addr, b.addr) {
        (IpAddr::V4(x), IpAddr::V4(y)) => v4_overlaps(x, a.prefix, y, b.prefix),
        (IpAddr::V6(x), IpAddr::V6(y)) => v6_overlaps(x, a.prefix, y, b.prefix),
        _ => false,
    }
}

/// The shape of a checked subject.
enum Subject {
    Ip(IpAddr),
    Net(IpNet),
    Host(String),
}

fn classify(subject: &str) -> Subject {
    if let Some(ip) = parse_canonical_ip(subject) {
        Subject::Ip(ip)
    } else if let Some(net) = parse_cidr(subject) {
        Subject::Net(net)
    } else {
        Subject::Host(subject.to_ascii_lowercase())
    }
}

/// True if `subject` (a host, IP literal or CIDR) is in scope: it matches no
/// blocked rule and at least one allowed rule. A CIDR subject is blocked when
/// it overlaps a blocked range and allowed only when fully contained in an
/// allowed range.
pub fn in_scope(scope: &ScopeDef, subject: &str) -> bool {
    match classify(subject) {
        Subject::Host(host) => {
            !scope
                .blocked_domains
                .iter()
                .any(|r| host_matches_rule(&host, r))
                && scope
                    .allowed_domains
                    .iter()
                    .any(|r| host_matches_rule(&host, r))
        }
        Subject::Ip(ip) => {
            !scope.blocked_cidrs.iter().any(|n| ip_in_net(&ip, n))
                && scope.allowed_cidrs.iter().any(|n| ip_in_net(&ip, n))
        }
        Subject::Net(net) => {
            !scope.blocked_cidrs.iter().any(|n| nets_overlap(&net, n))
                && scope.allowed_cidrs.iter().any(|n| net_contains(n, &net))
        }
    }
}

/// The scope check for argument `name`: refuses when no scope is loaded
/// (fail closed) and when `subject` is not in scope.
pub fn check_scope(
    name: &str,
    scope: Option<&ScopeDef>,
    subject: &str,
    value: &str,
) -> Result<(), ToolCladError> {
    let Some(scope) = scope else {
        return Err(ToolCladError::ValidationError(format!(
            "argument '{name}' scope_check is enabled but no scope/scope.toml was found (set {SCOPE_FILE_ENV})"
        )));
    };
    if in_scope(scope, subject) {
        Ok(())
    } else {
        Err(ToolCladError::ValidationError(format!(
            "argument '{name}' target '{value}' is not in scope"
        )))
    }
}

/// True if `url` passes a `url` argument with `scope_check = true` against a
/// scope whose `allowed_domains` is `allowed_hosts` (no CIDR rules, no
/// blocked rules). Exposed for the shared vector suite and for embedders.
pub fn url_host_in_scope(url: &str, allowed_hosts: &[&str]) -> bool {
    let scope = ScopeDef {
        allowed_domains: allowed_hosts
            .iter()
            .map(|h| h.to_ascii_lowercase())
            .collect(),
        ..Default::default()
    };
    let def = crate::types::ArgDef {
        type_name: "url".to_string(),
        scope_check: true,
        ..Default::default()
    };
    crate::validator::validate_arg_in("url", &def, url, false, Some(&scope)).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ArgDef;
    use crate::validator::{validate_arg, validate_arg_in};

    fn scope(toml_text: &str) -> ScopeDef {
        parse_scope(toml_text).unwrap()
    }

    fn arg(type_name: &str) -> ArgDef {
        ArgDef {
            type_name: type_name.to_string(),
            scope_check: true,
            ..Default::default()
        }
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "toolclad-scope-{tag}-{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    // ---- tests/scope_vectors.json -------------------------------------

    #[test]
    fn shared_scope_vectors() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/scope_vectors.json");
        let Ok(text) = std::fs::read_to_string(&path) else {
            eprintln!(
                "skipping shared scope vectors: {} not found",
                path.display()
            );
            return;
        };
        let doc: serde_json::Value = serde_json::from_str(&text).unwrap();
        let v = &doc["vectors"];
        let s = |x: &serde_json::Value| x.as_str().unwrap().to_string();
        let b = |x: &serde_json::Value| x.as_bool().unwrap();
        let mut count = 0;

        for section in ["ipv4_in_cidr", "ipv6_in_cidr"] {
            for case in v[section].as_array().unwrap() {
                let (ip, cidr) = (s(&case["ip"]), s(&case["cidr"]));
                assert_eq!(
                    ip_in_cidr(&ip, &cidr),
                    b(&case["expected"]),
                    "{section}: {ip} in {cidr}"
                );
                count += 1;
            }
        }
        for case in v["hostname_wildcard_match"].as_array().unwrap() {
            let (host, pat) = (s(&case["hostname"]), s(&case["pattern"]));
            assert_eq!(
                host_matches_rule(&host, &pat),
                b(&case["expected"]),
                "hostname_wildcard_match: {host} vs {pat}"
            );
            count += 1;
        }
        let target = ArgDef {
            type_name: "scope_target".to_string(),
            ..Default::default()
        };
        for case in v["scope_target_validation"].as_array().unwrap() {
            let value = s(&case["value"]);
            assert_eq!(
                validate_arg("target", &target, &value).is_ok(),
                b(&case["valid"]),
                "scope_target_validation: {value:?}"
            );
            count += 1;
        }
        for case in v["url_scope_check"].as_array().unwrap() {
            let url = s(&case["url"]);
            let hosts: Vec<String> = case["allowed_hosts"]
                .as_array()
                .unwrap()
                .iter()
                .map(s)
                .collect();
            let hosts: Vec<&str> = hosts.iter().map(String::as_str).collect();
            assert_eq!(
                url_host_in_scope(&url, &hosts),
                b(&case["expected"]),
                "url_scope_check: {url} against {hosts:?}"
            );
            count += 1;
        }
        assert!(count > 0, "scope vector file has no vectors");
    }

    // ---- matching ------------------------------------------------------

    #[test]
    fn blocked_beats_allowed() {
        let sc = scope(
            r#"[scope]
allowed_domains = ["*.example.com"]
blocked_domains = ["admin.example.com"]
allowed_cidrs = ["10.0.1.0/24"]
blocked_cidrs = ["10.0.1.128/25"]
"#,
        );
        assert!(in_scope(&sc, "app.example.com"));
        assert!(!in_scope(&sc, "admin.example.com"));
        assert!(!in_scope(&sc, "ADMIN.example.com"));
        assert!(in_scope(&sc, "10.0.1.5"));
        assert!(!in_scope(&sc, "10.0.1.200"));
        assert!(in_scope(&sc, "10.0.1.0/26"));
        // Contained in the allowed range but overlapping the blocked half.
        assert!(!in_scope(&sc, "10.0.1.0/24"));
    }

    #[test]
    fn wildcard_does_not_match_apex_or_suffix() {
        let sc = scope("[scope]\nallowed_domains = [\"*.example.com\"]\n");
        assert!(in_scope(&sc, "a.example.com"));
        assert!(in_scope(&sc, "deep.sub.example.com"));
        assert!(!in_scope(&sc, "example.com"));
        assert!(!in_scope(&sc, "evil-example.com"));
        assert!(!in_scope(&sc, "example.com.evil.com"));
    }

    #[test]
    fn cidr_subject_requires_full_containment() {
        let sc = scope("[scope]\nallowed_cidrs = [\"10.0.1.0/24\", \"2001:db8::/32\"]\n");
        assert!(in_scope(&sc, "10.0.1.0/25"));
        assert!(in_scope(&sc, "10.0.1.0/24"));
        assert!(!in_scope(&sc, "10.0.0.0/8"));
        assert!(!in_scope(&sc, "10.0.2.0/25"));
        assert!(in_scope(&sc, "2001:db8:1::/48"));
        assert!(!in_scope(&sc, "2001:db8::/16"));
        // Hostnames never match a CIDR rule (no DNS lookup is made).
        assert!(!in_scope(&sc, "example.com"));
    }

    #[test]
    fn empty_scope_puts_nothing_in_scope() {
        let sc = scope("[scope]\nallowed_domains = []\nallowed_cidrs = []\n");
        assert!(!in_scope(&sc, "example.com"));
        assert!(!in_scope(&sc, "10.0.1.1"));
        let sc = scope("");
        assert!(!in_scope(&sc, "example.com"));
    }

    // ---- validator wiring ---------------------------------------------

    #[test]
    fn validator_enforces_scope_on_all_supported_types() {
        let sc = scope(
            "[scope]\nallowed_domains = [\"example.com\"]\nallowed_cidrs = [\"10.0.1.0/24\"]\n",
        );
        let ok = |t: &str, v: &str| validate_arg_in("t", &arg(t), v, false, Some(&sc));
        assert!(ok("scope_target", "example.com").is_ok());
        assert!(ok("scope_target", "10.0.1.7").is_ok());
        assert!(ok("scope_target", "10.0.1.0/28").is_ok());
        assert!(ok("url", "https://example.com/x").is_ok());
        assert!(ok("url", "https://EXAMPLE.com:8443/x").is_ok());
        assert!(ok("ip_address", "10.0.1.9").is_ok());
        assert!(ok("cidr", "10.0.1.0/25").is_ok());

        let err = ok("scope_target", "other.com").unwrap_err().to_string();
        assert!(
            err.contains("argument 't' target 'other.com' is not in scope"),
            "{err}"
        );
        assert!(ok("url", "https://evil.com/").is_err());
        assert!(ok("ip_address", "10.0.2.9").is_err());
        assert!(ok("cidr", "10.0.0.0/8").is_err());
    }

    #[test]
    fn validator_fails_closed_without_scope() {
        for t in SCOPE_CHECK_TYPES {
            let v = match *t {
                "url" => "https://example.com/",
                "cidr" => "10.0.1.0/24",
                "ip_address" => "10.0.1.1",
                _ => "example.com",
            };
            let err = validate_arg_in("t", &arg(t), v, false, None)
                .unwrap_err()
                .to_string();
            assert!(
                err.contains(
                    "argument 't' scope_check is enabled but no scope/scope.toml was found (set TOOLCLAD_SCOPE_FILE)"
                ),
                "{t}: {err}"
            );
        }
        // Without scope_check the scope is never consulted.
        let plain = ArgDef {
            type_name: "scope_target".to_string(),
            ..Default::default()
        };
        assert!(validate_arg_in("t", &plain, "example.com", false, None).is_ok());
    }

    #[test]
    fn in_scope_but_internal_is_still_refused() {
        let sc = scope("[scope]\nallowed_cidrs = [\"10.0.0.0/8\", \"127.0.0.0/8\"]\n");
        let mut def = arg("scope_target");
        def.block_internal = true;
        let err = validate_arg_in("t", &def, "10.0.1.1", false, Some(&sc))
            .unwrap_err()
            .to_string();
        assert!(!err.contains("not in scope"), "{err}");
        let mut def = arg("url");
        def.block_internal = true;
        assert!(validate_arg_in("t", &def, "http://127.0.0.1/", false, Some(&sc)).is_err());
        // And the reverse: public and not in scope reports the scope refusal.
        let mut def = arg("ip_address");
        def.block_internal = true;
        let err = validate_arg_in("t", &def, "8.8.8.8", false, Some(&sc))
            .unwrap_err()
            .to_string();
        assert!(err.contains("not in scope"), "{err}");
    }

    // ---- scope file loading -------------------------------------------

    #[test]
    fn scope_file_load_errors() {
        for (text, needle) in [
            (
                "[scope]\nallowed_domain = []\n",
                "unknown key 'scope.allowed_domain'",
            ),
            ("extra = 1\n[scope]\n", "unknown key 'extra'"),
            (
                "[scope]\nallowed_cidrs = [\"10.0.1.0/33\"]\n",
                "invalid CIDR",
            ),
            ("[scope]\nblocked_cidrs = [\"10.0.1/24\"]\n", "invalid CIDR"),
            (
                "[scope]\nallowed_domains = [\"a.*.example.com\"]\n",
                "invalid domain rule",
            ),
            (
                "[scope]\nallowed_domains = [\"*example.com\"]\n",
                "invalid domain rule",
            ),
            (
                "[scope]\nallowed_domains = [\"*\"]\n",
                "invalid domain rule",
            ),
            (
                "[scope]\nallowed_domains = [\"exa mple.com\"]\n",
                "invalid domain rule",
            ),
            (
                "[scope]\nallowed_domains = [\"Example.com\"]\n",
                "invalid domain rule",
            ),
            (
                "[scope]\nallowed_domains = \"example.com\"\n",
                "array of strings",
            ),
        ] {
            let err = parse_scope(text).unwrap_err().to_string();
            assert!(err.contains(needle), "{text:?}: {err}");
        }
    }

    #[test]
    fn repository_scope_file_parses() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../scope/scope.toml");
        if path.is_file() {
            let sc = load_scope_file(&path).unwrap();
            assert!(sc.allowed_domains.contains(&"example.com".to_string()));
        }
    }

    #[test]
    fn env_file_wins_over_upward_walk() {
        let root = temp_dir("env");
        std::fs::create_dir_all(root.join("scope")).unwrap();
        std::fs::write(
            root.join("scope/scope.toml"),
            "[scope]\nallowed_domains = [\"walk.example.com\"]\n",
        )
        .unwrap();
        let explicit = root.join("explicit.toml");
        std::fs::write(
            &explicit,
            "[scope]\nallowed_domains = [\"env.example.com\"]\n",
        )
        .unwrap();

        let sc = discover_scope_with(Some(explicit.as_os_str()), Some(&root))
            .unwrap()
            .unwrap();
        assert_eq!(sc.allowed_domains, vec!["env.example.com"]);
        assert_eq!(sc.source.as_deref(), Some(explicit.as_path()));
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn upward_walk_finds_parent_scope() {
        let root = temp_dir("walk");
        let deep = root.join("tools/net/nested");
        std::fs::create_dir_all(&deep).unwrap();
        std::fs::create_dir_all(root.join("scope")).unwrap();
        std::fs::write(
            root.join("scope/scope.toml"),
            "[scope]\nallowed_domains = [\"walk.example.com\"]\n",
        )
        .unwrap();
        let sc = discover_scope_with(None, Some(&deep)).unwrap().unwrap();
        assert_eq!(sc.allowed_domains, vec!["walk.example.com"]);
        // An empty env value counts as unset.
        let sc = discover_scope_with(Some(OsStr::new("")), Some(&deep))
            .unwrap()
            .unwrap();
        assert_eq!(sc.allowed_domains, vec!["walk.example.com"]);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn unreadable_env_file_is_an_error() {
        let root = temp_dir("missing");
        let missing = root.join("does-not-exist.toml");
        let err = discover_scope_with(Some(missing.as_os_str()), Some(&root))
            .unwrap_err()
            .to_string();
        assert!(err.contains("failed to read scope file"), "{err}");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn no_scope_anywhere_is_none() {
        // A temp dir normally sits outside any tree with a scope/ directory;
        // skip if this machine happens to have one above it.
        let root = temp_dir("none");
        let found = root
            .ancestors()
            .any(|d| d.join("scope").join("scope.toml").is_file());
        if !found {
            assert!(discover_scope_with(None, Some(&root)).unwrap().is_none());
        }
        std::fs::remove_dir_all(&root).ok();
    }
}
