//! Host / IP egress policy shared by every argument type that can carry a
//! literal address: `scope_target`, `url`, `ip_address` and `cidr`.
//!
//! The range table in this module is the single source of truth for the Rust
//! runtime and is mirrored verbatim by the Go, JavaScript and Python runtimes,
//! so the four can be compared side by side. There are two tiers:
//!
//! * **Always blocked**, with or without `block_internal`: the link-local
//!   ranges. IPv4 link-local contains the cloud-metadata endpoint
//!   169.254.169.254, and the blast radius of reaching it (instance-credential
//!   theft) is maximal. No agent tool has a legitimate reason to target these.
//! * **Blocked when `block_internal = true`**: loopback, private, shared
//!   (carrier-grade NAT), unspecified, broadcast, documentation, benchmarking
//!   and reserved space, plus the IPv6 equivalents.
//!
//! IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) are unwrapped before the
//! table is consulted, so the IPv6 spelling of any IPv4 range is caught.
//!
//! The parser helpers at the bottom (`parse_canonical_ip`,
//! `looks_like_ip_literal`, `has_punycode_label`) sit in front of the policy:
//! a value the resolver would expand (`2130706433`, `0x7f000001`,
//! `0177.0.0.1`, `127.1`) must be refused outright rather than passed through
//! as a "hostname" the table never sees.
//!
//! The remaining hostname rules (internal-suffix denylist, embedded IP
//! literals, CIDR overlap, DNS resolution under `block_internal`) plug into
//! this module in a later wave.

use crate::types::ToolCladError;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// One blocked IPv4 prefix and the reason reported when a target falls in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockedRange4 {
    pub net: Ipv4Addr,
    pub prefix: u8,
    pub reason: &'static str,
}

/// One blocked IPv6 prefix and the reason reported when a target falls in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockedRange6 {
    pub net: Ipv6Addr,
    pub prefix: u8,
    pub reason: &'static str,
}

const fn r4(a: u8, b: u8, c: u8, d: u8, prefix: u8, reason: &'static str) -> BlockedRange4 {
    BlockedRange4 {
        net: Ipv4Addr::new(a, b, c, d),
        prefix,
        reason,
    }
}

#[allow(clippy::too_many_arguments)]
const fn r6(
    s0: u16,
    s1: u16,
    s2: u16,
    s3: u16,
    s4: u16,
    s5: u16,
    s6: u16,
    s7: u16,
    prefix: u8,
    reason: &'static str,
) -> BlockedRange6 {
    BlockedRange6 {
        net: Ipv6Addr::new(s0, s1, s2, s3, s4, s5, s6, s7),
        prefix,
        reason,
    }
}

/// IPv4 ranges blocked regardless of `block_internal`.
pub const ALWAYS_BLOCKED_V4: &[BlockedRange4] = &[r4(
    169,
    254,
    0,
    0,
    16,
    "is a link-local / cloud-metadata address (169.254.0.0/16) — always blocked",
)];

/// IPv6 ranges blocked regardless of `block_internal`.
pub const ALWAYS_BLOCKED_V6: &[BlockedRange6] = &[r6(
    0xfe80,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    10,
    "is an IPv6 link-local address (fe80::/10) — always blocked",
)];

/// IPv4 ranges blocked when `block_internal = true`. Entries are tested in
/// order, so the broadcast address (which also lies inside 240.0.0.0/4) is
/// reported as broadcast, not as reserved.
pub const BLOCK_INTERNAL_V4: &[BlockedRange4] = &[
    r4(127, 0, 0, 0, 8, "resolves to a loopback address"),
    r4(10, 0, 0, 0, 8, "resolves to a private address"),
    r4(172, 16, 0, 0, 12, "resolves to a private address"),
    r4(192, 168, 0, 0, 16, "resolves to a private address"),
    r4(
        100,
        64,
        0,
        0,
        10,
        "resolves to a shared / carrier-grade NAT address (100.64.0.0/10)",
    ),
    r4(0, 0, 0, 0, 8, "is in the unspecified range (0.0.0.0/8)"),
    r4(255, 255, 255, 255, 32, "is the broadcast address"),
    r4(192, 0, 2, 0, 24, "is a documentation-range address"),
    r4(198, 51, 100, 0, 24, "is a documentation-range address"),
    r4(203, 0, 113, 0, 24, "is a documentation-range address"),
    r4(
        198,
        18,
        0,
        0,
        15,
        "is a benchmarking-range address (198.18.0.0/15)",
    ),
    r4(240, 0, 0, 0, 4, "is a reserved address (240.0.0.0/4)"),
];

/// IPv6 ranges blocked when `block_internal = true`. Link-local appears here
/// as well as in the always-blocked tier so the table matches the policy as
/// written; in practice the always-blocked check fires first.
pub const BLOCK_INTERNAL_V6: &[BlockedRange6] = &[
    r6(
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        1,
        128,
        "resolves to the IPv6 loopback ::1",
    ),
    r6(
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        128,
        "is the IPv6 unspecified address ::",
    ),
    r6(
        0xfc00,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        7,
        "is an IPv6 unique-local address (fc00::/7)",
    ),
    r6(
        0xfe80,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        10,
        "is an IPv6 link-local address (fe80::/10)",
    ),
    r6(
        0x2001,
        0x0db8,
        0,
        0,
        0,
        0,
        0,
        0,
        32,
        "is an IPv6 documentation-range address (2001:db8::/32)",
    ),
];

/// True if `ip` lies inside the range (prefix match on the leading bits).
pub fn v4_in_range(ip: Ipv4Addr, range: &BlockedRange4) -> bool {
    let mask: u32 = if range.prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(range.prefix.min(32)))
    };
    (u32::from(ip) & mask) == (u32::from(range.net) & mask)
}

/// True if `ip` lies inside the range (prefix match on the leading bits).
pub fn v6_in_range(ip: Ipv6Addr, range: &BlockedRange6) -> bool {
    let mask: u128 = if range.prefix == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(range.prefix.min(128)))
    };
    (u128::from(ip) & mask) == (u128::from(range.net) & mask)
}

/// The IPv4 view of `ip`: the address itself, or the embedded address of an
/// IPv4-mapped IPv6 literal (`::ffff:a.b.c.d`). `None` for every other IPv6.
fn unwrap_v4(ip: &IpAddr) -> Option<Ipv4Addr> {
    match ip {
        IpAddr::V4(a) => Some(*a),
        IpAddr::V6(a) => a.to_ipv4_mapped(),
    }
}

/// Reason if `ip` must be blocked regardless of policy: link-local
/// (169.254.0.0/16, fe80::/10), which includes the cloud-metadata endpoint
/// 169.254.169.254. IPv4-mapped IPv6 is unwrapped first.
pub fn always_blocked_ip_reason(ip: &IpAddr) -> Option<&'static str> {
    if let Some(a) = unwrap_v4(ip) {
        return ALWAYS_BLOCKED_V4
            .iter()
            .find(|r| v4_in_range(a, r))
            .map(|r| r.reason);
    }
    if let IpAddr::V6(a) = ip {
        return ALWAYS_BLOCKED_V6
            .iter()
            .find(|r| v6_in_range(*a, r))
            .map(|r| r.reason);
    }
    None
}

/// Reason if `ip` is a non-public address that the opt-in `block_internal`
/// policy blocks: loopback, private, shared, unspecified, broadcast,
/// documentation, benchmarking, reserved, and the IPv6 equivalents.
/// IPv4-mapped IPv6 is unwrapped so `::ffff:127.0.0.1` is caught.
pub fn non_public_ip_reason(ip: &IpAddr) -> Option<&'static str> {
    if let Some(a) = unwrap_v4(ip) {
        return BLOCK_INTERNAL_V4
            .iter()
            .find(|r| v4_in_range(a, r))
            .map(|r| r.reason);
    }
    if let IpAddr::V6(a) = ip {
        return BLOCK_INTERNAL_V6
            .iter()
            .find(|r| v6_in_range(*a, r))
            .map(|r| r.reason);
    }
    None
}

/// Enforce the egress policy for a literal (or resolved) target IP on behalf
/// of argument `name`: link-local / metadata is always blocked; the remaining
/// non-public ranges are blocked only under the opt-in `block_internal`
/// policy.
pub fn enforce_ip_policy(
    name: &str,
    ip: &IpAddr,
    block_internal: bool,
) -> Result<(), ToolCladError> {
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

/// Parse only canonical IP text (dotted-quad IPv4 / standard IPv6). Rejects
/// integer, hex, octal, and shorthand encodings by construction: the `std`
/// parsers accept nothing else.
pub fn parse_canonical_ip(val: &str) -> Option<IpAddr> {
    val.parse::<Ipv4Addr>()
        .map(IpAddr::V4)
        .or_else(|_| val.parse::<Ipv6Addr>().map(IpAddr::V6))
        .ok()
}

/// True if `val` is an attempt at an IP literal in a non-canonical encoding:
/// a `0x…` hex form, or every dot-separated label is all ASCII digits
/// (integer / dotted-decimal / octal / shorthand). A libc resolver would
/// expand any of these to an address, so they must never pass as a hostname.
/// Canonical IPs are handled by [`parse_canonical_ip`] first and never reach
/// here.
pub fn looks_like_ip_literal(val: &str) -> bool {
    let lower = val.to_ascii_lowercase();
    if lower.starts_with("0x") {
        return true;
    }
    val.split('.')
        .all(|label| !label.is_empty() && label.bytes().all(|b| b.is_ascii_digit()))
}

/// True if any DNS label in `host` is an A-label (`xn--…`). Comparison is
/// case-insensitive per IDNA: `XN--`, `Xn--`, `xN--` all count. Punycode is
/// rejected everywhere because a homoglyph domain supplied in its ASCII form
/// would otherwise satisfy an ASCII-only hostname check.
pub fn has_punycode_label(host: &str) -> bool {
    host.split('.')
        .any(|label| label.len() >= 4 && label.as_bytes()[..4].eq_ignore_ascii_case(b"xn--"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap_or_else(|_| panic!("bad test literal {s}"))
    }

    #[test]
    fn always_blocked_tier_fires_in_both_modes() {
        for v in [
            "169.254.169.254",
            "169.254.0.1",
            "169.254.255.255",
            "::ffff:169.254.169.254",
            "fe80::1",
            "febf::1", // top of fe80::/10
        ] {
            let a = ip(v);
            assert!(always_blocked_ip_reason(&a).is_some(), "{v}");
            for block_internal in [false, true] {
                let err = enforce_ip_policy("t", &a, block_internal)
                    .unwrap_err()
                    .to_string();
                assert!(err.contains("always blocked"), "{v} -> {err}");
            }
        }
        // Just outside the ranges.
        for v in ["169.253.255.255", "169.255.0.0", "fe7f::1", "fec0::1"] {
            assert!(always_blocked_ip_reason(&ip(v)).is_none(), "{v}");
        }
    }

    #[test]
    fn block_internal_tier_covers_every_range() {
        // One representative per table row, plus the IPv4-mapped spelling.
        let cases: &[(&str, &str)] = &[
            ("127.0.0.1", "loopback"),
            ("127.255.255.254", "loopback"),
            ("10.0.0.5", "private"),
            ("172.16.0.1", "private"),
            ("172.31.255.255", "private"),
            ("192.168.1.1", "private"),
            ("100.64.0.1", "carrier-grade NAT"),
            ("100.127.255.255", "carrier-grade NAT"),
            ("0.0.0.0", "unspecified"),
            ("0.1.2.3", "unspecified"),
            ("255.255.255.255", "broadcast"),
            ("192.0.2.1", "documentation"),
            ("198.51.100.1", "documentation"),
            ("203.0.113.1", "documentation"),
            ("198.18.0.1", "benchmarking"),
            ("198.19.255.255", "benchmarking"),
            ("240.0.0.1", "reserved"),
            ("255.255.255.254", "reserved"),
            ("::1", "loopback"),
            ("::", "unspecified"),
            ("fc00::1", "unique-local"),
            ("fdff::1", "unique-local"),
            ("fe80::1", "link-local"),
            ("2001:db8::1", "documentation"),
            ("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", "documentation"),
            ("::ffff:127.0.0.1", "loopback"),
            ("::ffff:10.1.2.3", "private"),
            ("::ffff:100.64.0.1", "carrier-grade NAT"),
            ("::ffff:0.0.0.0", "unspecified"),
            ("::ffff:255.255.255.255", "broadcast"),
            ("::ffff:198.18.0.1", "benchmarking"),
            ("::ffff:240.0.0.1", "reserved"),
        ];
        for (v, word) in cases {
            let a = ip(v);
            let reason = non_public_ip_reason(&a).unwrap_or_else(|| panic!("{v} not blocked"));
            assert!(reason.contains(word), "{v}: {reason}");
            // Enforced when the policy is on. A row that also sits in the
            // always-blocked tier (fe80::/10) is reported by that tier first
            // and is refused with the policy off as well; every other row is
            // open with the policy off.
            let err = enforce_ip_policy("t", &a, true).unwrap_err().to_string();
            if always_blocked_ip_reason(&a).is_some() {
                assert!(err.contains("always blocked"), "{v} -> {err}");
                assert!(enforce_ip_policy("t", &a, false).is_err(), "{v} off");
            } else {
                assert!(
                    err.contains("blocked by block_internal policy"),
                    "{v} -> {err}"
                );
                assert!(enforce_ip_policy("t", &a, false).is_ok(), "{v} off");
            }
        }
    }

    #[test]
    fn block_internal_tier_range_boundaries() {
        // Immediately outside each range is public.
        for v in [
            "126.255.255.255",
            "128.0.0.0",
            "9.255.255.255",
            "11.0.0.0",
            "172.15.255.255",
            "172.32.0.0",
            "192.167.255.255",
            "192.169.0.0",
            "100.63.255.255",
            "100.128.0.0",
            "1.0.0.0",
            "192.0.1.255",
            "192.0.3.0",
            "198.51.99.255",
            "198.51.101.0",
            "203.0.112.255",
            "203.0.114.0",
            "198.17.255.255",
            "198.20.0.0",
            "239.255.255.255",
            "93.184.216.34",
            "8.8.8.8",
            "::2",
            "fbff::1",
            "fe00::1",
            "2001:db7:ffff::1",
            "2001:db9::1",
            "2606:2800:220:1:248:1893:25c8:1946",
            "::ffff:93.184.216.34",
        ] {
            let a = ip(v);
            assert!(non_public_ip_reason(&a).is_none(), "{v} should be public");
            assert!(enforce_ip_policy("t", &a, true).is_ok(), "{v}");
        }
    }

    #[test]
    fn broadcast_is_reported_before_reserved() {
        assert_eq!(
            non_public_ip_reason(&ip("255.255.255.255")),
            Some("is the broadcast address")
        );
    }

    #[test]
    fn prefix_math_handles_zero_and_full_prefixes() {
        let all4 = r4(0, 0, 0, 0, 0, "everything");
        assert!(v4_in_range(Ipv4Addr::new(93, 184, 216, 34), &all4));
        let exact4 = r4(93, 184, 216, 34, 32, "exact");
        assert!(v4_in_range(Ipv4Addr::new(93, 184, 216, 34), &exact4));
        assert!(!v4_in_range(Ipv4Addr::new(93, 184, 216, 35), &exact4));

        let all6 = r6(0, 0, 0, 0, 0, 0, 0, 0, 0, "everything");
        assert!(v6_in_range(
            Ipv6Addr::new(0x2606, 0x2800, 0, 0, 0, 0, 0, 1),
            &all6
        ));
        let exact6 = r6(0, 0, 0, 0, 0, 0, 0, 1, 128, "exact");
        assert!(v6_in_range(Ipv6Addr::LOCALHOST, &exact6));
        assert!(!v6_in_range(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 2), &exact6));
    }

    #[test]
    fn range_table_matches_policy_document() {
        // Pin the table shape so a drift in any runtime is a visible diff.
        let v4: Vec<String> = BLOCK_INTERNAL_V4
            .iter()
            .map(|r| format!("{}/{}", r.net, r.prefix))
            .collect();
        assert_eq!(
            v4,
            [
                "127.0.0.0/8",
                "10.0.0.0/8",
                "172.16.0.0/12",
                "192.168.0.0/16",
                "100.64.0.0/10",
                "0.0.0.0/8",
                "255.255.255.255/32",
                "192.0.2.0/24",
                "198.51.100.0/24",
                "203.0.113.0/24",
                "198.18.0.0/15",
                "240.0.0.0/4",
            ]
        );
        let v6: Vec<String> = BLOCK_INTERNAL_V6
            .iter()
            .map(|r| format!("{}/{}", r.net, r.prefix))
            .collect();
        assert_eq!(
            v6,
            [
                "::1/128",
                "::/128",
                "fc00::/7",
                "fe80::/10",
                "2001:db8::/32"
            ]
        );
        let always4: Vec<String> = ALWAYS_BLOCKED_V4
            .iter()
            .map(|r| format!("{}/{}", r.net, r.prefix))
            .collect();
        assert_eq!(always4, ["169.254.0.0/16"]);
        let always6: Vec<String> = ALWAYS_BLOCKED_V6
            .iter()
            .map(|r| format!("{}/{}", r.net, r.prefix))
            .collect();
        assert_eq!(always6, ["fe80::/10"]);
    }

    #[test]
    fn canonical_ip_parser_rejects_resolver_expansions() {
        assert!(parse_canonical_ip("127.0.0.1").is_some());
        assert!(parse_canonical_ip("::1").is_some());
        assert!(parse_canonical_ip("::ffff:127.0.0.1").is_some());
        for v in [
            "2130706433",
            "0x7f000001",
            "0177.0.0.1",
            "127.1",
            "010.0.0.1",
            "127.0.0.1.",
            "[::1]",
        ] {
            assert!(parse_canonical_ip(v).is_none(), "{v}");
        }
    }

    #[test]
    fn non_canonical_literal_detection() {
        for v in [
            "2130706433",
            "0x7f000001",
            "0X7F000001",
            "0177.0.0.1",
            "127.1",
            "1.2.3",
        ] {
            assert!(looks_like_ip_literal(v), "{v}");
        }
        for v in ["example.com", "localhost", "1.example", "a.1", "", "."] {
            assert!(!looks_like_ip_literal(v), "{v}");
        }
    }

    #[test]
    fn punycode_label_detection_is_case_insensitive() {
        for v in [
            "xn--example-9c.com",
            "sub.XN--example.com",
            "Xn--a.b",
            "a.xN--b",
        ] {
            assert!(has_punycode_label(v), "{v}");
        }
        for v in ["example.com", "xn-.com", "axn--b.com", "xn.com", ""] {
            assert!(!has_punycode_label(v), "{v}");
        }
    }
}
