package validator

import (
	"fmt"
	"net/netip"
	"strings"
)

// This file is the single home of the host / IP egress policy. Every place a
// literal address can reach a tool — scope_target (including the base
// address of a CIDR), the host of a url, ip_address and cidr — goes through
// enforceIPPolicy, so the range table below can be compared side by side
// with the same table in the other ToolClad runtimes.
//
// Two tiers:
//
//   - alwaysBlocked ranges are refused with or without block_internal. They
//     hold the link-local space, which contains the cloud metadata endpoint
//     169.254.169.254; no tool has a legitimate reason to reach it and the
//     blast radius (instance-credential theft) is maximal.
//   - nonPublic ranges are refused only when the argument sets
//     block_internal = true, so tools that legitimately target internal
//     hosts keep working without the opt-in.
//
// IPv4-mapped IPv6 addresses (::ffff:a.b.c.d) are unwrapped before lookup, so
// the mapped form of every entry is covered by the IPv4 table.

// blockedRange pairs a prefix with the reason reported when a target falls
// inside it. Tables are matched first-hit, so a narrower prefix must precede
// any wider one that contains it (255.255.255.255/32 before 240.0.0.0/4).
type blockedRange struct {
	prefix netip.Prefix
	reason string
}

// alwaysBlocked is applied regardless of block_internal.
var alwaysBlocked = []blockedRange{
	{netip.MustParsePrefix("169.254.0.0/16"), "is a link-local / cloud-metadata address (169.254.0.0/16) — always blocked"},
	{netip.MustParsePrefix("fe80::/10"), "is an IPv6 link-local address (fe80::/10) — always blocked"},
}

// nonPublicV4 is applied, after unmapping, when block_internal = true.
var nonPublicV4 = []blockedRange{
	{netip.MustParsePrefix("127.0.0.0/8"), "resolves to a loopback address"},
	{netip.MustParsePrefix("10.0.0.0/8"), "resolves to a private address"},
	{netip.MustParsePrefix("172.16.0.0/12"), "resolves to a private address"},
	{netip.MustParsePrefix("192.168.0.0/16"), "resolves to a private address"},
	{netip.MustParsePrefix("100.64.0.0/10"), "is a carrier-grade NAT address (100.64.0.0/10)"},
	{netip.MustParsePrefix("0.0.0.0/8"), "is the unspecified address 0.0.0.0"},
	{netip.MustParsePrefix("255.255.255.255/32"), "is the broadcast address"},
	{netip.MustParsePrefix("192.0.2.0/24"), "is a documentation-range address"},
	{netip.MustParsePrefix("198.51.100.0/24"), "is a documentation-range address"},
	{netip.MustParsePrefix("203.0.113.0/24"), "is a documentation-range address"},
	{netip.MustParsePrefix("198.18.0.0/15"), "is a benchmarking-range address (198.18.0.0/15)"},
	{netip.MustParsePrefix("240.0.0.0/4"), "is a reserved-range address (240.0.0.0/4)"},
}

// nonPublicV6 is applied to addresses that are not IPv4-mapped when
// block_internal = true.
var nonPublicV6 = []blockedRange{
	{netip.MustParsePrefix("::1/128"), "resolves to the IPv6 loopback ::1"},
	{netip.MustParsePrefix("::/128"), "is the IPv6 unspecified address ::"},
	{netip.MustParsePrefix("fc00::/7"), "is an IPv6 unique-local address (fc00::/7)"},
	{netip.MustParsePrefix("fe80::/10"), "is an IPv6 link-local address (fe80::/10)"},
	{netip.MustParsePrefix("2001:db8::/32"), "is an IPv6 documentation-range address (2001:db8::/32)"},
}

// matchRange returns the reason of the first table entry containing addr.
func matchRange(table []blockedRange, addr netip.Addr) string {
	for _, r := range table {
		if r.prefix.Contains(addr) {
			return r.reason
		}
	}
	return ""
}

// alwaysBlockedIPReason returns why addr must be refused regardless of
// policy, or "" if it is not in an always-blocked range. IPv4-mapped IPv6 is
// unwrapped first so ::ffff:169.254.169.254 is caught.
func alwaysBlockedIPReason(addr netip.Addr) string {
	return matchRange(alwaysBlocked, addr.Unmap())
}

// nonPublicIPReason returns why addr is a non-public address that SSRF
// defenses should block under block_internal, or "" if it is public.
// IPv4-mapped IPv6 is unwrapped first so ::ffff:127.0.0.1 is caught.
func nonPublicIPReason(addr netip.Addr) string {
	addr = addr.Unmap()
	if addr.Is4() {
		return matchRange(nonPublicV4, addr)
	}
	return matchRange(nonPublicV6, addr)
}

// enforceIPPolicy applies the egress policy to a literal target address:
// link-local / metadata is always refused; the remaining non-public ranges
// are refused only when the argument opted in with block_internal.
func enforceIPPolicy(argName string, addr netip.Addr, blockInternal bool) error {
	if reason := alwaysBlockedIPReason(addr); reason != "" {
		return newErr(argName, fmt.Sprintf("target %s", reason))
	}
	if blockInternal {
		if reason := nonPublicIPReason(addr); reason != "" {
			return newErr(argName, fmt.Sprintf("target %s (blocked by block_internal policy)", reason))
		}
	}
	return nil
}

// parseCanonicalIP parses only canonical IP text: dotted-quad IPv4 with
// decimal octets and no leading zeros, or standard IPv6 without a zone.
// Integer (2130706433), hex (0x7f000001), octal (0177.0.0.1) and shorthand
// (127.1) encodings — all of which a libc resolver would expand to
// 127.0.0.1 — fail here by construction and are caught by
// looksLikeIPLiteral instead.
func parseCanonicalIP(val string) (netip.Addr, bool) {
	addr, err := netip.ParseAddr(val)
	if err != nil || addr.Zone() != "" {
		return netip.Addr{}, false
	}
	return addr, true
}

// looksLikeIPLiteral reports whether val is an attempt at an IP literal in a
// non-canonical encoding: a 0x… hex form, or every dot-separated label is
// all ASCII digits (integer / dotted-decimal / octal / shorthand). Canonical
// IPs are handled by parseCanonicalIP first and never reach here.
func looksLikeIPLiteral(val string) bool {
	if len(val) >= 2 && strings.EqualFold(val[:2], "0x") {
		return true
	}
	for _, label := range strings.Split(val, ".") {
		if label == "" || !allASCIIDigits(label) {
			return false
		}
	}
	return true
}

// tldNotAllNumeric reports whether the rightmost DNS label is non-empty and
// not entirely numeric. A real TLD is never all digits (RFC 3696 §2), so
// this rejects e.g. example.123, dotted-decimal IPs that slipped past the
// literal parser, and a trailing-dot form whose last label is empty.
func tldNotAllNumeric(val string) bool {
	labels := strings.Split(val, ".")
	tld := labels[len(labels)-1]
	return tld != "" && !allASCIIDigits(tld)
}

func allASCIIDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// hasPunycodeLabel reports whether any DNS label in host is an A-label
// (xn-- prefix). Comparison is case-insensitive per IDNA: XN--, Xn-- and
// xN-- all count. Used to defend against IDN homoglyph bypass.
func hasPunycodeLabel(host string) bool {
	for _, label := range strings.Split(host, ".") {
		if len(label) >= 4 && strings.EqualFold(label[:4], "xn--") {
			return true
		}
	}
	return false
}
