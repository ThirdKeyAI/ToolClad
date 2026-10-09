package validator

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
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
//
// A name can reach a blocked address without spelling it as a literal, so the
// same table is also applied through three name-side controls:
//
//   - the internal-name denylist (enforceInternalName) refuses localhost and
//     the private-use suffixes unconditionally;
//   - an IP literal embedded in a hostname (embeddedIPLiteral) is extracted
//     and put through the range policy before the value is treated as a
//     name, closing the wildcard-DNS bypass (127.0.0.1.nip.io);
//   - under block_internal every A/AAAA answer for a name is put through the
//     range policy (enforceResolvedPolicy), failing closed when the name
//     cannot be resolved.
//
// A CIDR value is tested for overlap with every blocked range
// (enforceCIDRPolicy), not just by its base address, so a supernet such as
// 8.0.0.0/5 cannot smuggle 10.0.0.0/8 past the policy.

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

// matchRangeOverlap returns the reason of the first table entry whose range
// shares any address with prefix. Overlap, not containment of the base
// address, is the right test for a range: 8.0.0.0/5 has a public base but
// covers all of 10.0.0.0/8. netip.Prefix.Overlaps reports false across
// address families, so one pass over a mixed table is safe.
func matchRangeOverlap(table []blockedRange, prefix netip.Prefix) string {
	for _, r := range table {
		if r.prefix.Overlaps(prefix) {
			return r.reason
		}
	}
	return ""
}

// unmapPrefix converts an IPv4-mapped IPv6 prefix (::ffff:a.b.c.d/n with
// n >= 96) to its IPv4 form so the IPv4 table covers it, mirroring what
// Addr.Unmap does for single addresses. Any other prefix is returned as is.
func unmapPrefix(prefix netip.Prefix) netip.Prefix {
	addr := prefix.Addr()
	if addr.Is4In6() && prefix.Bits() >= 96 {
		return netip.PrefixFrom(addr.Unmap(), prefix.Bits()-96)
	}
	return prefix
}

// enforceCIDRPolicy applies the egress policy to a range target: refused if
// it overlaps the link-local / metadata space at all, and, under
// block_internal, if it overlaps any non-public range. Both IPv4 and IPv6
// prefixes are handled; the policy messages are the same ones a literal
// address inside the range would receive.
func enforceCIDRPolicy(argName string, prefix netip.Prefix, blockInternal bool) error {
	prefix = unmapPrefix(prefix)
	if reason := matchRangeOverlap(alwaysBlocked, prefix); reason != "" {
		return newErr(argName, fmt.Sprintf("target %s", reason))
	}
	if blockInternal {
		table := nonPublicV6
		if prefix.Addr().Is4() {
			table = nonPublicV4
		}
		if reason := matchRangeOverlap(table, prefix); reason != "" {
			return newErr(argName, fmt.Sprintf("target %s (blocked by block_internal policy)", reason))
		}
	}
	return nil
}

// internalNameSuffixes are the private-use and site-local DNS suffixes that
// never name a public host. A target under one of them is refused with or
// without block_internal, alongside the exact names in isInternalName.
var internalNameSuffixes = []string{
	".localhost",
	".local",
	".internal",
	".home.arpa",
	".lan",
	".intranet",
	".corp",
	".private",
}

// isInternalName reports whether host is on the internal-name denylist:
// exactly localhost or metadata.google.internal, or any name under one of
// internalNameSuffixes. The comparison is case-insensitive and ignores one
// trailing dot, so a fully-qualified spelling cannot sidestep it.
func isInternalName(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	if h == "localhost" || h == "metadata.google.internal" {
		return true
	}
	for _, suffix := range internalNameSuffixes {
		if strings.HasSuffix(h, suffix) {
			return true
		}
	}
	return false
}

// enforceInternalName refuses a host on the internal-name denylist. This is
// unconditional: an internal name is never a legitimate egress target, and
// resolving it would only confirm what the name already says.
func enforceInternalName(argName, host string) error {
	if isInternalName(host) {
		return newErr(argName, "target resolves to an internal name — always blocked")
	}
	return nil
}

// embeddedIPLiteral returns the IPv4 address a hostname spells in its
// leading labels, which wildcard-DNS services (nip.io, sslip.io, xip.io)
// resolve to that address: either the first four dot-separated labels form
// a canonical dotted quad (127.0.0.1.nip.io) or the first label is a dashed
// quad (10-0-0-1.nip.io). The shape alone is not a refusal — the caller puts
// the address through the range policy, so 93-184-216-34.example.com stays
// an ordinary hostname.
func embeddedIPLiteral(host string) (netip.Addr, bool) {
	labels := strings.Split(host, ".")
	if len(labels) >= 4 {
		if addr, ok := parseCanonicalIP(strings.Join(labels[:4], ".")); ok && addr.Is4() {
			return addr, true
		}
	}
	return parseDashedQuad(labels[0])
}

// parseDashedQuad parses a label of four 1-3 digit groups separated by "-",
// each 0-255, into an IPv4 address.
func parseDashedQuad(label string) (netip.Addr, bool) {
	groups := strings.Split(label, "-")
	if len(groups) != 4 {
		return netip.Addr{}, false
	}
	var octets [4]byte
	for i, g := range groups {
		if len(g) == 0 || len(g) > 3 || !allASCIIDigits(g) {
			return netip.Addr{}, false
		}
		n, err := strconv.Atoi(g)
		if err != nil || n > 255 {
			return netip.Addr{}, false
		}
		octets[i] = byte(n)
	}
	return netip.AddrFrom4(octets), true
}

// resolveTimeout bounds the DNS lookup made for a name under block_internal.
const resolveTimeout = 2 * time.Second

// lookupHost returns every A/AAAA answer for host, IPv4-mapped forms
// unwrapped. It is a package variable so tests can substitute a fixed
// answer table and never depend on live DNS; the default is the system
// resolver under a bounded context.
var lookupHost = func(host string) ([]netip.Addr, error) {
	ctx, cancel := context.WithTimeout(context.Background(), resolveTimeout)
	defer cancel()
	answers, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	addrs := make([]netip.Addr, 0, len(answers))
	for _, a := range answers {
		if addr, ok := netip.AddrFromSlice(a.IP); ok {
			addrs = append(addrs, addr.Unmap())
		}
	}
	return addrs, nil
}

// enforceResolvedPolicy is the block_internal control for a name that is
// not a literal and was not caught by the denylist or the embedded-literal
// rule: the name is resolved and every answer is put through the range
// policy, so a name pointing at an internal address — by attacker-controlled
// DNS or by rebinding — is refused. A name that cannot be resolved cannot be
// shown to be public, so resolution failure is a refusal, not a pass.
//
// The lookup here is a check, not a binding: between this answer and the
// tool's own connect a rebinding resolver can hand back a different
// address. A runtime that wants to close that window should pin the
// address this check saw into the invocation (for example
// `curl --resolve host:443:ip`) rather than letting the tool resolve again.
func enforceResolvedPolicy(argName, host string) error {
	addrs, err := lookupHost(host)
	if err != nil || len(addrs) == 0 {
		return newErr(argName, fmt.Sprintf("could not resolve host '%s' to verify it is public (block_internal)", host))
	}
	for _, addr := range addrs {
		if err := enforceIPPolicy(argName, addr, true); err != nil {
			return err
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

// CheckLiteralHost applies the host policy to the manifest-controlled host
// of an [http] url (hostport may carry a :port). A literal address, or one
// embedded in a wildcard-DNS name, goes through the range table: link-local
// / metadata always, the non-public ranges when blockInternal. The
// metadata hostname is always refused; the rest of the internal-name
// denylist applies under blockInternal, so a manifest that targets a local
// API without the opt-in keeps working. The name is not resolved here: this
// runs at load, and the host is the author's, not the caller's.
func CheckLiteralHost(hostport string, blockInternal bool) error {
	const name = "http.url"
	host, _, err := splitURLHostPort(hostport)
	if err != nil {
		return newErr(name, err.Error())
	}
	if addr, ok := parseCanonicalIP(host); ok {
		return enforceIPPolicy(name, addr, blockInternal)
	}
	if addr, ok := embeddedIPLiteral(host); ok {
		if err := enforceIPPolicy(name, addr, blockInternal); err != nil {
			return err
		}
	}
	if strings.EqualFold(strings.TrimSuffix(host, "."), "metadata.google.internal") {
		return newErr(name, "target is the cloud metadata name — always blocked")
	}
	if blockInternal {
		if err := enforceInternalName(name, host); err != nil {
			return err
		}
	}
	return nil
}
