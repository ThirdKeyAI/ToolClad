/**
 * Host / IP egress policy.
 *
 * One place for everything that decides whether a literal address may be a
 * tool target, so the range table can be compared side by side with the
 * other runtimes. The parsers here are deliberately strict and hand-rolled:
 * a normalizing parser (`new URL()`, `net.isIP` with its lenient forms, a
 * resolver) is exactly what hides the obfuscated encodings that this policy
 * exists to refuse. Only dotted-quad IPv4 and standard RFC 4291 IPv6 text are
 * accepted; integer, hex, octal and shorthand forms (`2130706433`,
 * `0x7f000001`, `0177.0.0.1`, `127.1`) fail to parse and are reported as
 * non-canonical literals by the caller.
 *
 * Representation: IPv4 is an unsigned 32-bit integer, IPv6 is an array of
 * eight 16-bit groups. IPv4-mapped IPv6 (`::ffff:a.b.c.d`) is unwrapped
 * before any range test so `::ffff:127.0.0.1` is caught by the IPv4 rows.
 */

/**
 * Ranges refused for every target, with or without `block_internal`.
 * The IPv4 link-local block contains the cloud-metadata endpoint
 * 169.254.169.254; no agent tool has a legitimate reason to reach it and
 * the blast radius (instance-credential theft) is maximal.
 * Rows are `[cidr, reason]`; the first matching row wins.
 */
export const ALWAYS_BLOCKED_RANGES = Object.freeze([
  ["169.254.0.0/16", "is a link-local / cloud-metadata address (169.254.0.0/16) — always blocked"],
  ["fe80::/10", "is an IPv6 link-local address (fe80::/10) — always blocked"],
]);

/**
 * Ranges refused only under the opt-in `block_internal = true` policy.
 * Rows are `[cidr, reason]`; the first matching row wins, so the broadcast
 * address (which also lies inside 240.0.0.0/4) is reported as broadcast, not
 * as reserved. IPv6 link-local appears here as well as in the always-blocked
 * tier so the table matches the policy as written; in practice the
 * always-blocked check fires first.
 */
export const BLOCK_INTERNAL_RANGES = Object.freeze([
  // IPv4
  ["127.0.0.0/8", "resolves to a loopback address"],
  ["10.0.0.0/8", "resolves to a private address"],
  ["172.16.0.0/12", "resolves to a private address"],
  ["192.168.0.0/16", "resolves to a private address"],
  ["100.64.0.0/10", "resolves to a shared / carrier-grade NAT address (100.64.0.0/10)"],
  ["0.0.0.0/8", "is in the unspecified range (0.0.0.0/8)"],
  ["255.255.255.255/32", "is the broadcast address"],
  ["192.0.2.0/24", "is a documentation-range address"],
  ["198.51.100.0/24", "is a documentation-range address"],
  ["203.0.113.0/24", "is a documentation-range address"],
  ["198.18.0.0/15", "is a benchmarking-range address (198.18.0.0/15)"],
  ["240.0.0.0/4", "is a reserved address (240.0.0.0/4)"],
  // IPv6
  ["::1/128", "resolves to the IPv6 loopback ::1"],
  ["::/128", "is the IPv6 unspecified address ::"],
  ["fc00::/7", "is an IPv6 unique-local address (fc00::/7)"],
  ["fe80::/10", "is an IPv6 link-local address (fe80::/10)"],
  ["2001:db8::/32", "is an IPv6 documentation-range address (2001:db8::/32)"],
]);

const IPV4_OCTET_RE = /^(0|[1-9][0-9]{0,2})$/;
const HEX_GROUP_RE = /^[0-9a-fA-F]{1,4}$/;

/**
 * Parse a canonical dotted-quad IPv4 literal. Exactly four decimal octets,
 * each 0-255 with no leading zeros (so `01.2.3.4` and `0177.0.0.1` fail, as
 * they do in the Rust and Go standard parsers).
 * @param {string} str
 * @returns {number|null} Unsigned 32-bit integer, or null if not canonical
 */
export function parseIpv4(str) {
  const labels = str.split(".");
  if (labels.length !== 4) return null;
  let addr = 0;
  for (const label of labels) {
    if (!IPV4_OCTET_RE.test(label)) return null;
    const octet = Number(label);
    if (octet > 255) return null;
    addr = addr * 256 + octet;
  }
  return addr >>> 0;
}

/**
 * Parse a standard RFC 4291 IPv6 literal: hex groups of 1-4 digits, at most
 * one `::`, an optional trailing dotted-quad IPv4 (`::ffff:1.2.3.4`). No
 * brackets, no zone id (`%eth0`), nothing else.
 * @param {string} str
 * @returns {number[]|null} Eight 16-bit groups, or null if not canonical
 */
export function parseIpv6(str) {
  if (str.length === 0 || !/^[0-9a-fA-F:.]+$/.test(str)) return null;
  const gap = str.indexOf("::");
  let head;
  let tail;
  if (gap === -1) {
    head = str;
    tail = null;
  } else {
    head = str.slice(0, gap);
    tail = str.slice(gap + 2);
    if (tail.includes("::")) return null;
  }
  // A dotted-quad IPv4 may only close the address: in the head when there
  // is no `::`, otherwise only in the tail.
  const headGroups = parseGroupRun(head, tail === null);
  if (headGroups === null) return null;
  const tailGroups = tail === null ? [] : parseGroupRun(tail, true);
  if (tailGroups === null) return null;
  if (tail === null) {
    // No `::` — the head must be the whole address.
    return headGroups.length === 8 ? headGroups : null;
  }
  // `::` stands for at least one zero group.
  if (headGroups.length + tailGroups.length > 7) return null;
  const zeros = new Array(8 - headGroups.length - tailGroups.length).fill(0);
  return [...headGroups, ...zeros, ...tailGroups];
}

/**
 * Parse a colon-separated run of hex groups. When `allowIpv4Tail` is set the
 * final group may be a dotted-quad IPv4, which contributes two groups.
 * @returns {number[]|null}
 */
function parseGroupRun(run, allowIpv4Tail) {
  if (run === "") return [];
  const parts = run.split(":");
  const groups = [];
  for (let i = 0; i < parts.length; i++) {
    const part = parts[i];
    if (i === parts.length - 1 && part.includes(".")) {
      if (!allowIpv4Tail) return null;
      const v4 = parseIpv4(part);
      if (v4 === null) return null;
      groups.push(v4 >>> 16, v4 & 0xffff);
      continue;
    }
    if (!HEX_GROUP_RE.test(part)) return null;
    groups.push(parseInt(part, 16));
  }
  return groups;
}

/**
 * Parse only canonical IP text: dotted-quad IPv4 or standard IPv6. Integer,
 * hex, octal and shorthand encodings fail by construction.
 * @param {string} str
 * @returns {{family: 4, addr: number} | {family: 6, groups: number[]} | null}
 */
export function parseCanonicalIp(str) {
  const v4 = parseIpv4(str);
  if (v4 !== null) return { family: 4, addr: v4 };
  const v6 = parseIpv6(str);
  if (v6 !== null) return { family: 6, groups: v6 };
  return null;
}

/**
 * Parse `address/prefix` with a canonical base address and a prefix within
 * the family's bound (0-32 or 0-128).
 * @param {string} str
 * @returns {{ip: object, prefix: number} | null}
 */
export function parseCidr(str) {
  const slash = str.indexOf("/");
  if (slash === -1) return null;
  const ip = parseCanonicalIp(str.slice(0, slash));
  if (ip === null) return null;
  const prefixText = str.slice(slash + 1);
  if (!/^[0-9]{1,3}$/.test(prefixText)) return null;
  const prefix = Number(prefixText);
  if (prefix > (ip.family === 4 ? 32 : 128)) return null;
  return { ip, prefix };
}

/**
 * True if `ip` lies inside the range `{ip: base, prefix}`. Families must
 * match; an IPv4-mapped IPv6 address is unwrapped by the caller, not here.
 */
export function ipInRange(ip, range) {
  if (ip.family !== range.ip.family) return false;
  const prefix = range.prefix;
  if (ip.family === 4) {
    if (prefix === 0) return true;
    return ((ip.addr ^ range.ip.addr) >>> (32 - prefix)) === 0;
  }
  const full = prefix >> 4;
  for (let i = 0; i < full; i++) {
    if (ip.groups[i] !== range.ip.groups[i]) return false;
  }
  const rem = prefix & 15;
  if (rem === 0) return true;
  const mask = (0xffff << (16 - rem)) & 0xffff;
  return (ip.groups[full] & mask) === (range.ip.groups[full] & mask);
}

/**
 * The IPv4 address carried by an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`),
 * or the address itself when it is already IPv4. Null for any other IPv6.
 * @returns {{family: 4, addr: number} | null}
 */
export function toIpv4Mapped(ip) {
  if (ip.family === 4) return ip;
  const g = ip.groups;
  if (g[0] === 0 && g[1] === 0 && g[2] === 0 && g[3] === 0 && g[4] === 0 && g[5] === 0xffff) {
    return { family: 4, addr: ((g[6] << 16) | g[7]) >>> 0 };
  }
  return null;
}

function compileTable(rows) {
  return rows.map(([cidr, reason]) => {
    const range = parseCidr(cidr);
    if (range === null) {
      throw new Error(`hostpolicy: malformed range '${cidr}' in policy table`);
    }
    return { cidr, range, reason };
  });
}

// Parsed once at module load; a malformed row is a startup error, never a
// silently skipped rule.
const ALWAYS_BLOCKED = compileTable(ALWAYS_BLOCKED_RANGES);
const BLOCK_INTERNAL = compileTable(BLOCK_INTERNAL_RANGES);

function firstMatch(table, ip) {
  // IPv4 rows are tested against the unwrapped address, IPv6 rows against the
  // address as given, so a v4-mapped literal is caught by the IPv4 rows.
  const v4 = toIpv4Mapped(ip);
  for (const row of table) {
    const candidate = row.range.ip.family === 4 ? v4 : ip.family === 6 ? ip : null;
    if (candidate !== null && ipInRange(candidate, row.range)) return row.reason;
  }
  return null;
}

/**
 * Reason `ip` must be blocked regardless of policy, or null.
 * @param {object} ip - Parsed address from parseCanonicalIp
 * @returns {string|null}
 */
export function alwaysBlockedIpReason(ip) {
  return firstMatch(ALWAYS_BLOCKED, ip);
}

/**
 * Reason `ip` is a non-public address that `block_internal` refuses, or null.
 * @param {object} ip - Parsed address from parseCanonicalIp
 * @returns {string|null}
 */
export function nonPublicIpReason(ip) {
  return firstMatch(BLOCK_INTERNAL, ip);
}

/**
 * Enforce the egress policy for a literal target address: link-local /
 * metadata is always blocked; the remaining non-public ranges are blocked
 * only when the argument sets `block_internal = true`.
 * @param {object} ip - Parsed address from parseCanonicalIp
 * @param {boolean} blockInternal
 * @throws {Error} with the policy reason
 */
export function enforceIpPolicy(ip, blockInternal) {
  const always = alwaysBlockedIpReason(ip);
  if (always !== null) {
    throw new Error(`target ${always}`);
  }
  if (blockInternal === true) {
    const reason = nonPublicIpReason(ip);
    if (reason !== null) {
      throw new Error(`target ${reason} (blocked by block_internal policy)`);
    }
  }
}

/**
 * True if `val` is an attempt at an IP literal in a non-canonical encoding:
 * a `0x…` hex form, or every dot-separated label is all ASCII digits
 * (integer / dotted-decimal / octal / shorthand). A resolver would expand
 * such a value to an address, so it must never pass as a "hostname".
 * Canonical literals are handled before this is consulted.
 * @param {string} val
 * @returns {boolean}
 */
export function looksLikeIpLiteral(val) {
  if (val.toLowerCase().startsWith("0x")) return true;
  return val.split(".").every((label) => label.length > 0 && /^[0-9]+$/.test(label));
}

/**
 * True if any DNS label in `host` is an A-label (`xn--…`), compared
 * case-insensitively per IDNA.
 * @param {string} host
 * @returns {boolean}
 */
export function hasPunycodeLabel(host) {
  return host
    .split(".")
    .some((label) => label.length >= 4 && label.slice(0, 4).toLowerCase() === "xn--");
}
