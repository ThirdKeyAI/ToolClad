import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { writeFileSync, mkdtempSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { loadManifest, loadManifestWithOptions, validateManifestWithCustomTypes } from "../src/manifest.js";
import {
  validateArg,
  validateArgMode,
  validateArgAsync,
  validateArgWithCustomTypes,
  validateArgWithCustomTypesAsync,
} from "../src/validator.js";
import {
  parseCidr,
  prefixesOverlap,
  toIpv4MappedPrefix,
  internalNameReason,
  embeddedIpv4Literal,
  INTERNAL_NAMES,
  INTERNAL_NAME_SUFFIXES,
} from "../src/hostpolicy.js";
import {
  buildCommandArgv,
  compileCommand,
  execute,
  executeHttp,
  isEgressManifest,
  lintNetworkEgress,
  EGRESS_BINARIES,
} from "../src/executor.js";

// Tests in this file never run a network tool and never open a connection.
// The only network activity is a DNS lookup of a `.invalid` name (reserved by
// RFC 2606, never resolves), used to assert the fail-closed path. Positive
// cases use literals; negative cases use the internal-name denylist and the
// embedded-literal shapes, none of which need a resolver.

function writeTmp(content) {
  const dir = mkdtempSync(join(tmpdir(), "toolclad-w4-"));
  const path = join(dir, "test.clad.toml");
  writeFileSync(path, content);
  return path;
}

function oneshot(tool, args, command) {
  return {
    tool: { name: "t", description: "d", ...tool },
    args,
    command,
    output: { format: "text" },
  };
}

const INTERNAL = /^Error: target resolves to an internal name — always blocked$/;
const BLOCKED_BY_POLICY = /\(blocked by block_internal policy\)$/;
const LOOPBACK = /^Error: target resolves to a loopback address \(blocked by block_internal policy\)$/;
const PRIVATE = /^Error: target resolves to a private address \(blocked by block_internal policy\)$/;
const ALWAYS_V4 =
  /^Error: target is a link-local \/ cloud-metadata address \(169\.254\.0\.0\/16\) — always blocked$/;
const ALWAYS_V6 = /^Error: target is an IPv6 link-local address \(fe80::\/10\) — always blocked$/;
const SYNC_UNRESOLVED =
  /^Error: hostname cannot be verified without DNS resolution; pass an IP literal or use validateArgAsync$/;
const couldNotResolve = (host) =>
  new RegExp(`^Error: could not resolve host '${host.replace(/\./g, "\\.")}' to verify it is public \\(block_internal\\)$`);
const LINT_TARGET =
  /^Error: argument 'target' is a network target for an egress binary but block_internal is not set; set block_internal = true to default-deny internal\/SSRF targets$/;

// --- D1 internal-name denylist ---------------------------------------------

describe("W4 D1 - internal-name denylist is unconditional", () => {
  const names = [
    "localhost",
    "api.localhost",
    "printer.local",
    "metadata.google.internal",
    "db.internal",
    "x.home.arpa",
    "nas.lan",
    "wiki.intranet",
    "fs.corp",
    "vault.private",
  ];

  it("refuses each name as a scope_target without block_internal", async () => {
    for (const v of names) {
      assert.throws(() => validateArg({ type: "scope_target" }, v), INTERNAL, v);
      assert.throws(() => validateArg({ type: "scope_target", block_internal: false }, v), INTERNAL, v);
      assert.throws(() => validateArg({ type: "scope_target", block_internal: true }, v), INTERNAL, v);
    }
  });

  it("refuses each name as a url host without block_internal", async () => {
    for (const v of names) {
      assert.throws(() => validateArg({ type: "url" }, `http://${v}/`), INTERNAL, v);
      assert.throws(() => validateArg({ type: "url" }, `https://${v}:8443/path?q=1`), INTERNAL, v);
    }
  });

  it("compares case-insensitively and ignores one trailing dot", async () => {
    const reason = "resolves to an internal name — always blocked";
    assert.equal(internalNameReason("LOCALHOST"), reason);
    assert.equal(internalNameReason("Api.LocalHost."), reason);
    assert.equal(internalNameReason("Metadata.Google.Internal"), reason);
    assert.equal(internalNameReason("HOST.Home.ARPA"), reason);
    assert.throws(() => validateArg({ type: "scope_target" }, "LocalHost"), INTERNAL);
    assert.throws(() => validateArg({ type: "url" }, "http://Printer.LOCAL/"), INTERNAL);
  });

  it("matches whole labels only", async () => {
    assert.equal(internalNameReason("example.com"), null);
    assert.equal(internalNameReason("localhost.example.com"), null);
    assert.equal(internalNameReason("mylocal.example"), null);
    assert.equal(internalNameReason("corp.example.com"), null);
    assert.equal(internalNameReason("notlocalhost"), null);
    assert.equal(validateArg({ type: "scope_target" }, "localhost.example.com"), "localhost.example.com");
    assert.equal(validateArg({ type: "url" }, "https://corp.example.com/"), "https://corp.example.com/");
  });

  it("the tables match the normative list", async () => {
    assert.deepEqual([...INTERNAL_NAMES], ["localhost", "metadata.google.internal"]);
    assert.deepEqual(
      [...INTERNAL_NAME_SUFFIXES],
      [".localhost", ".local", ".internal", ".home.arpa", ".lan", ".intranet", ".corp", ".private"]
    );
  });
});

// --- D2 embedded IP literal -------------------------------------------------

describe("W4 D2 - IP literal embedded in a hostname", () => {
  it("169.254.169.254.nip.io is refused without block_internal", async () => {
    assert.throws(() => validateArg({ type: "scope_target" }, "169.254.169.254.nip.io"), ALWAYS_V4);
    assert.throws(() => validateArg({ type: "scope_target" }, "169-254-169-254.nip.io"), ALWAYS_V4);
    assert.throws(
      () => validateArg({ type: "url" }, "http://169.254.169.254.xip.io/latest/meta-data/"),
      ALWAYS_V4
    );
    assert.throws(() => validateArg({ type: "url" }, "http://169-254-169-254.sslip.io:80/"), ALWAYS_V4);
  });

  it("127.0.0.1.nip.io and 10-0-0-1.nip.io are refused with block_internal", async () => {
    const def = { type: "scope_target", block_internal: true };
    assert.throws(() => validateArg(def, "127.0.0.1.nip.io"), LOOPBACK);
    assert.throws(() => validateArg(def, "10-0-0-1.nip.io"), PRIVATE);
    assert.throws(() => validateArg(def, "192-168-1-1.sslip.io"), PRIVATE);
    assert.throws(() => validateArg({ type: "url", block_internal: true }, "http://127.0.0.1.nip.io:8080/"), LOOPBACK);
    assert.throws(() => validateArg({ type: "url", block_internal: true }, "https://10-0-0-1.nip.io/"), PRIVATE);
  });

  it("the embedded policy is opt-in like the literal policy", async () => {
    // 127/8 and 10/8 are block_internal rows: without the flag the name is an
    // ordinary hostname and no resolution is attempted.
    assert.equal(validateArg({ type: "scope_target" }, "127.0.0.1.nip.io"), "127.0.0.1.nip.io");
    assert.equal(validateArg({ type: "scope_target" }, "10-0-0-1.nip.io"), "10-0-0-1.nip.io");
  });

  it("a public embedded address is not refused for its shape", async () => {
    assert.equal(validateArg({ type: "scope_target" }, "93-184-216-34.example.com"), "93-184-216-34.example.com");
    assert.equal(validateArg({ type: "scope_target" }, "93.184.216.34.example.com"), "93.184.216.34.example.com");
    assert.equal(validateArg({ type: "url" }, "https://93-184-216-34.example.com/"), "https://93-184-216-34.example.com/");
    // With block_internal the shape passes the policy and the name reaches
    // the resolution step; the sync path refuses for that reason and no
    // other, which is the observable proof that the shape alone did not.
    assert.throws(
      () => validateArg({ type: "scope_target", block_internal: true }, "93-184-216-34.example.com"),
      SYNC_UNRESOLVED
    );
  });

  it("embeddedIpv4Literal recognizes exactly the two shapes", async () => {
    assert.deepEqual(embeddedIpv4Literal("127.0.0.1.nip.io"), { family: 4, addr: 0x7f000001 });
    assert.deepEqual(embeddedIpv4Literal("10-0-0-1.nip.io"), { family: 4, addr: 0x0a000001 });
    assert.deepEqual(embeddedIpv4Literal("10-0-0-1"), { family: 4, addr: 0x0a000001 });
    // Dashed groups are decimal 0-255; a leading zero does not change the value.
    assert.deepEqual(embeddedIpv4Literal("010-0-0-1.nip.io"), { family: 4, addr: 0x0a000001 });
    assert.equal(embeddedIpv4Literal("10-0-0-256.nip.io"), null);
    assert.equal(embeddedIpv4Literal("10-0-0.nip.io"), null);
    assert.equal(embeddedIpv4Literal("10-0-0-1-2.nip.io"), null);
    // Only the first four labels / the first label count.
    assert.equal(embeddedIpv4Literal("x.127.0.0.1.nip.io"), null);
    assert.equal(embeddedIpv4Literal("x.10-0-0-1.nip.io"), null);
    // The dotted form must be canonical, as for a bare literal.
    assert.equal(embeddedIpv4Literal("0177.0.0.1.nip.io"), null);
    assert.equal(embeddedIpv4Literal("127.0.0.256.nip.io"), null);
    assert.equal(embeddedIpv4Literal("example.com"), null);
  });
});

// --- D3 CIDR overlap ----------------------------------------------------------

describe("W4 D3 - CIDR overlap, not base address", () => {
  it("8.0.0.0/5 is refused with block_internal: its base is public but it contains 10.0.0.0/8", async () => {
    assert.throws(() => validateArg({ type: "scope_target", block_internal: true }, "8.0.0.0/5"), PRIVATE);
    assert.throws(() => validateArg({ type: "cidr", block_internal: true }, "8.0.0.0/5"), PRIVATE);
    // Opt-in: 8.0.0.0/5 contains no always-blocked range.
    assert.equal(validateArg({ type: "scope_target" }, "8.0.0.0/5"), "8.0.0.0/5");
    assert.equal(validateArg({ type: "cidr" }, "8.0.0.0/5"), "8.0.0.0/5");
  });

  it("10.0.0.0/24 is refused and 93.184.216.0/24 is accepted", async () => {
    for (const type of ["scope_target", "cidr"]) {
      const def = { type, block_internal: true };
      assert.throws(() => validateArg(def, "10.0.0.0/24"), PRIVATE, type);
      assert.throws(() => validateArg(def, "127.1.0.0/16"), LOOPBACK, type);
      assert.throws(() => validateArg(def, "0.0.0.0/0"), ALWAYS_V4, type);
      assert.equal(validateArg(def, "93.184.216.0/24"), "93.184.216.0/24", type);
      assert.equal(validateArg(def, "8.8.8.0/24"), "8.8.8.0/24", type);
    }
  });

  it("IPv6: 2001:db8::/32 is refused and 2606:4700::/32 is accepted", async () => {
    for (const type of ["scope_target", "cidr"]) {
      const def = { type, block_internal: true };
      assert.throws(() => validateArg(def, "2001:db8::/32"), BLOCKED_BY_POLICY, type);
      // A supernet and a subnet of the documentation range both overlap it.
      assert.throws(() => validateArg(def, "2001::/16"), BLOCKED_BY_POLICY, type);
      assert.throws(() => validateArg(def, "2001:db8:1::/48"), BLOCKED_BY_POLICY, type);
      assert.throws(() => validateArg(def, "fc00::/8"), BLOCKED_BY_POLICY, type);
      // ::/0 contains the IPv4-mapped block, so the first table row (IPv4
      // link-local) reports it, exactly as for a ::ffff: literal.
      assert.throws(() => validateArg(def, "::/0"), ALWAYS_V4, type);
      assert.equal(validateArg(def, "2606:4700::/32"), "2606:4700::/32", type);
      assert.equal(validateArg(def, "2001:4860::/32"), "2001:4860::/32", type);
    }
  });

  it("a range containing link-local is always blocked, with or without block_internal", async () => {
    for (const blockInternal of [false, true]) {
      for (const type of ["scope_target", "cidr"]) {
        const def = { type, block_internal: blockInternal };
        assert.throws(() => validateArg(def, "169.254.0.0/16"), ALWAYS_V4);
        assert.throws(() => validateArg(def, "169.254.169.0/24"), ALWAYS_V4);
        assert.throws(() => validateArg(def, "160.0.0.0/3"), ALWAYS_V4);
        assert.throws(() => validateArg(def, "0.0.0.0/0"), ALWAYS_V4);
        assert.throws(() => validateArg(def, "fe80::/64"), ALWAYS_V6);
        assert.throws(() => validateArg(def, "fe00::/8"), ALWAYS_V6);
        assert.throws(() => validateArg(def, "::/0"), ALWAYS_V4);
        assert.throws(() => validateArg(def, "8000::/1"), ALWAYS_V6);
      }
    }
  });

  it("IPv4-mapped IPv6 ranges are projected onto the IPv4 rows", async () => {
    const def = { type: "cidr", block_internal: true };
    assert.throws(() => validateArg(def, "::ffff:127.0.0.0/104"), LOOPBACK);
    assert.throws(() => validateArg(def, "::ffff:10.0.0.0/104"), PRIVATE);
    assert.throws(() => validateArg({ type: "cidr" }, "::ffff:169.254.0.0/112"), ALWAYS_V4);
    assert.throws(() => validateArg({ type: "cidr" }, "::ffff:0:0/96"), ALWAYS_V4);
    assert.equal(validateArg(def, "::ffff:93.184.216.0/120"), "::ffff:93.184.216.0/120");
    assert.deepEqual(toIpv4MappedPrefix(parseCidr("::ffff:127.0.0.0/104")), {
      ip: { family: 4, addr: 0x7f000000 },
      prefix: 8,
    });
    assert.deepEqual(toIpv4MappedPrefix(parseCidr("::ffff:0:0/95")), {
      ip: { family: 4, addr: 0 },
      prefix: 0,
    });
    assert.equal(toIpv4MappedPrefix(parseCidr("2001:db8::/32")), null);
    assert.equal(toIpv4MappedPrefix(parseCidr("::fffe:0:0/96")), null);
  });

  it("prefixesOverlap: boundaries on the 32-bit and eight-group representations", async () => {
    const o = (a, b) => prefixesOverlap(parseCidr(a), parseCidr(b));
    assert.equal(o("8.0.0.0/5", "10.0.0.0/8"), true);
    assert.equal(o("10.0.0.0/8", "8.0.0.0/5"), true);
    assert.equal(o("10.0.0.0/8", "10.0.0.0/8"), true);
    assert.equal(o("10.0.0.0/8", "11.0.0.0/8"), false);
    assert.equal(o("10.255.255.255/32", "10.0.0.0/8"), true);
    assert.equal(o("11.0.0.0/32", "10.0.0.0/8"), false);
    assert.equal(o("9.255.255.255/32", "10.0.0.0/8"), false);
    assert.equal(o("0.0.0.0/0", "255.255.255.255/32"), true);
    assert.equal(o("255.255.255.255/32", "0.0.0.0/0"), true);
    assert.equal(o("128.0.0.0/1", "127.0.0.0/8"), false);
    assert.equal(o("172.16.0.0/12", "172.32.0.0/12"), false);
    assert.equal(o("172.31.255.0/24", "172.16.0.0/12"), true);
    // Families never overlap.
    assert.equal(o("127.0.0.0/8", "::1/128"), false);
    assert.equal(o("::/0", "0.0.0.0/0"), false);
    // IPv6: whole groups and the masked boundary group.
    assert.equal(o("2001:db8::/32", "2001:db8:ffff::/48"), true);
    assert.equal(o("2001:db8::/32", "2001:db9::/32"), false);
    assert.equal(o("2001::/16", "2001:db8::/32"), true);
    assert.equal(o("::/0", "fe80::/10"), true);
    assert.equal(o("fe80::/10", "fec0::/10"), false);
    assert.equal(o("febf::/16", "fe80::/10"), true);
    assert.equal(o("fec0::/16", "fe80::/10"), false);
    assert.equal(o("fc00::/7", "fdff:ffff:ffff:ffff::/64"), true);
    assert.equal(o("fc00::/7", "fe00::/8"), false);
    assert.equal(o("::1/128", "::1/128"), true);
    assert.equal(o("::1/128", "::2/127"), false);
    assert.equal(o("::/127", "::1/128"), true);
  });
});

// --- D4 DNS resolution ----------------------------------------------------------

describe("W4 D4 - DNS resolution under block_internal (fail closed)", () => {
  it("sync: a hostname under block_internal is refused without a lookup", async () => {
    assert.throws(() => validateArg({ type: "scope_target", block_internal: true }, "example.com"), SYNC_UNRESOLVED);
    assert.throws(() => validateArgMode({ type: "scope_target", block_internal: true }, "example.com", true), SYNC_UNRESOLVED);
    assert.throws(() => validateArg({ type: "url", block_internal: true }, "https://example.com/"), SYNC_UNRESOLVED);
    assert.throws(
      () => validateArgWithCustomTypes({ type: "host", block_internal: true }, "example.com", { host: { base: "scope_target" } }),
      SYNC_UNRESOLVED
    );
    assert.throws(
      () => validateArgWithCustomTypes({ type: "web", block_internal: true }, "https://example.com/", { web: { base: "url" } }),
      SYNC_UNRESOLVED
    );
  });

  it("sync: the same name is accepted when block_internal is false (no resolution is attempted)", async () => {
    assert.equal(validateArg({ type: "scope_target" }, "no-such-host.invalid"), "no-such-host.invalid");
    assert.equal(validateArg({ type: "scope_target", block_internal: false }, "no-such-host.invalid"), "no-such-host.invalid");
    assert.equal(validateArg({ type: "url" }, "https://no-such-host.invalid/"), "https://no-such-host.invalid/");
  });

  it("async: a name that cannot resolve is refused with the could-not-resolve message", async () => {
    await assert.rejects(
      validateArgAsync({ type: "scope_target", block_internal: true }, "no-such-host.invalid"),
      couldNotResolve("no-such-host.invalid")
    );
    await assert.rejects(
      validateArgAsync({ type: "url", block_internal: true }, "https://no-such-host.invalid:8443/x?y=1"),
      couldNotResolve("no-such-host.invalid")
    );
    await assert.rejects(
      validateArgWithCustomTypesAsync(
        { type: "web", block_internal: true },
        "https://no-such-host.invalid/",
        { web: { base: "url" } }
      ),
      couldNotResolve("no-such-host.invalid")
    );
    await assert.rejects(
      validateArgAsync({ type: "scope_target", block_internal: true }, "no-such-host.invalid", true),
      couldNotResolve("no-such-host.invalid")
    );
  });

  it("async: the same name is accepted when block_internal is false", async () => {
    assert.equal(await validateArgAsync({ type: "scope_target" }, "no-such-host.invalid"), "no-such-host.invalid");
    assert.equal(await validateArgAsync({ type: "url" }, "https://no-such-host.invalid/"), "https://no-such-host.invalid/");
  });

  it("async: literals, ranges, the denylist and embedded literals take the shared path", async () => {
    const def = { type: "scope_target", block_internal: true };
    assert.equal(await validateArgAsync(def, "93.184.216.34"), "93.184.216.34");
    assert.equal(await validateArgAsync(def, "2606:4700::1"), "2606:4700::1");
    assert.equal(await validateArgAsync(def, "93.184.216.0/24"), "93.184.216.0/24");
    assert.equal(await validateArgAsync({ type: "url", block_internal: true }, "https://93.184.216.34/x"), "https://93.184.216.34/x");
    assert.equal(await validateArgAsync({ type: "ip_address", block_internal: true }, "93.184.216.34"), "93.184.216.34");
    assert.equal(await validateArgAsync({ type: "cidr", block_internal: true }, "2606:4700::/32"), "2606:4700::/32");
    await assert.rejects(validateArgAsync(def, "127.0.0.1"), LOOPBACK);
    await assert.rejects(validateArgAsync(def, "8.0.0.0/5"), PRIVATE);
    await assert.rejects(validateArgAsync(def, "localhost"), INTERNAL);
    await assert.rejects(validateArgAsync(def, "127.0.0.1.nip.io"), LOOPBACK);
    await assert.rejects(validateArgAsync({ type: "scope_target" }, "169.254.169.254.nip.io"), ALWAYS_V4);
    await assert.rejects(validateArgAsync({ type: "url", block_internal: true }, "http://10-0-0-1.nip.io/"), PRIVATE);
  });

  it("async: hygiene, structure and the other types are the same implementation", async () => {
    const def = { type: "scope_target", block_internal: true };
    await assert.rejects(validateArgAsync(def, "a b"), /must not contain whitespace/);
    await assert.rejects(validateArgAsync(def, "xn--example-9c.com"), /punycode/);
    await assert.rejects(validateArgAsync(def, "0x7f000001"), /non-canonical IP literal/);
    await assert.rejects(validateArgAsync({ type: "url", block_internal: true }, "ftp://93.184.216.34/"), /not in allowed schemes/);
    await assert.rejects(validateArgAsync({ type: "integer", min: 1 }, "0"), /below minimum/);
    await assert.rejects(validateArgAsync({ type: "nope" }, "x"), /Unknown argument type: nope/);
    assert.equal(await validateArgAsync({ type: "integer" }, "7"), 7);
    assert.equal(await validateArgAsync({ type: "boolean" }, "true"), true);
    assert.equal(await validateArgAsync({ type: "string", allow_whitespace: true }, "a b", true), "a b");
    await assert.rejects(validateArgAsync({ type: "string", allow_whitespace: true }, "a b", false), /must not contain whitespace/);
    assert.equal(
      await validateArgWithCustomTypesAsync({ type: "level" }, "high", { level: { base: "enum", allowed: ["low", "high"] } }),
      "high"
    );
  });

  it("the build path is synchronous: a hostname under block_internal is refused, a literal builds", async () => {
    const m = oneshot(
      { binary: "echo" },
      { target: { type: "scope_target", required: true, block_internal: true } },
      { exec: ["echo", "{target}"] }
    );
    assert.throws(() => buildCommandArgv(m, { target: "example.com" }), SYNC_UNRESOLVED);
    assert.throws(() => buildCommandArgv(m, { target: "localhost" }), INTERNAL);
    assert.deepEqual(buildCommandArgv(m, { target: "93.184.216.34" }).argv, ["echo", "93.184.216.34"]);
    assert.deepEqual(buildCommandArgv(m, { target: "93.184.216.0/24" }).argv, ["echo", "93.184.216.0/24"]);
  });
});

// --- D5 egress lint ---------------------------------------------------------

describe("W4 D5 - egress lint as a manifest property (TC-15)", () => {
  it("the egress binary list is exactly the Rust list", async () => {
    assert.deepEqual(
      [...EGRESS_BINARIES],
      ["curl", "wget", "nmap", "nc", "ncat", "netcat", "masscan", "telnet", "ssh", "ping", "fping", "httpie", "http", "wfuzz", "ffuf", "hydra", "nikto"]
    );
  });

  it("a curl manifest without block_internal is refused at load; with the flag it loads", async () => {
    const curl = (flag) => `[tool]
name = "fetch"
binary = "curl"
description = "d"

[args.target]
position = 1
required = true
type = "url"
description = "u"
${flag}
[command]
exec = ["curl", "{target}"]

[output]
format = "text"
`;
    assert.throws(() => loadManifest(writeTmp(curl(""))), LINT_TARGET);
    assert.throws(() => loadManifest(writeTmp(curl("block_internal = false\n"))), LINT_TARGET);
    const m = loadManifest(writeTmp(curl("block_internal = true\n")));
    assert.equal(m.args.target.block_internal, true);
    assert.equal(isEgressManifest(m), true);
  });

  it("an nmap manifest without block_internal is refused at load; with the flag it loads", async () => {
    const nmap = (flag) => `[tool]
name = "scan"
binary = "nmap"
description = "d"

[args.target]
position = 1
required = true
type = "scope_target"
description = "t"
${flag}
[command]
exec = ["nmap", "-sn", "{target}"]

[output]
format = "text"
`;
    assert.throws(() => loadManifest(writeTmp(nmap(""))), LINT_TARGET);
    const m = loadManifest(writeTmp(nmap("block_internal = true\n")));
    assert.equal(m.args.target.block_internal, true);
  });

  it("every network target type is covered; other types are not linted", async () => {
    for (const type of ["scope_target", "url", "ip_address", "cidr"]) {
      const m = oneshot({ binary: "wget" }, { target: { type, required: true } }, { exec: ["wget", "{target}"] });
      assert.throws(() => compileCommand(m), LINT_TARGET, type);
      const ok = oneshot({ binary: "wget" }, { target: { type, required: true, block_internal: true } }, { exec: ["wget", "{target}"] });
      compileCommand(ok);
    }
    const m = oneshot(
      { binary: "wget" },
      { count: { type: "integer" }, name: { type: "string" }, mode: { type: "enum", allowed: ["a"] } },
      { exec: ["wget", "{name}"] }
    );
    compileCommand(m);
    assert.equal(isEgressManifest(m), true);
  });

  it("network_egress = true makes a manifest egress even when the binary is not listed", async () => {
    const m = oneshot(
      { binary: "mytool", network_egress: true },
      { target: { type: "scope_target" } },
      { exec: ["mytool", "{target}"] }
    );
    assert.throws(() => compileCommand(m), LINT_TARGET);
    const path = writeTmp(`[tool]
name = "x"
binary = "mytool"
network_egress = true
description = "d"

[args.target]
type = "ip_address"
description = "t"

[command]
exec = ["mytool", "{target}"]

[output]
format = "text"
`);
    assert.throws(() => loadManifest(path), LINT_TARGET);
    const unflagged = oneshot({ binary: "mytool" }, { target: { type: "scope_target" } }, { exec: ["mytool", "{target}"] });
    compileCommand(unflagged);
    assert.equal(isEgressManifest(unflagged), false);
  });

  it("an [http] manifest with a url argument requires the flag, at load and in memory", async () => {
    const path = writeTmp(`[tool]
name = "api"
description = "d"

[args.target]
type = "url"
description = "u"

[http]
method = "GET"
url = "https://api.example.com/fetch?u={target}"

[output]
format = "json"
`);
    assert.throws(() => loadManifest(path), LINT_TARGET);

    const m = {
      tool: { name: "api", description: "d" },
      args: { target: { type: "url", required: true } },
      http: { method: "GET", url: "https://api.example.com/fetch?u={target}" },
    };
    assert.equal(isEgressManifest(m), true);
    await assert.rejects(executeHttp(m, { target: "https://93.184.216.34/" }, { dryRun: true }), LINT_TARGET);
    await assert.rejects(() => execute(m, { target: "https://93.184.216.34/" }, { dryRun: true }), LINT_TARGET);

    m.args.target.block_internal = true;
    const r = await executeHttp(m, { target: "https://93.184.216.34/" }, { dryRun: true });
    assert.equal(r.status, "dry_run");
    assert.equal(
      r.http_url,
      `https://api.example.com/fetch?u=${encodeURIComponent("https://93.184.216.34/")}`
    );
    assert.equal((await execute(m, { target: "https://93.184.216.34/" }, { dryRun: true })).status, "dry_run");
  });

  it("a [browser] manifest is an egress manifest", async () => {
    const path = writeTmp(`[tool]
name = "b"
description = "d"

[args.target]
type = "url"
description = "u"

[browser]
engine = "cdp"

[output]
format = "json"
`);
    assert.throws(() => loadManifest(path), LINT_TARGET);
    assert.equal(isEgressManifest({ tool: { name: "b" }, browser: { engine: "cdp" } }), true);
  });

  it("a non-egress binary (whois) does not require the flag", async () => {
    const m = oneshot({ binary: "whois" }, { target: { type: "scope_target", required: true } }, { exec: ["whois", "{target}"] });
    compileCommand(m);
    assert.equal(isEgressManifest(m), false);
    assert.deepEqual(buildCommandArgv(m, { target: "example.com" }).argv, ["whois", "example.com"]);
    const path = writeTmp(`[tool]
name = "whois_lookup"
binary = "whois"
description = "d"

[args.target]
position = 1
required = true
type = "scope_target"
description = "t"

[command]
exec = ["whois", "{target}"]

[output]
format = "text"
`);
    assert.equal(loadManifest(path).args.target.block_internal, false);
  });

  it("the binary is matched by lowercased basename in tool.binary, exec[0] and the template", async () => {
    assert.equal(isEgressManifest(oneshot({ binary: "/usr/bin/Curl" }, {}, { exec: ["x"] })), true);
    assert.equal(isEgressManifest(oneshot({ binary: "C:\\tools\\NMAP" }, {}, { exec: ["x"] })), true);
    assert.equal(isEgressManifest(oneshot({ binary: "wrapper" }, {}, { exec: ["/opt/bin/nc", "-z"] })), true);
    assert.equal(isEgressManifest(oneshot({ binary: "wrapper" }, {}, { template: "  ping -c 1 {target}" })), true);
    assert.equal(isEgressManifest(oneshot({ binary: "wrapper" }, {}, { template: "/usr/sbin/fping {target}" })), true);
    assert.equal(isEgressManifest(oneshot({ binary: "whois" }, {}, { exec: ["whois"] })), false);
    assert.equal(isEgressManifest(oneshot({ binary: "curling" }, {}, { exec: ["curling"] })), false);
    assert.equal(isEgressManifest(oneshot({ binary: "nmap.exe" }, {}, { exec: ["nmap.exe"] })), false);
  });

  it("an executor-only manifest is an egress manifest only when the author declares it", async () => {
    const silent = oneshot({}, { target: { type: "scope_target", required: true } }, { executor: "scripts/run.sh" });
    compileCommand(silent);
    assert.equal(isEgressManifest(silent), false);
    const declared = oneshot(
      { network_egress: true },
      { target: { type: "scope_target", required: true } },
      { executor: "scripts/run.sh" }
    );
    assert.throws(() => compileCommand(declared), LINT_TARGET);
  });

  it("the lint runs before any argument value is examined", async () => {
    const m = oneshot({ binary: "curl" }, { target: { type: "url", required: true } }, { exec: ["curl", "{target}"] });
    assert.throws(() => buildCommandArgv(m, {}), LINT_TARGET);
    assert.throws(() => buildCommandArgv(m, { target: "not a url" }), LINT_TARGET);
  });

  it("names the first offending argument in declaration order", async () => {
    const m = oneshot(
      { binary: "curl" },
      {
        first: { type: "url", block_internal: true },
        second: { type: "cidr" },
        third: { type: "ip_address" },
      },
      { exec: ["curl", "{first}"] }
    );
    assert.throws(
      () => compileCommand(m),
      /^Error: argument 'second' is a network target for an egress binary but block_internal is not set; set block_internal = true to default-deny internal\/SSRF targets$/
    );
  });

  it("a custom type with a network-target base is refused once the custom types are known", async () => {
    const types = {
      host: { base: "scope_target" },
      web: { base: "url" },
      level: { base: "enum", allowed: ["a"] },
    };
    const m = oneshot(
      { binary: "curl" },
      { target: { type: "web", block_internal: true }, mode: { type: "level" } },
      { exec: ["curl", "{target}", "{mode}"] }
    );
    // Without the type map the lint cannot see the base: the load succeeds.
    compileCommand(m);
    lintNetworkEgress(m);
    assert.throws(
      () => validateManifestWithCustomTypes(m, types),
      /^Error: argument 'target' uses custom type 'web' as a network target; custom types cannot carry block_internal — use the built-in url type$/
    );
    const m2 = oneshot({ binary: "nmap" }, { target: { type: "host" } }, { exec: ["nmap", "{target}"] });
    assert.throws(
      () => lintNetworkEgress(m2, types),
      /^Error: argument 'target' uses custom type 'host' as a network target; custom types cannot carry block_internal — use the built-in scope_target type$/
    );
    // A non-egress manifest may use the same custom type.
    const m3 = oneshot({ binary: "whois" }, { target: { type: "host" } }, { exec: ["whois", "{target}"] });
    assert.equal(validateManifestWithCustomTypes(m3, types), m3);
    // A custom type with a non-network base is fine in an egress manifest.
    const m4 = oneshot(
      { binary: "curl" },
      { mode: { type: "level" }, target: { type: "url", block_internal: true } },
      { exec: ["curl", "{target}"] }
    );
    assert.equal(validateManifestWithCustomTypes(m4, types), m4);
    // A loaded manifest can be checked the same way.
    const path = writeTmp(`[tool]
name = "fetch"
binary = "wget"
description = "d"

[args.target]
type = "web"
description = "u"
block_internal = true

[command]
exec = ["wget", "{target}"]

[output]
format = "text"
`);
    // A loaded manifest gets the same check at load, given the type map.
    assert.throws(() => loadManifestWithOptions(path, { customTypes: types }), /uses custom type 'web' as a network target/);
    // Without it, the unknown type itself is refused at load.
    assert.throws(() => loadManifest(path), /unknown type 'web' for argument 'target'/);
  });
});
