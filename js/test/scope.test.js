import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { writeFileSync, mkdtempSync, mkdirSync, existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { loadManifest, validateManifestWithCustomTypes } from "../src/manifest.js";
import { validateArg, validateArgIn, validateArgInAsync } from "../src/validator.js";
import { execute, executeMcp } from "../src/executor.js";
import {
  makeScope,
  loadScopeFile,
  discoverScope,
  ipInCidr,
  hostMatchesRule,
  checkScope,
  urlHostInScope,
  NO_SCOPE_FILE_MESSAGE,
} from "../src/scope.js";

// No network tool is run and no DNS lookup is made: commands are echo dry
// runs, and every argument here either omits block_internal or uses a literal.

const CLI = fileURLToPath(new URL("../src/cli.js", import.meta.url));
const VECTORS = fileURLToPath(new URL("../../tests/scope_vectors.json", import.meta.url));

const SCOPE_TOML = `
[scope]
allowed_domains = ["example.com", "*.example.com"]
allowed_cidrs = ["10.0.1.0/24", "2001:db8::/32"]
blocked_domains = ["bad.example.com"]
blocked_cidrs = ["10.0.1.128/25"]
`;

const SCOPE = makeScope({
  allowed_domains: ["example.com", "*.example.com"],
  allowed_cidrs: ["10.0.1.0/24", "2001:db8::/32"],
  blocked_domains: ["bad.example.com"],
  blocked_cidrs: ["10.0.1.128/25"],
});

function tmpDir() {
  return mkdtempSync(join(tmpdir(), "toolclad-scope-"));
}

function withEnv(value, fn) {
  const saved = process.env.TOOLCLAD_SCOPE_FILE;
  if (value === undefined) delete process.env.TOOLCLAD_SCOPE_FILE;
  else process.env.TOOLCLAD_SCOPE_FILE = value;
  try {
    return fn();
  } finally {
    if (saved === undefined) delete process.env.TOOLCLAD_SCOPE_FILE;
    else process.env.TOOLCLAD_SCOPE_FILE = saved;
  }
}

function manifestToml(type = "scope_target", extra = "") {
  return `
[tool]
name = "t"
binary = "echo"
description = "d"

[args.target]
position = 1
required = true
type = "${type}"
description = "t"
scope_check = true
${extra}

[command]
exec = ["echo", "{target}"]

[output]
format = "text"
`;
}

describe("scope_vectors.json (normative)", () => {
  const present = existsSync(VECTORS);
  const vectors = present ? JSON.parse(readFileSync(VECTORS, "utf-8")).vectors : {};
  const skip = present ? false : `vector file not found at ${VECTORS}`;

  it("ipv4_in_cidr", { skip }, () => {
    for (const v of vectors.ipv4_in_cidr) {
      assert.equal(ipInCidr(v.ip, v.cidr), v.expected, `${v.ip} in ${v.cidr}`);
    }
  });

  it("ipv6_in_cidr", { skip }, () => {
    for (const v of vectors.ipv6_in_cidr) {
      assert.equal(ipInCidr(v.ip, v.cidr), v.expected, `${v.ip} in ${v.cidr}`);
    }
  });

  it("hostname_wildcard_match", { skip }, () => {
    for (const v of vectors.hostname_wildcard_match) {
      assert.equal(hostMatchesRule(v.hostname, v.pattern), v.expected, `${v.hostname} ~ ${v.pattern}`);
    }
  });

  it("scope_target_validation", { skip }, () => {
    for (const v of vectors.scope_target_validation) {
      let ok = true;
      try {
        validateArg({ type: "scope_target" }, v.value);
      } catch {
        ok = false;
      }
      assert.equal(ok, v.valid, JSON.stringify(v.value));
    }
  });

  it("url_scope_check", { skip }, () => {
    for (const v of vectors.url_scope_check) {
      const scope = makeScope({ allowed_domains: v.allowed_hosts });
      let ok = true;
      try {
        validateArgIn({ type: "url", scope_check: true }, v.url, { scope });
      } catch {
        ok = false;
      }
      assert.equal(ok, v.expected, v.url);
      assert.equal(urlHostInScope(v.url, v.allowed_hosts), v.expected, v.url);
    }
  });
});

describe("scope matching", () => {
  const check = (type, value) => validateArgIn({ type, scope_check: true }, value, { scope: SCOPE });

  it("matches exact and wildcard domain rules", () => {
    assert.equal(check("scope_target", "example.com"), "example.com");
    assert.equal(check("scope_target", "EXAMPLE.com"), "EXAMPLE.com");
    assert.equal(check("scope_target", "deep.sub.example.com"), "deep.sub.example.com");
  });

  it("wildcard does not match the apex", () => {
    const scope = makeScope({ allowed_domains: ["*.example.com"] });
    assert.throws(
      () => validateArgIn({ type: "scope_target", scope_check: true }, "example.com", { scope }),
      /target 'example\.com' is not in scope/
    );
  });

  it("matches on a label boundary only", () => {
    assert.throws(() => check("scope_target", "evil-example.com"), /is not in scope/);
    assert.throws(() => check("url", "https://example.com.evil.com/"), /target 'example\.com\.evil\.com' is not in scope/);
  });

  it("blocked rules beat allowed rules", () => {
    assert.throws(() => check("scope_target", "bad.example.com"), /is not in scope/);
    // An exact blocked rule does not reach its subdomains.
    assert.equal(check("scope_target", "x.bad.example.com"), "x.bad.example.com");
    assert.equal(check("ip_address", "10.0.1.5"), "10.0.1.5");
    assert.throws(() => check("ip_address", "10.0.1.200"), /target '10\.0\.1\.200' is not in scope/);
  });

  it("a CIDR must be fully contained in an allowed range", () => {
    assert.equal(check("cidr", "10.0.1.0/26"), "10.0.1.0/26");
    assert.throws(() => check("cidr", "10.0.0.0/8"), /is not in scope/);
    // Overlaps the blocked upper half.
    assert.throws(() => check("cidr", "10.0.1.0/24"), /is not in scope/);
    const plain = makeScope({ allowed_cidrs: ["10.0.1.0/24"] });
    assert.equal(
      validateArgIn({ type: "scope_target", scope_check: true }, "10.0.1.0/25", { scope: plain }),
      "10.0.1.0/25"
    );
    assert.equal(checkScope("2001:db8:1::/48", SCOPE), undefined);
  });

  it("checks the host of a url, and IP literals", () => {
    assert.equal(check("url", "https://app.example.com:8443/x"), "https://app.example.com:8443/x");
    assert.equal(check("url", "http://10.0.1.5/"), "http://10.0.1.5/");
    assert.equal(check("scope_target", "2001:db8::1"), "2001:db8::1");
    assert.throws(() => check("url", "https://other.org/"), /target 'other\.org' is not in scope/);
  });

  it("an in-scope target is still refused by block_internal", () => {
    assert.throws(
      () =>
        validateArgIn({ type: "ip_address", scope_check: true, block_internal: true }, "10.0.1.5", {
          scope: SCOPE,
        }),
      /block_internal/
    );
  });

  it("the async entry point enforces scope too", async () => {
    await assert.rejects(
      validateArgInAsync({ type: "scope_target", scope_check: true }, "other.org", { scope: SCOPE }),
      /is not in scope/
    );
    assert.equal(
      await validateArgInAsync({ type: "scope_target", scope_check: true }, "example.com", { scope: SCOPE }),
      "example.com"
    );
  });

  it("an empty scope file puts nothing in scope", () => {
    assert.throws(
      () => validateArgIn({ type: "scope_target", scope_check: true }, "example.com", { scope: makeScope({}) }),
      /is not in scope/
    );
  });

  it("no scope fails closed", () => {
    assert.throws(
      () => validateArgIn({ type: "scope_target", scope_check: true }, "example.com"),
      (err) => err.message === NO_SCOPE_FILE_MESSAGE
    );
    assert.throws(
      () => validateArg({ type: "url", scope_check: true }, "https://example.com/"),
      /no scope\/scope\.toml was found \(set TOOLCLAD_SCOPE_FILE\)/
    );
  });

  it("scope_check on an unsupported type is refused at validation time", () => {
    assert.throws(
      () => validateArgIn({ type: "string", scope_check: true }, "x", { scope: SCOPE }),
      /scope_check is not supported for type 'string'/
    );
  });
});

describe("scope file loading", () => {
  function scopeFile(content) {
    const dir = tmpDir();
    const path = join(dir, "scope.toml");
    writeFileSync(path, content);
    return path;
  }

  it("loads a valid file", () => {
    const scope = loadScopeFile(scopeFile(SCOPE_TOML));
    assert.deepEqual([...scope.allowed_domains], ["example.com", "*.example.com"]);
    assert.equal(scope.allowed_cidrs.length, 2);
  });

  it("refuses unknown keys", () => {
    assert.throws(() => loadScopeFile(scopeFile(`[scope]\nallowed_domain = ["a.com"]\n`)), /unknown key 'scope\.allowed_domain'/);
    assert.throws(() => loadScopeFile(scopeFile(`[other]\nx = 1\n`)), /unknown key 'other'/);
  });

  it("refuses a malformed CIDR", () => {
    assert.throws(() => loadScopeFile(scopeFile(`[scope]\nallowed_cidrs = ["10.0.1.0/33"]\n`)), /invalid CIDR/);
    assert.throws(() => loadScopeFile(scopeFile(`[scope]\nblocked_cidrs = ["10.0.1/24"]\n`)), /invalid CIDR/);
  });

  it("refuses a bad wildcard or domain rule", () => {
    for (const rule of ["ex*ample.com", "*example.com", "a.*.com", "*", "*.", "Example.com", "a..com", "a_b.com"]) {
      assert.throws(
        () => loadScopeFile(scopeFile(`[scope]\nallowed_domains = ["${rule}"]\n`)),
        /invalid domain rule/,
        rule
      );
    }
  });
});

describe("scope discovery", () => {
  let saved;
  before(() => {
    saved = process.env.TOOLCLAD_SCOPE_FILE;
    delete process.env.TOOLCLAD_SCOPE_FILE;
  });
  after(() => {
    if (saved !== undefined) process.env.TOOLCLAD_SCOPE_FILE = saved;
  });

  it("walks upward from the manifest directory", () => {
    const root = tmpDir();
    mkdirSync(join(root, "scope"));
    writeFileSync(join(root, "scope", "scope.toml"), SCOPE_TOML);
    const nested = join(root, "a", "b");
    mkdirSync(nested, { recursive: true });
    const path = join(nested, "t.clad.toml");
    writeFileSync(path, manifestToml());
    const manifest = loadManifest(path);
    const ok = execute(manifest, { target: "app.example.com" }, { dryRun: true });
    assert.deepEqual(ok.argv, ["echo", "app.example.com"]);
    assert.throws(() => execute(manifest, { target: "other.org" }, { dryRun: true }), /target 'other\.org' is not in scope/);
    assert.equal(discoverScope(nested).source, join(root, "scope", "scope.toml"));
  });

  it("TOOLCLAD_SCOPE_FILE wins over the upward walk", () => {
    const root = tmpDir();
    mkdirSync(join(root, "scope"));
    writeFileSync(join(root, "scope", "scope.toml"), SCOPE_TOML);
    const other = join(tmpDir(), "elsewhere.toml");
    writeFileSync(other, `[scope]\nallowed_domains = ["other.org"]\n`);
    const path = join(root, "t.clad.toml");
    writeFileSync(path, manifestToml());
    withEnv(other, () => {
      const manifest = loadManifest(path);
      assert.deepEqual(execute(manifest, { target: "other.org" }, { dryRun: true }).argv, ["echo", "other.org"]);
      assert.throws(() => execute(manifest, { target: "example.com" }, { dryRun: true }), /is not in scope/);
    });
  });

  it("an unreadable TOOLCLAD_SCOPE_FILE is an error, not a fallback", () => {
    const root = tmpDir();
    mkdirSync(join(root, "scope"));
    writeFileSync(join(root, "scope", "scope.toml"), SCOPE_TOML);
    const path = join(root, "t.clad.toml");
    writeFileSync(path, manifestToml());
    withEnv(join(root, "missing.toml"), () => {
      const manifest = loadManifest(path);
      assert.throws(
        () => execute(manifest, { target: "example.com" }, { dryRun: true }),
        /cannot read scope file/
      );
    });
  });

  it("fails closed when no scope file exists anywhere", (t) => {
    const root = tmpDir();
    if (discoverScope(root) !== null) {
      t.skip("a scope/scope.toml exists above the temp directory");
      return;
    }
    const path = join(root, "t.clad.toml");
    writeFileSync(path, manifestToml());
    const manifest = loadManifest(path);
    assert.throws(
      () => execute(manifest, { target: "example.com" }, { dryRun: true }),
      /scope_check is enabled but no scope\/scope\.toml was found/
    );
  });

  it("applies on the MCP path", () => {
    const other = join(tmpDir(), "s.toml");
    writeFileSync(other, `[scope]\nallowed_domains = ["example.com"]\n`);
    const manifest = {
      tool: { name: "m", description: "d" },
      args: { target: { type: "scope_target", scope_check: true } },
      mcp: { server: "s", tool: "x" },
    };
    withEnv(other, () => {
      assert.equal(executeMcp(manifest, { target: "example.com" }).mapped_args.target, "example.com");
      assert.throws(() => executeMcp({ ...manifest }, { target: "evil.org" }), /is not in scope/);
    });
  });

  it("applies on the CLI test command", () => {
    const root = tmpDir();
    const path = join(root, "t.clad.toml");
    writeFileSync(path, manifestToml());
    const scopePath = join(root, "s.toml");
    writeFileSync(scopePath, `[scope]\nallowed_domains = ["example.com"]\n`);
    const env = { ...process.env, TOOLCLAD_SCOPE_FILE: scopePath };
    const ok = spawnSync(process.execPath, [CLI, "test", path, "--arg", "target=example.com"], { encoding: "utf-8", env });
    assert.equal(ok.status, 0, ok.stderr);
    const bad = spawnSync(process.execPath, [CLI, "test", path, "--arg", "target=evil.org"], { encoding: "utf-8", env });
    assert.notEqual(bad.status, 0);
    assert.match(bad.stderr, /target 'evil\.org' is not in scope/);
  });
});

describe("scope_check at manifest load", () => {
  it("is refused on an unsupported built-in type", () => {
    const path = join(tmpDir(), "t.clad.toml");
    writeFileSync(path, manifestToml("string"));
    assert.throws(() => loadManifest(path), /scope_check is not supported for type 'string'/);
  });

  it("is refused on a custom type with an unsupported base", () => {
    const path = join(tmpDir(), "t.clad.toml");
    writeFileSync(path, manifestToml("ticket"));
    const manifest = loadManifest(path);
    assert.throws(
      () => validateManifestWithCustomTypes(manifest, { ticket: { base: "string" } }),
      /scope_check is not supported for type 'ticket'/
    );
  });

  it("is accepted on every supported type", () => {
    for (const type of ["scope_target", "url", "ip_address", "cidr"]) {
      const path = join(tmpDir(), "t.clad.toml");
      writeFileSync(path, manifestToml(type));
      assert.doesNotThrow(() => loadManifest(path), type);
    }
  });
});
