// The shipped examples, loaded through the same discovery path the CLI uses
// (toolclad.toml and scope/scope.toml searched upward from each manifest), and
// dry-run end to end. Only argv is built; no tool is ever executed.

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { loadManifest } from "../src/manifest.js";
import { execute } from "../src/executor.js";

const JS_DIR = join(dirname(fileURLToPath(import.meta.url)), "..");
const EXAMPLES = join(JS_DIR, "..", "examples");
const CLI = join(JS_DIR, "src", "cli.js");
const SKIP = existsSync(EXAMPLES)
  ? false
  : `examples directory not found at ${EXAMPLES} (package built outside the repository)`;

const example = (name) => join(EXAMPLES, `${name}.clad.toml`);

// Discovery must come from the manifest's location, not the environment.
function withoutDiscoveryOverrides(fn) {
  return async () => {
    const saved = {
      scope: process.env.TOOLCLAD_SCOPE_FILE,
      config: process.env.TOOLCLAD_CONFIG_FILE,
    };
    delete process.env.TOOLCLAD_SCOPE_FILE;
    delete process.env.TOOLCLAD_CONFIG_FILE;
    try {
      await fn();
    } finally {
      if (saved.scope !== undefined) process.env.TOOLCLAD_SCOPE_FILE = saved.scope;
      if (saved.config !== undefined) process.env.TOOLCLAD_CONFIG_FILE = saved.config;
    }
  };
}

async function dryRun(name, args) {
  return execute(loadManifest(example(name)), args, { dryRun: true });
}

describe("shipped examples (W12)", { skip: SKIP }, () => {
  it("every example loads, including nikto's custom types", withoutDiscoveryOverrides(() => {
    const names = readdirSync(EXAMPLES).filter((f) => f.endsWith(".clad.toml")).sort();
    assert.deepEqual(names, [
      "curl_fetch.clad.toml",
      "dig_lookup.clad.toml",
      "nikto_scan.clad.toml",
      "nmap_scan.clad.toml",
      "whois_lookup.clad.toml",
    ]);
    for (const name of names) {
      assert.doesNotThrow(() => loadManifest(join(EXAMPLES, name)), name);
    }
  }));

  it("`toolclad validate` accepts all five", () => {
    const env = { ...process.env };
    delete env.TOOLCLAD_SCOPE_FILE;
    delete env.TOOLCLAD_CONFIG_FILE;
    for (const name of readdirSync(EXAMPLES).filter((f) => f.endsWith(".clad.toml"))) {
      const out = execFileSync(process.execPath, [CLI, "validate", join(EXAMPLES, name)], {
        env,
        encoding: "utf-8",
      });
      assert.match(out, /OK/, name);
    }
  });

  it("nikto dry run builds the expected argv with custom types", withoutDiscoveryOverrides(async () => {
    const result = await dryRun("nikto_scan", {
      target: "93.184.216.34",
      port: "8080-8090",
      protocol: "https",
      max_rate: "250",
    });
    for (const token of ["-h", "https://93.184.216.34:8080-8090", "-Plugins", "@@ALL", "-maxrate", "250"]) {
      assert.ok(result.argv.includes(token), `argv ${JSON.stringify(result.argv)} lacks ${token}`);
    }
  }));

  it("nikto refuses a port outside the anchored port_range pattern", withoutDiscoveryOverrides(async () => {
    await assert.rejects(dryRun("nikto_scan", { target: "93.184.216.34", port: "80;id" }));
    await assert.rejects(
      dryRun("nikto_scan", { target: "93.184.216.34", port: "80x" }),
      /does not match pattern/
    );
    await assert.rejects(
      dryRun("nikto_scan", { target: "93.184.216.34", protocol: "gopher" }),
      /gopher/
    );
  }));

  it("curl refuses a public IP literal as out of scope", withoutDiscoveryOverrides(async () => {
    await assert.rejects(
      dryRun("curl_fetch", { url: "https://93.184.216.34/" }),
      /target '93\.184\.216\.34' is not in scope/
    );
  }));

  it("curl refuses a hostname under block_internal without resolving it", withoutDiscoveryOverrides(async () => {
    // The JS executor validates synchronously: a hostname under
    // block_internal cannot be verified without DNS and is refused.
    await assert.rejects(
      dryRun("curl_fetch", { url: "https://example.com/" }),
      /cannot be verified without DNS resolution/
    );
  }));
});

describe("CLI version", () => {
  it("reports package.json's version", () => {
    const pkg = JSON.parse(readFileSync(join(JS_DIR, "package.json"), "utf-8"));
    const out = execFileSync(process.execPath, [CLI, "--version"], { encoding: "utf-8" });
    assert.equal(out.trim(), pkg.version);
  });
});
