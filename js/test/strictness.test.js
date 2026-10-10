import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { writeFileSync, mkdtempSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { loadManifest, loadManifestWithOptions } from "../src/manifest.js";
import { validateArg } from "../src/validator.js";

// Validator strictness shared with the other runtimes. No network tool is
// run and no DNS lookup is made.

function refused(type, values, extra = {}) {
  for (const value of values) {
    assert.throws(() => validateArg({ type, ...extra }, value), undefined, `${type} ${JSON.stringify(value)}`);
  }
}

function accepted(type, pairs, extra = {}) {
  for (const [value, out] of pairs) {
    assert.equal(validateArg({ type, ...extra }, value), out, `${type} ${JSON.stringify(value)}`);
  }
}

describe("numeric strictness", () => {
  it("integer requires plain decimal", () => {
    refused("integer", ["", "0x10", "1_000", " 7 ", "7\n", "1e3", "7.0", "++7", "Infinity", "0b1"]);
    accepted("integer", [["+7", 7], ["7", 7], ["-3", -3], ["007", 7], [42, 42]], { allow_leading_dash: true });
    assert.equal(String(validateArg({ type: "integer" }, "+7")), "7");
  });

  it("port requires digits in 1-65535", () => {
    refused("port", ["", "+80", "0x50", " 80", "80 ", "0", "65536", "8.0", "-1"]);
    accepted("port", [["80", 80], ["65535", 65535], [443, 443]]);
  });

  it("number requires a decimal literal and re-renders it", () => {
    refused("number", ["NaN", "inf", "Infinity", "-inf", "0x1p3", "0x10", "", " 1", "1 ", "1_0", "1e", "."]);
    assert.equal(String(validateArg({ type: "number" }, "1e2")), "100");
    assert.equal(String(validateArg({ type: "number" }, "0.50")), "0.5");
    assert.equal(String(validateArg({ type: "number" }, ".5")), "0.5");
    assert.equal(String(validateArg({ type: "number" }, "5.")), "5");
  });

  it("duration requires the exact grammar", () => {
    refused("duration", ["5m\n", "1_000", " 7 ", "5 m", "", "5x", "1m1h", "5M"]);
    accepted("duration", [["30", "30"], ["5m", "5m"], ["1h30m", "1h30m"], ["500ms", "500ms"], ["1h2m3s4ms", "1h2m3s4ms"]]);
  });

  it("boolean is case-insensitive and normalized", () => {
    assert.equal(String(validateArg({ type: "boolean" }, "True")), "true");
    assert.equal(String(validateArg({ type: "boolean" }, "FALSE")), "false");
    refused("boolean", ["yes", "1", " true", ""]);
  });
});

describe("host shape parity", () => {
  it("refuses a trailing dot in a hostname", () => {
    refused("scope_target", ["example.com."]);
    refused("url", ["https://example.com./"]);
  });

  it("accepts a canonical IPv6 CIDR", () => {
    accepted("scope_target", [["2001:db8::/32", "2001:db8::/32"]]);
    accepted("cidr", [["2001:db8::/32", "2001:db8::/32"]]);
  });

  it("applies the policy to an IPv6 CIDR", () => {
    refused("scope_target", ["2001:db8::/32"], { block_internal: true });
    refused("cidr", ["fe80::/10"]);
  });
});

describe("path components", () => {
  it("refuses .. as a whole component", () => {
    refused("path", ["..", "foo/..", "foo\\..", "../x", "a/../b", "/abs", "C:x"]);
    accepted("path", [["foo/..bar", "foo/..bar"], ["a/b..", "a/b.."], ["x/y", "x/y"]]);
  });

  it("refuses .. in a credential_file", () => {
    refused("credential_file", ["..", "foo/.."]);
  });
});

describe("per-argument defaults are validated at load", () => {
  function manifest(argBody) {
    const dir = mkdtempSync(join(tmpdir(), "toolclad-strict-"));
    const path = join(dir, "t.clad.toml");
    writeFileSync(
      path,
      `
[tool]
name = "t"
binary = "echo"
description = "d"

[args.a]
position = 1
description = "a"
${argBody}

[command]
template = "echo {a}"

[output]
format = "text"
`
    );
    return path;
  }

  it("refuses a port default of 0", () => {
    assert.throws(() => loadManifest(manifest(`type = "port"\ndefault = 0`)), /args\.a\.default is invalid/);
  });

  it("refuses an integer default below min", () => {
    assert.throws(
      () => loadManifest(manifest(`type = "integer"\nmin = 1\ndefault = 0`)),
      /args\.a\.default is invalid/
    );
  });

  it("refuses a string default with a space in template mode", () => {
    assert.throws(
      () => loadManifest(manifest(`type = "string"\ndefault = "a b"`)),
      /args\.a\.default is invalid/
    );
  });

  it("accepts valid defaults and an empty string default", () => {
    assert.doesNotThrow(() => loadManifest(manifest(`type = "port"\ndefault = 80`)));
    assert.doesNotThrow(() => loadManifest(manifest(`type = "string"\ndefault = ""`)));
    assert.doesNotThrow(() => loadManifest(manifest(`type = "string"\nrequired = true\ndefault = ""`)));
    assert.doesNotThrow(() => loadManifest(manifest(`type = "boolean"\ndefault = true`)));
  });

  it("checks custom-type defaults once the custom types are known", () => {
    assert.throws(
      () =>
        loadManifestWithOptions(manifest(`type = "level"\ndefault = "9"`), {
          customTypes: { level: { base: "integer", min: 1, max: 5 } },
        }),
      /args\.a\.default is invalid/
    );
  });
});
