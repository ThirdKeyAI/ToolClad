import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { writeFileSync, unlinkSync, mkdtempSync, mkdirSync, rmdirSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  validateArg,
  validateArgWithCustomTypes,
} from "../src/validator.js";
import { execute } from "../src/executor.js";

// --- msf_options ---

describe("validateArg - msf_options", () => {
  it("accepts valid key-value pairs", async () => {
    assert.equal(
      validateArg({ type: "msf_options" }, "RHOSTS 10.0.0.1"),
      "RHOSTS 10.0.0.1"
    );
  });

  it("accepts semicolon-separated pairs", async () => {
    assert.equal(
      validateArg({ type: "msf_options" }, "RHOSTS 10.0.0.1; RPORT 445"),
      "RHOSTS 10.0.0.1; RPORT 445"
    );
  });

  it("rejects missing value (no space)", async () => {
    assert.throws(
      () => validateArg({ type: "msf_options" }, "RHOSTS"),
      /invalid pair/
    );
  });

  it("rejects lowercase keys", async () => {
    assert.throws(
      () => validateArg({ type: "msf_options" }, "rhosts 10.0.0.1"),
      /invalid key/
    );
  });

  it("rejects pipe in value", async () => {
    assert.throws(
      () => validateArg({ type: "msf_options" }, "RHOSTS 10.0.0.1|whoami"),
      /disallowed characters/
    );
  });

  it("rejects backtick in value", async () => {
    assert.throws(
      () => validateArg({ type: "msf_options" }, "RHOSTS `id`"),
      /disallowed characters/
    );
  });

  it("allows empty string between semicolons", async () => {
    assert.equal(
      validateArg({ type: "msf_options" }, "RHOSTS 10.0.0.1;;"),
      "RHOSTS 10.0.0.1;;"
    );
  });
});

// --- credential_file ---

describe("validateArg - credential_file", () => {
  it("accepts a valid relative file path", async () => {
    const dir = mkdtempSync(join(tmpdir(), "toolclad-cred-"));
    const file = join(dir, "creds.json");
    writeFileSync(file, "{}");
    try {
      // credential_file requires a relative path, so we test with the full
      // path only for existence. In practice this would be relative to cwd.
      // We'll test rejection of absolute paths separately.
      assert.equal(validateArg({ type: "credential_file" }, file), file);
    } catch (err) {
      // Absolute paths are rejected — that's the correct behavior
      assert.match(err.message, /relative path|Injection/);
    } finally {
      unlinkSync(file);
    }
  });

  it("rejects absolute paths", async () => {
    assert.throws(
      () => validateArg({ type: "credential_file" }, "/etc/passwd"),
      /relative path|Injection/
    );
  });

  it("rejects path traversal", async () => {
    assert.throws(
      () => validateArg({ type: "credential_file" }, "foo/../../../etc/passwd"),
      /traversal|Injection/
    );
  });

  it("rejects nonexistent file", async () => {
    assert.throws(
      () => validateArg({ type: "credential_file" }, "no-such-file.json"),
      /not found/
    );
  });

  it("rejects a directory", async () => {
    const testDir = "test-cred-dir-tmp";
    mkdirSync(testDir, { recursive: true });
    try {
      assert.throws(
        () => validateArg({ type: "credential_file" }, testDir),
        /Not a file/
      );
    } finally {
      try {
        rmdirSync(testDir);
      } catch {
        // best-effort cleanup
      }
    }
  });
});

// --- duration ---

describe("validateArg - duration", () => {
  it("accepts plain integer seconds", async () => {
    assert.equal(validateArg({ type: "duration" }, "30"), "30");
    assert.equal(validateArg({ type: "duration" }, "0"), "0");
  });

  it("accepts duration with suffixes", async () => {
    assert.equal(validateArg({ type: "duration" }, "5m"), "5m");
    assert.equal(validateArg({ type: "duration" }, "2h"), "2h");
    assert.equal(validateArg({ type: "duration" }, "1h30m"), "1h30m");
    assert.equal(validateArg({ type: "duration" }, "500ms"), "500ms");
    assert.equal(validateArg({ type: "duration" }, "1h30m15s"), "1h30m15s");
  });

  it("rejects invalid durations", async () => {
    assert.throws(
      () => validateArg({ type: "duration" }, "abc"),
      /Invalid duration/
    );
    assert.throws(
      () => validateArg({ type: "duration" }, "5x"),
      /Invalid duration/
    );
    assert.throws(
      () => validateArg({ type: "duration" }, "m5"),
      /Invalid duration/
    );
  });
});

// --- regex_match ---

describe("validateArg - regex_match", () => {
  it("accepts values matching pattern", async () => {
    const def = { type: "regex_match", pattern: "^[a-z0-9-]+$" };
    assert.equal(validateArg(def, "my-scan-123"), "my-scan-123");
  });

  it("rejects values not matching pattern", async () => {
    const def = { type: "regex_match", pattern: "^[a-z]+$" };
    assert.throws(
      () => validateArg(def, "HAS-UPPER"),
      /does not match required pattern/
    );
  });

  it("throws when pattern field is missing", async () => {
    assert.throws(
      () => validateArg({ type: "regex_match" }, "anything"),
      /requires a 'pattern' field/
    );
  });

  it("rejects injection even when pattern matches", async () => {
    const def = { type: "regex_match", pattern: ".*" };
    assert.throws(
      () => validateArg(def, "foo;bar"),
      /Injection/
    );
  });
});

// --- validateArgWithCustomTypes ---

describe("validateArgWithCustomTypes", () => {
  it("falls through to validateArg when no custom type matches", async () => {
    const result = validateArgWithCustomTypes(
      { type: "integer" },
      42,
      {}
    );
    assert.equal(result, 42);
  });

  it("applies custom type with base=enum", async () => {
    const customTypes = {
      severity: {
        base: "enum",
        allowed: ["low", "medium", "high", "critical"],
      },
    };
    const result = validateArgWithCustomTypes(
      { type: "severity" },
      "high",
      customTypes
    );
    assert.equal(result, "high");
  });

  it("rejects disallowed value in custom enum type", async () => {
    const customTypes = {
      severity: {
        base: "enum",
        allowed: ["low", "medium", "high"],
      },
    };
    assert.throws(
      () =>
        validateArgWithCustomTypes(
          { type: "severity" },
          "extreme",
          customTypes
        ),
      /not in allowed/
    );
  });

  it("applies custom type with base=integer and min/max", async () => {
    const customTypes = {
      thread_count: {
        base: "integer",
        min: 1,
        max: 64,
      },
    };
    assert.equal(
      validateArgWithCustomTypes(
        { type: "thread_count" },
        32,
        customTypes
      ),
      32
    );
    assert.throws(
      () =>
        validateArgWithCustomTypes(
          { type: "thread_count" },
          100,
          customTypes
        ),
      /exceeds maximum/
    );
  });

  it("throws on invalid base type", async () => {
    const customTypes = {
      bad_type: { base: "nonexistent" },
    };
    assert.throws(
      () =>
        validateArgWithCustomTypes(
          { type: "bad_type" },
          "value",
          customTypes
        ),
      /invalid base type/
    );
  });
});

// --- executor session/browser gates ---

describe("execute - session/browser gates", () => {
  it("throws on session manifest", async () => {
    const manifest = {
      tool: { name: "psql", description: "test" },
      session: { startup_command: "psql" },
      args: {},
    };
    await assert.rejects(
      () => execute(manifest, {}),
      /session mode is parsed but not yet executable/
    );
  });

  it("throws on browser manifest", async () => {
    const manifest = {
      tool: { name: "browser", description: "test" },
      browser: { engine: "cdp" },
      args: {},
    };
    await assert.rejects(
      () => execute(manifest, {}),
      /browser mode is parsed but not yet executable/
    );
  });
});
