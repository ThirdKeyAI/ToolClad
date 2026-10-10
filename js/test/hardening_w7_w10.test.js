// Policy gate seam (TC-9), output caps and fail-closed schema validation
// (TC-12, TC-14), HTTP hardening and the declared envelope command (TC-16,
// design issue 9). HTTP tests talk only to a node:http server on 127.0.0.1.
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createServer } from "node:http";
import { existsSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { loadManifest } from "../src/manifest.js";
import {
  GateDecision,
  PolicyGateError,
  approveGate,
  defaultGate,
  execute,
  executeHttp,
  executeHttpSync,
  executeMcp,
} from "../src/executor.js";
import { validateJsonSchema } from "../src/schema.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const CLI = join(HERE, "..", "src", "cli.js");
const EXAMPLES = join(HERE, "..", "..", "examples");
const GATE_DENIED = /policy gate denied: /;

function tmp(prefix = "toolclad-w7-") {
  return mkdtempSync(join(tmpdir(), prefix));
}

function writeTmp(content) {
  const path = join(tmp(), "t.clad.toml");
  writeFileSync(path, content);
  return path;
}

function oneshot(exec, extra = {}) {
  return {
    tool: { name: "t", description: "d", timeout_seconds: 10, ...(extra.tool || {}) },
    args: extra.args || {},
    command: { exec, ...(extra.command || {}) },
    output: { format: "text", ...(extra.output || {}) },
  };
}

let savedEvidence;
before(() => {
  savedEvidence = process.env.TOOLCLAD_EVIDENCE_DIR;
  process.env.TOOLCLAD_EVIDENCE_DIR = join(tmp("toolclad-ev-"), "evidence");
});
after(() => {
  if (savedEvidence === undefined) delete process.env.TOOLCLAD_EVIDENCE_DIR;
  else process.env.TOOLCLAD_EVIDENCE_DIR = savedEvidence;
});

/** A loopback HTTP server that records every request it receives. */
function startServer(handler) {
  const requests = [];
  const server = createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      requests.push({ method: req.method, url: req.url, headers: req.headers, body });
      handler(req, res);
    });
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      resolve({
        base: `http://127.0.0.1:${port}`,
        requests,
        close: () => new Promise((r) => server.close(r)),
      });
    });
  });
}

function httpManifest(http, extra = {}) {
  return {
    tool: { name: "h", description: "d", timeout_seconds: 10, ...(extra.tool || {}) },
    args: extra.args || {},
    http,
    output: { format: "text", ...(extra.output || {}) },
  };
}

// ---------------------------------------------------------------------------
// W7: policy gate
// ---------------------------------------------------------------------------

describe("W7 policy gate seam (TC-9)", () => {
  it("human_approval = true is denied by default and nothing runs", async () => {
    const marker = join(tmp(), "ran");
    const m = oneshot(["touch", marker], { tool: { human_approval: true } });
    await assert.rejects(execute(m, {}), (err) => {
      assert.ok(err instanceof PolicyGateError);
      assert.equal(
        err.message,
        "policy gate denied: manifest requires human approval (human_approval = true)"
      );
      return true;
    });
    assert.equal(existsSync(marker), false);
  });

  it("risk_tier high and critical are denied; info, low and medium run", async () => {
    for (const tier of ["high", "critical"]) {
      const m = oneshot(["echo", "x"], { tool: { risk_tier: tier } });
      await assert.rejects(execute(m, {}), {
        message: `policy gate denied: risk_tier '${tier}' requires explicit approval`,
      });
    }
    for (const tier of ["info", "low", "medium"]) {
      const r = await execute(oneshot(["echo", "x"], { tool: { risk_tier: tier } }), {});
      assert.equal(r.status, "success");
    }
  });

  it("approve: true and an explicit allow-all gate run a gated manifest", async () => {
    const m = oneshot(["echo", "ok"], { tool: { human_approval: true, risk_tier: "critical" } });
    assert.equal((await execute(m, {}, { approve: true })).results.raw_output, "ok\n");
    assert.equal((await execute(m, {}, { gate: approveGate })).results.raw_output, "ok\n");
    assert.equal((await execute(m, {}, { gate: () => GateDecision.allow() })).status, "success");
  });

  it("passing both gate and approve is an error", async () => {
    const m = oneshot(["echo", "ok"]);
    await assert.rejects(execute(m, {}, { gate: approveGate, approve: true }), /not both/);
  });

  it("a custom gate's own condition and reason reach the caller, with validated values", async () => {
    const m = oneshot(["echo", "{mode}", "{name}"], {
      args: {
        mode: { type: "enum", allowed: ["safe", "loud"], required: true },
        name: { type: "string", default: "anon" },
      },
    });
    const seen = [];
    const gate = (manifest, args) => {
      seen.push(args);
      return args.mode === "loud" ? GateDecision.deny("loud mode needs a ticket") : GateDecision.allow();
    };
    await assert.rejects(execute(m, { mode: "loud" }, { gate }), {
      message: "policy gate denied: loud mode needs a ticket",
    });
    const r = await execute(m, { mode: "safe" }, { gate });
    assert.equal(r.results.raw_output, "safe anon\n");
    // The default was applied before the gate saw the arguments.
    assert.deepEqual({ ...seen[1] }, { mode: "safe", name: "anon" });
    assert.ok(Object.isFrozen(seen[1]));
  });

  it("a gate result that is not an explicit allow denies (fail closed)", async () => {
    const m = oneshot(["echo", "x"]);
    await assert.rejects(execute(m, {}, { gate: () => true }), GATE_DENIED);
    await assert.rejects(execute(m, {}, { gate: () => undefined }), GATE_DENIED);
  });

  it("validation runs before the gate: invalid and denied reports the validation error", async () => {
    const m = oneshot(["echo", "{n}"], {
      tool: { human_approval: true },
      args: { n: { type: "integer", required: true } },
    });
    let called = false;
    const gate = () => {
      called = true;
      return GateDecision.deny("never");
    };
    await assert.rejects(execute(m, { n: "abc" }, { gate }), (err) => {
      assert.doesNotMatch(err.message, GATE_DENIED);
      return true;
    });
    assert.equal(called, false);
    await assert.rejects(execute(m, { n: "abc" }), (err) => !GATE_DENIED.test(err.message));
  });

  it("the dry run is not gated", async () => {
    const m = oneshot(["echo", "x"], { tool: { human_approval: true, risk_tier: "high" } });
    const r = await execute(m, {}, { dryRun: true });
    assert.equal(r.status, "dry_run");
    assert.deepEqual(r.argv, ["echo", "x"]);
  });

  it("the HTTP path is gated before any request", async () => {
    const srv = await startServer((req, res) => res.end("hi"));
    try {
      const m = httpManifest({ method: "GET", url: `${srv.base}/x` }, { tool: { human_approval: true } });
      await assert.rejects(execute(m, {}), GATE_DENIED);
      await assert.rejects(executeHttp(m, {}), GATE_DENIED);
      assert.equal(srv.requests.length, 0);
      const r = await execute(m, {}, { approve: true });
      assert.equal(r.status, "success");
      assert.equal(srv.requests.length, 1);
    } finally {
      await srv.close();
    }
  });

  it("the MCP path is gated before the envelope is built", async () => {
    const m = {
      tool: { name: "m", description: "d", risk_tier: "critical" },
      args: { q: { type: "string", required: true } },
      mcp: { server: "srv", tool: "search" },
    };
    await assert.rejects(execute(m, { q: "x" }), GATE_DENIED);
    assert.throws(() => executeMcp(m, { q: "x" }), GATE_DENIED);
    const r = await execute(m, { q: "x" }, { approve: true });
    assert.equal(r.status, "delegation_preview");
    assert.equal(r.command, "mcp://srv/search");
  });

  it("defaultGate is exported and pure", () => {
    assert.deepEqual({ ...defaultGate({ tool: { risk_tier: "low" } }, {}) }, { allowed: true });
    assert.equal(defaultGate({ tool: { risk_tier: "HIGH" } }, {}).allowed, false);
  });

  it("CLI: run without --approve on the nikto example exits non-zero and runs nothing", () => {
    // The CLI does not load toolclad.toml yet, so this example fails on its
    // custom argument types before the gate is reached; either way nothing
    // executes and no envelope is printed. Never run it with --approve.
    const r = spawnSync(
      process.execPath,
      [CLI, "run", join(EXAMPLES, "nikto_scan.clad.toml"), "--arg", "target=93.184.216.34"],
      { encoding: "utf-8" }
    );
    assert.notEqual(r.status, 0);
    assert.equal(r.stdout, "");
  });

  it("CLI: run without --approve on a nikto-like human_approval manifest prints the gate message", () => {
    const path = writeTmp(`[tool]
name = "nikto_like"
description = "d"
binary = "nikto"
human_approval = true
network_egress = true

[args.target]
type = "scope_target"
required = true
block_internal = true
description = "t"

[command]
exec = ["nikto", "-h", "{target}"]

[output]
format = "text"
`);
    const r = spawnSync(process.execPath, [CLI, "run", path, "--arg", "target=93.184.216.34"], {
      encoding: "utf-8",
    });
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /policy gate denied: manifest requires human approval \(human_approval = true\)/);
    assert.equal(r.stdout, "");
  });

  it("CLI: run --approve runs an echo manifest that requires approval; test shows the tier", () => {
    const path = writeTmp(`[tool]
name = "approved_echo"
description = "d"
binary = "echo"
risk_tier = "high"
human_approval = true

[command]
exec = ["echo", "approved"]

[output]
format = "text"
`);
    const denied = spawnSync(process.execPath, [CLI, "run", path], { encoding: "utf-8" });
    assert.notEqual(denied.status, 0);
    assert.match(denied.stderr, /policy gate denied: /);

    const ok = spawnSync(process.execPath, [CLI, "run", path, "--approve"], { encoding: "utf-8" });
    assert.equal(ok.status, 0, ok.stderr);
    const env = JSON.parse(ok.stdout);
    assert.equal(env.status, "success");
    assert.equal(env.results.raw_output, "approved\n");

    const dry = spawnSync(process.execPath, [CLI, "test", path], { encoding: "utf-8" });
    assert.equal(dry.status, 0, dry.stderr);
    assert.match(dry.stdout, /Risk tier: high/);
    assert.match(dry.stdout, /Approval:\s+required/);
  });
});

// ---------------------------------------------------------------------------
// W9: output caps, XML hardening, schema validation
// ---------------------------------------------------------------------------

describe("W9 output cap (TC-12)", () => {
  it("stdout past max_bytes is capped and flagged; status is unaffected", async () => {
    const m = oneshot(["seq", "1", "5000"], { output: { max_bytes: 1024 } });
    const r = await execute(m, {});
    assert.equal(r.status, "success");
    assert.equal(r.output_truncated, true);
    assert.equal(r.results.raw_output.length, 1024);
    assert.ok(r.results.raw_output.startsWith("1\n2\n3\n"));
  });

  it("output under the cap carries no truncation flag", async () => {
    const r = await execute(oneshot(["echo", "small"], { output: { max_bytes: 1024 } }), {});
    assert.equal(r.output_truncated, undefined);
  });

  it("a capped multibyte stream never exceeds max_bytes or splits a character", async () => {
    const m = oneshot(["echo", "é".repeat(100)], { output: { max_bytes: 51 } });
    const r = await execute(m, {});
    assert.equal(r.output_truncated, true);
    assert.ok(Buffer.byteLength(r.results.raw_output) <= 51);
    assert.equal(r.results.raw_output, "é".repeat(25));
  });

  it("max_bytes must be an integer in 1..=1 GiB at load", () => {
    const head = `[tool]
name = "t"
description = "d"
binary = "echo"

[command]
exec = ["echo", "x"]

[output]
format = "text"
`;
    for (const bad of ["0", "-1", "1.5", '"big"', "1073741825"]) {
      assert.throws(() => loadManifest(writeTmp(`${head}max_bytes = ${bad}\n`)), /max_bytes/, bad);
    }
    assert.equal(loadManifest(writeTmp(`${head}max_bytes = 1073741824\n`)).output.max_bytes, 1073741824);
    assert.equal(loadManifest(writeTmp(head)).output.max_bytes, 8388608);
  });

  it("an in-memory manifest with a bad max_bytes is refused too", async () => {
    await assert.rejects(execute(oneshot(["echo", "x"], { output: { max_bytes: 0 } }), {}), /max_bytes/);
  });
});

describe("W9 XML hardening (TC-12)", () => {
  it("XML with a DOCTYPE / ENTITY declaration is refused as parse_error", async () => {
    const xml = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY a "aaaa">]><foo>&a;</foo>';
    const r = await execute(oneshot(["echo", xml], { output: { format: "xml" } }), {});
    assert.equal(r.status, "parse_error");
    assert.equal(
      r.results.parse_error,
      "XML output contains a DOCTYPE or ENTITY declaration; refusing to parse"
    );
    assert.equal(r.results.raw_output, `${xml}\n`);
    const lower = await execute(oneshot(["echo", "<!entity x><a/>"], { output: { format: "xml" } }), {});
    assert.equal(lower.status, "parse_error");
  });

  it("plain XML still parses; malformed XML is a parse_error", async () => {
    const ok = await execute(
      oneshot(["echo", '<?xml version="1.0"?><run><host addr="10.0.0.1"/></run>'], {
        output: { format: "xml" },
      }),
      {}
    );
    assert.equal(ok.status, "success");
    assert.deepEqual(ok.results, { run: { host: { "@addr": "10.0.0.1" } } });
    const bad = await execute(oneshot(["echo", "<run><host"], { output: { format: "xml" } }), {});
    assert.equal(bad.status, "parse_error");
  });
});

describe("W9 schema validator (TC-14)", () => {
  it("type, including arrays of names and integer accepting 30.0", () => {
    assert.equal(validateJsonSchema({ type: "integer" }, 30.0), null);
    assert.equal(validateJsonSchema({ type: "integer" }, 30.5), "/: expected integer, got number");
    assert.equal(validateJsonSchema({ type: ["string", "null"] }, null), null);
    assert.equal(validateJsonSchema({ type: "object" }, []), "/: expected object, got array");
    assert.equal(validateJsonSchema({ type: "boolean" }, "yes"), "/: expected boolean, got string");
    assert.equal(validateJsonSchema({ type: "null" }, 0), "/: expected null, got integer");
  });

  it("properties, required and additionalProperties: false", () => {
    const s = {
      type: "object",
      required: ["a"],
      additionalProperties: false,
      properties: { a: { type: "string" }, b: { type: "number" } },
    };
    assert.equal(validateJsonSchema(s, { a: "x", b: 1 }), null);
    assert.equal(validateJsonSchema(s, { b: 1 }), "/: missing required property 'a'");
    assert.equal(validateJsonSchema(s, { a: "x", c: 1 }), "/c: additional property is not allowed");
    assert.equal(validateJsonSchema(s, { a: 1 }), "/a: expected string, got integer");
    assert.equal(validateJsonSchema({ ...s, additionalProperties: true }, { a: "x", c: 1 }), null);
  });

  it("nested items and the JSON-pointer path format", () => {
    const s = {
      type: "object",
      properties: {
        hosts: {
          type: "array",
          items: { type: "object", properties: { port: { type: "integer" } } },
        },
      },
    };
    assert.equal(validateJsonSchema(s, { hosts: [{ port: 22 }, { port: 80 }] }), null);
    assert.equal(
      validateJsonSchema(s, { hosts: [{ port: "22" }] }),
      "/hosts/0/port: expected integer, got string"
    );
    assert.equal(
      validateJsonSchema({ properties: { "a/b": { type: "string" } } }, { "a/b": 1 }),
      "/a~1b: expected string, got integer"
    );
  });

  it("enum (deep equality), minimum/maximum, minLength/maxLength in code points", () => {
    assert.equal(validateJsonSchema({ enum: [{ a: [1] }, "x"] }, { a: [1] }), null);
    assert.match(validateJsonSchema({ enum: ["x"] }, "y"), /^\/: value "y" is not one of/);
    assert.equal(validateJsonSchema({ minimum: 1, maximum: 3 }, 3), null);
    assert.match(validateJsonSchema({ minimum: 1 }, 0), /less than the minimum/);
    assert.match(validateJsonSchema({ maximum: 3 }, 4), /greater than the maximum/);
    assert.equal(validateJsonSchema({ maxLength: 2 }, "😀😀"), null);
    assert.match(validateJsonSchema({ maxLength: 1 }, "😀😀"), /longer than 1/);
    assert.match(validateJsonSchema({ minLength: 3 }, "ab"), /shorter than 3/);
  });

  it("pattern is anchored", () => {
    assert.equal(validateJsonSchema({ pattern: "[a-z]+" }, "abc"), null);
    assert.match(validateJsonSchema({ pattern: "[a-z]+" }, "abc1"), /does not match pattern/);
    assert.match(validateJsonSchema({ pattern: "b" }, "abc"), /does not match pattern/);
  });

  it("unknown keywords are ignored", () => {
    assert.equal(validateJsonSchema({ type: "string", format: "ipv4", description: "x" }, "nope"), null);
  });
});

describe("W9 fail-closed results (TC-14)", () => {
  const schema = {
    type: "object",
    required: ["ok"],
    properties: { ok: { type: "boolean" } },
  };

  it("a schema mismatch is schema_error with the path, a match is success, bad JSON is parse_error", async () => {
    const path = writeTmp(`[tool]
name = "j"
description = "d"
binary = "echo"

[command]
exec = ["echo", "{{\\"ok\\": \\"yes\\"}}"]

[output]
format = "json"

[output.schema]
type = "object"
required = ["ok"]

[output.schema.properties.ok]
type = "boolean"
`);
    const bad = await execute(loadManifest(path), {});
    assert.equal(bad.status, "schema_error");
    assert.equal(bad.results.schema_error, "/ok: expected boolean, got string");
    assert.equal(bad.results.raw_output, '{"ok": "yes"}\n');
    assert.equal(bad.exit_code, 0);

    const good = await execute(oneshot(["echo", '{"ok": true}'], { output: { format: "json", schema } }), {});
    assert.equal(good.status, "success");
    assert.deepEqual(good.results, { ok: true });

    const notJson = await execute(oneshot(["echo", "not json"], { output: { format: "json", schema } }), {});
    assert.equal(notJson.status, "parse_error");
    assert.match(notJson.results.parse_error, /^invalid JSON output/);
    assert.equal(notJson.results.raw_output, "not json\n");
  });

  it("results are always an object: json non-object, jsonl, csv and text", async () => {
    const arr = await execute(oneshot(["echo", "[1, 2]"], { output: { format: "json" } }), {});
    assert.deepEqual(arr.results, { parsed_output: [1, 2] });
    const jsonl = await execute(oneshot(["echo", '{"a":1}\n{"a":2}'], { output: { format: "jsonl" } }), {});
    assert.deepEqual(jsonl.results, { parsed_output: [{ a: 1 }, { a: 2 }] });
    const csv = await execute(oneshot(["echo", "h,p\nx,30"], { output: { format: "csv" } }), {});
    assert.deepEqual(csv.results, { parsed_output: [{ h: "x", p: 30 }] });
    const text = await execute(oneshot(["echo", "t"]), {});
    assert.deepEqual(text.results, { raw_output: "t\n" });
    const badJsonl = await execute(oneshot(["echo", "{nope"], { output: { format: "jsonl" } }), {});
    assert.equal(badJsonl.status, "parse_error");
  });

  it("a custom parser is refused at load and in memory; every builtin is accepted", async () => {
    const head = (parser) => `[tool]
name = "p"
description = "d"
binary = "echo"

[command]
exec = ["echo", "x"]

[output]
format = "text"
parser = "${parser}"
`;
    assert.throws(
      () => loadManifest(writeTmp(head("scripts/x.py"))),
      /custom output parsers are not supported by the reference runtimes \(parser = "scripts\/x.py"\)/
    );
    for (const p of ["builtin:json", "builtin:jsonl", "builtin:csv", "builtin:xml", "builtin:text"]) {
      assert.equal(loadManifest(writeTmp(head(p))).output.parser, p);
    }
    await assert.rejects(
      execute(oneshot(["echo", "x"], { output: { parser: "scripts/x.py" } }), {}),
      /custom output parsers are not supported/
    );
  });
});

// ---------------------------------------------------------------------------
// W10: HTTP hardening and the declared envelope command
// ---------------------------------------------------------------------------

describe("W10 HTTP interpolation (TC-16)", () => {
  it("a path placeholder is percent-encoded and cannot change the structure", async () => {
    const m = httpManifest(
      { method: "GET", url: "https://api.example.com/{endpoint}" },
      { args: { endpoint: { type: "string", required: true } } }
    );
    const r = await executeHttp(m, { endpoint: "../admin?role=admin" }, { dryRun: true });
    assert.equal(r.http_url, "https://api.example.com/..%2Fadmin%3Frole%3Dadmin");
    const u = new URL(r.http_url);
    assert.equal(u.host, "api.example.com");
    assert.equal(u.search, "");
    assert.equal(u.pathname.includes("/admin"), false);
  });

  it("a query placeholder encodes & and =", async () => {
    const m = httpManifest(
      { method: "GET", url: "https://api.example.com/search?q={q}&n=1" },
      // enum values skip the metacharacter check, so `&` can reach the URL.
      { args: { q: { type: "enum", allowed: ["a&admin=true"], required: true } } }
    );
    const r = await executeHttp(m, { q: "a&admin=true" }, { dryRun: true });
    assert.equal(r.http_url, "https://api.example.com/search?q=a%26admin%3Dtrue&n=1");
    assert.deepEqual([...new URL(r.http_url).searchParams.keys()], ["q", "n"]);
  });

  it("interpolating into the scheme or host is a load error", async () => {
    const head = (url) => `[tool]
name = "h"
description = "d"

[args.host]
type = "string"
description = "h"

[http]
method = "GET"
url = "${url}"
`;
    for (const url of [
      "https://{host}/x",
      "https://api.{host}.com/x",
      "https://api.example.com:{host}/x",
      "{host}/x",
      "{host}://api.example.com/",
      "https://{_secret:h}/x",
    ]) {
      assert.throws(
        () => loadManifest(writeTmp(head(url))),
        /http\.url may not interpolate into the scheme or host/,
        url
      );
    }
    // The same check guards an in-memory manifest.
    const m = httpManifest({ method: "GET", url: "https://{host}/x" }, { args: { host: { type: "string" } } });
    await assert.rejects(executeHttp(m, { host: "a" }, { dryRun: true }), /scheme or host/);
  });

  it("the literal host is held to the host policy at load", () => {
    const head = (url, blockInternal) => `[tool]
name = "h"
description = "d"

[args.q]
type = "string"
description = "q"
block_internal = ${blockInternal}

[http]
method = "GET"
url = "${url}"
`;
    assert.throws(() => loadManifest(writeTmp(head("http://169.254.169.254/x", false))), /always blocked/);
    assert.ok(loadManifest(writeTmp(head("http://127.0.0.1:8080/x", false))));
    assert.throws(() => loadManifest(writeTmp(head("http://127.0.0.1:8080/x", true))));
    assert.throws(() => loadManifest(writeTmp(head("http://10.1.2.3/x", true))));
  });

  it("a header value with CR/LF after interpolation is refused; header names must be tokens", async () => {
    const m = httpManifest(
      { method: "GET", url: "https://api.example.com/", headers: { "X-Tag": "{tag}" } },
      { args: { tag: { type: "enum", allowed: ["ok", "a\r\nX-Admin: 1"], required: true } } }
    );
    await assert.rejects(executeHttp(m, { tag: "a\r\nX-Admin: 1" }, { dryRun: true }), /CR, LF or NUL/);
    assert.equal((await executeHttp(m, { tag: "ok" }, { dryRun: true })).http_headers["X-Tag"], "ok");

    assert.throws(
      () =>
        loadManifest(
          writeTmp(`[tool]
name = "h"
description = "d"

[http]
method = "GET"
url = "https://api.example.com/"

[http.headers]
"Bad Name" = "x"
`)
        ),
      /not a valid token/
    );
  });
});

describe("W10 HTTP requests against a loopback server", () => {
  const SECRET = "tok-value-never-in-the-envelope";
  let srv;
  let savedSecret;

  before(async () => {
    savedSecret = process.env.TOOLCLAD_SECRET_TOK;
    process.env.TOOLCLAD_SECRET_TOK = SECRET;
    srv = await startServer((req, res) => {
      if (req.url.startsWith("/redir")) {
        res.writeHead(302, { Location: "http://127.0.0.1:1/" });
        res.end("moved");
      } else if (req.url.startsWith("/big")) {
        res.end("a".repeat(5000));
      } else if (req.url.startsWith("/json")) {
        res.setHeader("content-type", "application/json");
        res.end('{"ok": "yes"}');
      } else {
        res.end("hello");
      }
    });
  });
  after(async () => {
    await srv.close();
    if (savedSecret === undefined) delete process.env.TOOLCLAD_SECRET_TOK;
    else process.env.TOOLCLAD_SECRET_TOK = savedSecret;
  });

  it("a 302 is not followed: redirect_blocked, Location reported, one request", async () => {
    const before = srv.requests.length;
    const r = await executeHttp(httpManifest({ method: "GET", url: `${srv.base}/redir` }), {});
    assert.equal(r.status, "redirect_blocked");
    assert.equal(r.http_status, 302);
    assert.equal(r.results.location, "http://127.0.0.1:1/");
    assert.equal(r.results.raw_output, "moved");
    assert.equal(srv.requests.length - before, 1);
  });

  it("the response body is capped at max_bytes", async () => {
    const r = await executeHttp(
      httpManifest({ method: "GET", url: `${srv.base}/big` }, { output: { max_bytes: 1000 } }),
      {}
    );
    assert.equal(r.status, "success");
    assert.equal(r.output_truncated, true);
    assert.equal(r.results.raw_output, "a".repeat(1000));
  });

  it("an HTTP json result is schema-checked, fail closed", async () => {
    const r = await executeHttp(
      httpManifest(
        { method: "GET", url: `${srv.base}/json` },
        { output: { format: "json", schema: { properties: { ok: { type: "boolean" } } } } }
      ),
      {}
    );
    assert.equal(r.status, "schema_error");
    assert.equal(r.results.schema_error, "/ok: expected boolean, got string");
  });

  it("the envelope command is the declared request; the secret is sent but never reported", async () => {
    const url = `${srv.base}/x?k={_secret:tok}&q={q}`;
    const m = httpManifest(
      { method: "GET", url, headers: { Authorization: "Bearer {_secret:tok}" } },
      { args: { q: { type: "string", required: true } } }
    );
    const before = srv.requests.length;
    const r = await executeHttp(m, { q: "a/b?c" });
    assert.equal(r.status, "success");
    assert.equal(r.command, `GET ${url}`);
    assert.ok(r.command.includes("{_secret:tok}"));
    assert.equal(JSON.stringify(r).includes(SECRET), false);
    const seen = srv.requests[before];
    assert.equal(seen.url, `/x?k=${SECRET}&q=a%2Fb%3Fc`);
    assert.equal(seen.headers.authorization, `Bearer ${SECRET}`);
  });

  it("executeHttpSync is a deprecated alias of the fetch path (no curl, nothing on an argv)", async () => {
    const before = srv.requests.length;
    const pending = executeHttpSync(
      httpManifest({ method: "GET", url: `${srv.base}/x`, headers: { Authorization: "Bearer {_secret:tok}" } }),
      {}
    );
    assert.ok(pending instanceof Promise);
    const r = await pending;
    assert.equal(r.status, "success");
    assert.equal(r.results.raw_output, "hello");
    assert.equal(srv.requests.length - before, 1);
    assert.equal(srv.requests[before].headers.authorization, `Bearer ${SECRET}`);
  });
});

describe("W10 declared envelope command (design issue 9)", () => {
  it("oneshot: the declared exec joined by spaces, no evidence path; the dry run stays resolved", async () => {
    const m = oneshot(["echo", "{target}", "{_output_file}"], {
      args: { target: { type: "string", required: true } },
    });
    const r = await execute(m, { target: "hello" });
    assert.equal(r.command, "echo {target} {_output_file}");
    assert.equal(r.command.includes(process.env.TOOLCLAD_EVIDENCE_DIR), false);
    assert.ok(r.results.raw_output.startsWith("hello "));

    const dry = await execute(m, { target: "hello" }, { dryRun: true });
    assert.equal(dry.argv[1], "hello");
    assert.equal(dry.command, dry.argv.join(" "));
    assert.ok(dry.command.includes(process.env.TOOLCLAD_EVIDENCE_DIR));
  });

  it("a legacy template is reported as written", async () => {
    const m = {
      tool: { name: "t", description: "d", timeout_seconds: 10 },
      args: { target: { type: "string", required: true } },
      command: { template: "echo {target}" },
      output: { format: "text" },
    };
    const r = await execute(m, { target: "x" });
    assert.equal(r.command, "echo {target}");
    assert.equal(r.results.raw_output, "x\n");
  });
});
