// Spawn-path hardening (environment, secrets, argv[0], stdin, cwd, evidence
// paths) and timeouts that fire (SIGTERM, grace, SIGKILL to the group).
import { describe, it, before, after, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  statSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { loadManifest } from "../src/manifest.js";
import {
  FIXED_PATH,
  buildChildEnv,
  compileCommand,
  ensurePrivateDir,
  execute,
  executeSync,
  injectTemplateVars,
  makeSecretResolver,
  resolveBinary,
} from "../src/executor.js";

const SCAN_ID_RE = /^\d+-[0-9a-f]{32}$/;
const ALLOWED_ENV = new Set(["PATH", "HOME", "LANG", "LC_ALL", "TZ", "TERM"]);

function tmp(prefix = "toolclad-w6-") {
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

function envNames(stdout) {
  return stdout
    .split("\n")
    .filter((line) => line.includes("="))
    .map((line) => line.slice(0, line.indexOf("=")));
}

/** Set environment variables for the duration of each test in a describe. */
function useEnv(values) {
  const saved = {};
  beforeEach(() => {
    for (const [k, v] of Object.entries(values())) {
      saved[k] = process.env[k];
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  });
  afterEach(() => {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  });
}

let evidenceRoot;
let savedEvidence;
before(() => {
  savedEvidence = process.env.TOOLCLAD_EVIDENCE_DIR;
  evidenceRoot = join(tmp("toolclad-ev-"), "evidence");
  process.env.TOOLCLAD_EVIDENCE_DIR = evidenceRoot;
});
after(() => {
  if (savedEvidence === undefined) delete process.env.TOOLCLAD_EVIDENCE_DIR;
  else process.env.TOOLCLAD_EVIDENCE_DIR = savedEvidence;
});

// --- environment -----------------------------------------------------------

describe("child environment allowlist", () => {
  useEnv(() => ({
    TOOLCLAD_SECRET_LEAK: "sentinel-one",
    AWS_SECRET_ACCESS_KEY: "sentinel-two",
    LD_PRELOAD: "/tmp/x",
    PATH: "/attacker/bin:" + process.env.PATH,
  }));

  it("contains only allowlisted names and the fixed PATH", async () => {
    const r = await execute(oneshot(["printenv"]), {});
    assert.equal(r.status, "success", r.stderr);
    const out = r.results.raw_output;
    for (const sentinel of ["sentinel-one", "sentinel-two", "/tmp/x", "/attacker/bin"]) {
      assert.equal(out.includes(sentinel), false, `${sentinel} leaked`);
    }
    for (const name of envNames(out)) {
      assert.ok(ALLOWED_ENV.has(name), `unexpected variable ${name}`);
    }
    assert.ok(out.split("\n").includes(`PATH=${FIXED_PATH}`));
  });

  it("executor hatch adds TOOLCLAD_ARG_* and context, never TOOLCLAD_SECRET_*", async () => {
    const m = {
      tool: { name: "hatch", description: "d", timeout_seconds: 10 },
      args: { msg: { type: "string", required: true } },
      command: { executor: resolveBinary("printenv") },
      output: { format: "text" },
    };
    const r = await execute(m, { msg: "hello" });
    assert.equal(r.status, "success", r.stderr);
    const lines = r.results.raw_output.split("\n");
    assert.ok(lines.includes("TOOLCLAD_ARG_MSG=hello"));
    assert.ok(lines.includes(`TOOLCLAD_SCAN_ID=${r.scan_id}`));
    assert.ok(lines.includes("TOOLCLAD_TOOL_NAME=hatch"));
    assert.ok(lines.includes(`TOOLCLAD_EVIDENCE_DIR=${evidenceRoot}`));
    assert.ok(lines.includes(`TOOLCLAD_OUTPUT_DIR=${join(evidenceRoot, `${r.scan_id}-hatch`)}`));
    assert.ok(lines.includes(`PATH=${FIXED_PATH}`));
    assert.equal(lines.some((l) => l.startsWith("TOOLCLAD_SECRET_")), false);
    assert.equal(r.results.raw_output.includes("sentinel"), false);
    const extra = new Set([
      "TOOLCLAD_ARG_MSG", "TOOLCLAD_SCAN_ID", "TOOLCLAD_TOOL_NAME",
      "TOOLCLAD_EVIDENCE_DIR", "TOOLCLAD_OUTPUT_DIR",
    ]);
    for (const name of envNames(r.results.raw_output)) {
      assert.ok(ALLOWED_ENV.has(name) || extra.has(name), `unexpected variable ${name}`);
    }
  });

  it("buildChildEnv filters TOOLCLAD_SECRET_* even when passed explicitly", () => {
    const env = buildChildEnv({ TOOLCLAD_SECRET_X: "s", TOOLCLAD_ARG_X: "a" });
    assert.equal(env.TOOLCLAD_SECRET_X, undefined);
    assert.equal(env.TOOLCLAD_ARG_X, "a");
    assert.equal(env.PATH, FIXED_PATH);
  });
});

// --- secrets file ----------------------------------------------------------

describe("TOOLCLAD_SECRETS_FILE", () => {
  let file;
  useEnv(() => {
    file = join(tmp(), "secrets.toml");
    writeFileSync(file, 'api_key = "from-file"\n', { mode: 0o600 });
    chmodSync(file, 0o600);
    return {
      TOOLCLAD_SECRETS_FILE: file,
      TOOLCLAD_SECRET_API_KEY: "from-env",
      TOOLCLAD_SECRET_ONLY_ENV: "env-only",
      TOOLCLAD_SECRET_ABSENT: undefined,
    };
  });

  it("a 0600 file's value is used and wins over the environment variable", () => {
    assert.equal(injectTemplateVars("k={_secret:api_key}"), "k=from-file");
  });

  it("the environment variable still serves names the file lacks", () => {
    assert.equal(injectTemplateVars("{_secret:only_env}"), "env-only");
  });

  it("a group- or world-readable file is refused, naming the mode", () => {
    chmodSync(file, 0o644);
    assert.throws(
      () => injectTemplateVars("{_secret:api_key}"),
      /TOOLCLAD_SECRETS_FILE '.*' is readable by group or others \(mode 0644\); chmod 600 it/
    );
  });

  it("a missing secret is still an error", () => {
    assert.throws(
      () => injectTemplateVars("{_secret:absent}"),
      /Missing environment variable: TOOLCLAD_SECRET_ABSENT/
    );
  });

  it("the file is read at most once per resolver", () => {
    const resolve = makeSecretResolver();
    assert.equal(resolve("api_key"), "from-file");
    unlinkSync(file);
    assert.equal(injectTemplateVars("{_secret:api_key}{_secret:api_key}", resolve), "from-filefrom-file");
  });
});

// --- argv[0] ---------------------------------------------------------------

describe("argv[0] resolution and the interpreter denylist", () => {
  const head = (tool) => `[tool]
name = "t"
description = "d"
${tool}
`;
  const tail = `
[output]
format = "text"
`;

  it("a bare name resolves against the fixed PATH and runs", async () => {
    const path = resolveBinary("echo");
    assert.ok(FIXED_PATH.split(":").some((dir) => path === join(dir, "echo")));
    const r = await execute(oneshot(["echo", "hi"]), {});
    assert.equal(r.results.raw_output, "hi\n");
  });

  it("an unresolvable binary names the binary and the search path", () => {
    assert.throws(
      () => resolveBinary("toolclad-no-such-binary"),
      new RegExp(`'toolclad-no-such-binary' on PATH ${FIXED_PATH}`)
    );
  });

  it("a basename mismatch against tool.binary is a load error", () => {
    const path = writeTmp(`${head('binary = "whois"')}
[command]
exec = ["echo", "x"]
${tail}`);
    assert.throws(
      () => loadManifest(path),
      /command argv\[0\] 'echo' does not match tool\.binary 'whois'/
    );
  });

  it("a matching basename with a path loads", () => {
    const path = writeTmp(`${head('binary = "echo"')}
[command]
exec = ["/usr/bin/echo", "x"]
${tail}`);
    assert.doesNotThrow(() => loadManifest(path));
  });

  it("bash as argv[0] needs allow_interpreter", () => {
    const body = `
[command]
exec = ["bash", "--version"]
${tail}`;
    assert.throws(
      () => loadManifest(writeTmp(`${head('binary = "bash"')}${body}`)),
      /command argv\[0\] 'bash' is an interpreter; set allow_interpreter = true to permit it/
    );
    assert.doesNotThrow(() =>
      loadManifest(writeTmp(`${head('binary = "bash"\nallow_interpreter = true')}${body}`))
    );
  });

  it("an interpreter executor is refused too", () => {
    const m = {
      tool: { name: "t", description: "d" },
      command: { executor: "/bin/sh" },
      output: { format: "text" },
    };
    assert.throws(() => compileCommand(m), /'\/bin\/sh' is an interpreter/);
  });

  it("callback dispatch skips the checks", () => {
    const m = oneshot(["sh"], { tool: { dispatch: "callback", binary: "other" } });
    assert.doesNotThrow(() => compileCommand(m));
  });
});

// --- stdin and cwd ---------------------------------------------------------

describe("stdin and working directory", () => {
  it("stdin is /dev/null: cat with no arguments exits at once", async () => {
    const start = Date.now();
    const r = await execute(oneshot(["cat"], { tool: { timeout_seconds: 5 } }), {});
    assert.equal(r.status, "success");
    assert.equal(r.results.raw_output, "");
    assert.ok(Date.now() - start < 3000);
  });

  it("cwd is <evidence>/<scan_id>-work and is removed when empty", async () => {
    const r = await execute(oneshot(["pwd"]), {});
    const work = join(evidenceRoot, `${r.scan_id}-work`);
    assert.equal(r.results.raw_output.trim(), work);
    assert.equal(existsSync(work), false);
  });

  it("a scratch directory the tool wrote to is kept, mode 0700", async () => {
    const r = await execute(oneshot(["touch", "relative-file"]), {});
    assert.equal(r.status, "success", r.stderr);
    const work = join(evidenceRoot, `${r.scan_id}-work`);
    assert.ok(existsSync(join(work, "relative-file")));
    assert.equal(statSync(work).mode & 0o777, 0o700);
  });
});

// --- evidence paths --------------------------------------------------------

describe("evidence paths", () => {
  it("_output_file follows the table and its directory exists 0700 before the spawn", async () => {
    const m = oneshot(["stat", "-c", "%a %F", "{_output_file}", "{_evidence_dir}"], {
      tool: { name: "ev" },
      output: { format: "json" },
    });
    const dry = await execute(m, {}, { dryRun: true });
    assert.match(dry.scan_id, SCAN_ID_RE);
    assert.equal(dry.argv[3], join(evidenceRoot, `${dry.scan_id}-ev`, "scan.json"));

    const r = await execute(m, {});
    const outputDir = join(evidenceRoot, `${r.scan_id}-ev`);
    assert.equal(r.command.split(" ")[4], join(outputDir, "scan.json"));
    // The tool saw a pre-created 0600 regular file and the 0700 root.
    assert.deepEqual(r.results.raw_output.trim().split("\n"), [
      "600 regular empty file",
      "700 directory",
    ]);
    assert.equal(statSync(outputDir).mode & 0o777, 0o700);
  });

  it("[tool.evidence] output_dir is honored", async () => {
    const m = oneshot(["echo", "{_output_file}"], {
      tool: { evidence: { output_dir: "{evidence_dir}/custom-{scan_id}" } },
      output: { format: "jsonl" },
    });
    const r = await execute(m, {});
    const expected = join(evidenceRoot, `custom-${r.scan_id}`, "scan.jsonl");
    assert.equal(r.results.raw_output.trim(), expected);
    assert.ok(existsSync(expected));
    assert.equal(statSync(dirname(expected)).mode & 0o777, 0o700);
  });

  it("unknown formats use .txt and consecutive scan ids differ", async () => {
    const m = oneshot(["echo", "{_output_file}"]);
    const a = await execute(m, {});
    const b = await execute(m, {});
    assert.match(a.scan_id, SCAN_ID_RE);
    assert.match(b.scan_id, SCAN_ID_RE);
    assert.notEqual(a.scan_id, b.scan_id);
    assert.notEqual(a.scan_id.split("-")[1], b.scan_id.split("-")[1]);
    assert.ok(a.results.raw_output.trim().endsWith("/scan.txt"));
  });

  it("a pre-planted symlink at the output file is refused, not followed", async () => {
    const outputDir = join(evidenceRoot, "fixed");
    mkdirSync(outputDir, { recursive: true, mode: 0o700 });
    const target = join(tmp(), "victim");
    symlinkSync(target, join(outputDir, "scan.txt"));
    const m = oneshot(["true"], { tool: { evidence: { output_dir: "{evidence_dir}/fixed" } } });
    await assert.rejects(() => execute(m, {}), /symbolic link/);
    assert.equal(existsSync(target), false);
  });

  it("a symlinked evidence directory is refused", () => {
    const real = tmp();
    const link = join(tmp(), "link");
    symlinkSync(real, link);
    assert.throws(() => ensurePrivateDir(link), /symbolic link/);
  });
});

// --- timeouts --------------------------------------------------------------

/** Pids whose command line contains `marker`, via /proc (Linux). */
function pidsWithMarker(marker) {
  const found = [];
  for (const entry of readdirSync("/proc")) {
    if (!/^\d+$/.test(entry)) continue;
    try {
      if (readFileSync(`/proc/${entry}/cmdline`, "utf-8").includes(marker)) found.push(entry);
    } catch {
      // Process exited while scanning.
    }
  }
  return found;
}

describe("timeouts", () => {
  useEnv(() => ({ TOOLCLAD_KILL_GRACE_MS: "200" }));

  it("a sleep past the deadline returns status timeout within about 1 s + grace", async (t) => {
    const marker = "10.4242";
    const start = Date.now();
    const r = await execute(oneshot(["sleep", marker], { tool: { timeout_seconds: 1 } }), {});
    const elapsed = Date.now() - start;
    assert.equal(r.status, "timeout");
    assert.equal(r.exit_code, -1);
    assert.ok(elapsed < 5000, `took ${elapsed} ms`);
    if (!existsSync("/proc/self/cmdline")) {
      t.skip("no /proc to check for the child");
      return;
    }
    assert.deepEqual(pidsWithMarker(marker), [], "the sleep is still running");
  });

  it("partial output captured before the kill is kept", async () => {
    const file = join(tmp(), "lines.txt");
    writeFileSync(file, "partial line\n");
    const r = await execute(
      oneshot(["tail", "-n", "+1", "-f", file], { tool: { timeout_seconds: 1 } }),
      {}
    );
    assert.equal(r.status, "timeout");
    assert.equal(r.results.raw_output, "partial line\n");
  });

  it("a child that ignores SIGTERM is killed after the grace period", async () => {
    const script =
      "process.on('SIGTERM',()=>{});console.log('ignoring');setInterval(()=>{},1000)";
    const m = oneshot([process.execPath, "-e", script], {
      tool: { timeout_seconds: 1, allow_interpreter: true },
    });
    const start = Date.now();
    const r = await execute(m, {});
    assert.equal(r.status, "timeout");
    assert.equal(r.results.raw_output, "ignoring\n");
    assert.ok(Date.now() - start < 5000);
  });

  it("timeout_seconds = 0 is refused at load and before execution", async () => {
    const path = writeTmp(`[tool]
name = "t"
binary = "echo"
description = "d"
timeout_seconds = 0

[command]
exec = ["echo"]

[output]
format = "text"
`);
    assert.throws(() => loadManifest(path), /timeout_seconds must be greater than zero/);
    await assert.rejects(
      () => execute(oneshot(["echo"], { tool: { timeout_seconds: -1 } }), {}),
      /timeout_seconds must be greater than zero/
    );
  });

  it("execute() returns a Promise and executeSync throws the removal message", async () => {
    const p = execute(oneshot(["echo"]), {}, { dryRun: true });
    assert.ok(p instanceof Promise);
    await p;
    assert.throws(
      () => executeSync(oneshot(["echo"]), {}),
      /^Error: executeSync was removed: execute\(\) is async; await execute\(\.\.\.\)$/
    );
  });

  it("cli run awaits execution and prints the envelope", () => {
    const path = writeTmp(`[tool]
name = "t"
binary = "echo"
description = "d"

[args.msg]
type = "string"
required = true

[command]
exec = ["echo", "{msg}"]

[output]
format = "text"
`);
    const cli = join(dirname(fileURLToPath(import.meta.url)), "..", "src", "cli.js");
    const r = spawnSync(process.execPath, [cli, "run", path, "--arg", "msg=hello"], {
      encoding: "utf-8",
      env: { ...process.env, TOOLCLAD_EVIDENCE_DIR: evidenceRoot },
    });
    assert.equal(r.status, 0, r.stderr);
    const envelope = JSON.parse(r.stdout);
    assert.equal(envelope.status, "success");
    assert.equal(envelope.results.raw_output, "hello\n");
  });
});
