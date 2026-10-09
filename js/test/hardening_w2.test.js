import { describe, it, mock } from "node:test";
import assert from "node:assert/strict";
import { writeFileSync, mkdtempSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import TOML from "@iarna/toml";
import {
  loadManifest,
  loadManifestWithOptions,
  findUnknownKeys,
} from "../src/manifest.js";
import { execute, executeMcp } from "../src/executor.js";

// Tests in this file never run a network tool: commands are echo, dry runs,
// or pure load-time assertions. The CLI tests spawn node on the local CLI
// only.

const CLI = fileURLToPath(new URL("../src/cli.js", import.meta.url));

function writeTmp(content) {
  const dir = mkdtempSync(join(tmpdir(), "toolclad-w2-"));
  const path = join(dir, "test.clad.toml");
  writeFileSync(path, content);
  return path;
}

function silenceWarn(t) {
  const m = mock.method(console, "warn", () => {});
  t.after(() => m.mock.restore());
  return m;
}

function execManifest(exec, args) {
  return {
    tool: { name: "t", binary: "echo", description: "d" },
    args,
    command: { exec },
    output: { format: "text" },
  };
}

const TOOL_HEAD = `
[tool]
name = "t"
binary = "echo"
description = "d"
`;
const ARGS = `
[args.target]
position = 1
required = true
type = "string"
description = "t"
`;
const COMMAND = `
[command]
exec = ["echo", "{target}"]
`;
const OUTPUT = `
[output]
format = "text"
`;
const BASE = TOOL_HEAD + ARGS + COMMAND + OUTPUT;

// The normative allowlist, transcribed independently of src/manifest.js so a
// key dropped from either copy fails a test here.
const W2 = {
  tool: "name version binary description timeout_seconds risk_tier human_approval dispatch mode network_egress allow_interpreter cedar evidence limits",
  "tool.cedar": "resource action",
  "tool.evidence": "output_dir capture hash screenshots",
  "tool.limits": "nproc nofile fsize_bytes address_space_bytes cpu_seconds",
  args: "position required type description default allowed pattern sanitize min max min_float max_float clamp schemes scope_check block_internal allow_leading_dash allow_whitespace",
  command: "template exec executor defaults mappings conditionals end_of_options",
  "command.conditionals": "when template",
  output: "format parser envelope schema max_bytes",
  http: "method url headers body_template success_status error_status",
  mcp: "server tool field_map",
  session: "startup_command ready_pattern startup_timeout_seconds idle_timeout_seconds session_timeout_seconds max_interactions interaction commands child_detection",
  "session.interaction": "input_sanitize output_max_bytes output_wait_ms",
  "session.commands": "pattern description risk_tier human_approval extract_target args",
  "session.child_detection": "pattern type manifest",
  browser: "engine headless connect extract_mode startup_timeout_seconds session_timeout_seconds idle_timeout_seconds max_interactions scope commands state defaults",
  "browser.defaults": "extract_mode",
  "browser.scope": "allowed_domains blocked_domains allow_external",
  "browser.commands": "description risk_tier human_approval args",
  "browser.state": "fields",
};

function sortedKeys(table) {
  return Object.keys(table).sort();
}

function unionKeys(tables) {
  return [...new Set(Object.values(tables).flatMap(Object.keys))].sort();
}

function assertCovers(actual, section) {
  assert.deepEqual(actual, W2[section].split(" ").sort(), `[${section}] keys`);
}

// --- W2 unknown keys are refused ----------------------------------------------

describe("W2 unknown keys - refused at load", () => {
  it("refuses tiemout_seconds in [tool] and names the key", () => {
    const path = writeTmp(`${TOOL_HEAD}tiemout_seconds = 5\n${ARGS}${COMMAND}${OUTPUT}`);
    assert.throws(
      () => loadManifest(path),
      /^Error: unknown key 'tool\.tiemout_seconds' in manifest$/
    );
  });

  it("refuses an unknown [args.<n>] key with the concrete path", () => {
    const path = writeTmp(`${TOOL_HEAD}${ARGS}block_internal_typo = true\n${COMMAND}${OUTPUT}`);
    assert.throws(
      () => loadManifest(path),
      /^Error: unknown key 'args\.target\.block_internal_typo' in manifest$/
    );
  });

  it("refuses an unknown [command] key", () => {
    const path = writeTmp(`${TOOL_HEAD}${ARGS}${COMMAND}templte = "echo"\n${OUTPUT}`);
    assert.throws(
      () => loadManifest(path),
      /^Error: unknown key 'command\.templte' in manifest$/
    );
  });

  it("refuses an unknown [output] key", () => {
    const path = writeTmp(`${TOOL_HEAD}${ARGS}${COMMAND}${OUTPUT}formt = "json"\n`);
    assert.throws(
      () => loadManifest(path),
      /^Error: unknown key 'output\.formt' in manifest$/
    );
  });

  it("refuses an unknown [http] key", () => {
    const path = writeTmp(`${TOOL_HEAD}${ARGS}
[http]
method = "GET"
url = "https://api.example.com/{target}"
methd = "POST"
${OUTPUT}`);
    assert.throws(
      () => loadManifest(path),
      /^Error: unknown key 'http\.methd' in manifest$/
    );
  });

  it("refuses an unknown [command.conditionals.<n>] key with the concrete path", () => {
    const path = writeTmp(`${TOOL_HEAD}${ARGS}
[args.rate]
position = 2
required = false
type = "integer"
default = 100

[command]
exec = ["echo", "{_rate_flag}", "{target}"]

[command.conditionals.rate_flag]
when = "rate != '100'"
template = "--rate {rate}"
whenn = "x"
${OUTPUT}`);
    assert.throws(
      () => loadManifest(path),
      /^Error: unknown key 'command\.conditionals\.rate_flag\.whenn' in manifest$/
    );
  });

  it("refuses an unknown top-level section", () => {
    const path = writeTmp(`${BASE}
[toool]
name = "x"
`);
    assert.throws(() => loadManifest(path), /^Error: unknown key 'toool' in manifest$/);
  });

  it("reports every unknown key in one sorted message", () => {
    const path = writeTmp(`${TOOL_HEAD}tiemout_seconds = 5
${ARGS}block_internal_typo = true

[args.rate]
position = 2
required = false
type = "integer"
default = 100

[command]
exec = ["echo", "{_rate_flag}", "{target}"]

[command.conditionals.rate_flag]
when = "rate != '100'"
template = "--rate {rate}"
whenn = "x"

[output]
format = "text"
formt = "json"
`);
    assert.throws(
      () => loadManifest(path),
      (err) => {
        assert.equal(
          err.message,
          "unknown key 'args.target.block_internal_typo' in manifest; " +
            "unknown key 'command.conditionals.rate_flag.whenn' in manifest; " +
            "unknown key 'output.formt' in manifest; " +
            "unknown key 'tool.tiemout_seconds' in manifest"
        );
        return true;
      }
    );
  });

  it("runs the key check before structural validation", () => {
    // No [command] and no [output], yet the unknown key is what is reported.
    const path = writeTmp(`${TOOL_HEAD}tiemout_seconds = 5\n`);
    assert.throws(
      () => loadManifest(path),
      /^Error: unknown key 'tool\.tiemout_seconds' in manifest$/
    );
  });
});

// --- W2 escape hatch ----------------------------------------------------------

describe("W2 unknown keys - allowUnknownKeys escape hatch", () => {
  const content = `${TOOL_HEAD}tiemout_seconds = 5\n${ARGS}block_internal_typo = true\n${COMMAND}${OUTPUT}`;

  it("loadManifestWithOptions downgrades to warnings and loads", (t) => {
    const warn = silenceWarn(t);
    const path = writeTmp(content);
    const m = loadManifestWithOptions(path, { allowUnknownKeys: true });
    assert.equal(m.tool.name, "t");
    assert.deepEqual(
      warn.mock.calls.map((c) => c.arguments[0]),
      [
        "warning: unknown key 'args.target.block_internal_typo' in manifest",
        "warning: unknown key 'tool.tiemout_seconds' in manifest",
      ]
    );
  });

  it("loadManifestWithOptions defaults to strict", () => {
    const path = writeTmp(content);
    assert.throws(() => loadManifestWithOptions(path), /unknown key 'tool\.tiemout_seconds'/);
    assert.throws(() => loadManifestWithOptions(path, {}), /unknown key 'tool\.tiemout_seconds'/);
  });

  it("loadManifest stays strict", () => {
    const path = writeTmp(content);
    assert.throws(() => loadManifest(path), /unknown key 'tool\.tiemout_seconds'/);
  });

  it("CLI validate fails on an unknown key and --allow-unknown-keys warns instead", () => {
    const path = writeTmp(content);

    const strict = spawnSync(process.execPath, [CLI, "validate", path], { encoding: "utf-8" });
    assert.equal(strict.status, 1);
    assert.match(strict.stderr, /unknown key 'tool\.tiemout_seconds' in manifest/);

    const lenient = spawnSync(
      process.execPath,
      [CLI, "validate", path, "--allow-unknown-keys"],
      { encoding: "utf-8" }
    );
    assert.equal(lenient.status, 0, lenient.stderr);
    assert.match(lenient.stdout, /OK {2}\(tool: t\)/);
    assert.match(lenient.stderr, /^warning: unknown key 'args\.target\.block_internal_typo' in manifest$/m);
    assert.match(lenient.stderr, /^warning: unknown key 'tool\.tiemout_seconds' in manifest$/m);
  });
});

// --- W2 every known key is accepted -------------------------------------------

describe("W2 allowlist - every normative key loads", () => {
  it("accepts every [tool]/[tool.*]/[args.*]/[command]/[output] key", () => {
    const path = writeTmp(`
[tool]
name = "full"
version = "1.0.0"
binary = "echo"
description = "every oneshot key"
timeout_seconds = 30
risk_tier = "low"
human_approval = false
dispatch = "exec"
mode = "oneshot"
network_egress = true
allow_interpreter = true

[tool.cedar]
resource = "Tool::Full"
action = "execute_tool"

[tool.evidence]
output_dir = "{evidence_dir}/{scan_id}-full"
capture = true
hash = "sha256"
screenshots = true

[tool.limits]
nproc = 64
nofile = 256
fsize_bytes = 1048576
address_space_bytes = 536870912
cpu_seconds = 60

[args.target]
position = 1
required = true
type = "string"
description = "target"
pattern = "^[a-z.]+$"
sanitize = ["injection"]
scope_check = false
block_internal = true
allow_leading_dash = false
allow_whitespace = false

[args.port]
position = 2
required = false
type = "integer"
description = "port"
default = 80
min = 1
max = 65535
clamp = true

[args.ratio]
position = 3
required = false
type = "float"
description = "ratio"
default = 0.5
min_float = 0.0
max_float = 1.0

[args.url]
position = 4
required = false
type = "url"
description = "url"
schemes = ["https"]
block_internal = true

[args.speed]
position = 5
required = false
type = "enum"
description = "speed"
allowed = ["fast", "slow"]
default = "fast"

[command]
template = "echo {target}"
exec = ["echo", "{_speed_flags}", "{_rate_flag}", "{target}", "{port}", "{rate}"]
executor = "scripts/wrapper.sh"
end_of_options = "--"

[command.defaults]
rate = "100"

[command.mappings.speed]
fast = "-f"
slow = "-s"

[command.conditionals.rate_flag]
when = "rate != '100'"
template = "--rate {rate}"

[output]
format = "json"
parser = "builtin:json"
envelope = true
max_bytes = 1024

[output.schema]
type = "object"

[output.schema.properties.raw_output]
type = "string"
`);
    const m = loadManifest(path);

    assertCovers(sortedKeys(m.tool), "tool");
    assertCovers(sortedKeys(m.tool.cedar), "tool.cedar");
    assertCovers(sortedKeys(m.tool.evidence), "tool.evidence");
    assertCovers(sortedKeys(m.tool.limits), "tool.limits");
    assertCovers(unionKeys(m.args), "args");
    assertCovers(sortedKeys(m.command), "command");
    assertCovers(unionKeys(m.command.conditionals), "command.conditionals");
    assertCovers(sortedKeys(m.output), "output");

    assert.equal(m.tool.mode, "oneshot");
    assert.equal(m.tool.network_egress, true);
    assert.equal(m.tool.allow_interpreter, true);
    assert.equal(m.tool.evidence.screenshots, true);
    assert.equal(m.tool.limits.cpu_seconds, 60);
    assert.equal(m.output.max_bytes, 1024);
    // Open maps keep their author-chosen keys untouched.
    assert.equal(m.command.defaults.rate, "100");
    assert.equal(m.command.mappings.speed.slow, "-s");
    assert.equal(m.output.schema.properties.raw_output.type, "string");
  });

  it("accepts every [session]/[session.*] key", () => {
    const path = writeTmp(`
[tool]
name = "s"
description = "session"
mode = "session"

[session]
startup_command = "cat"
ready_pattern = "^> $"
startup_timeout_seconds = 5
idle_timeout_seconds = 60
session_timeout_seconds = 600
max_interactions = 10

[session.interaction]
input_sanitize = ["injection"]
output_max_bytes = 65536
output_wait_ms = 200

[session.commands.select]
pattern = "^SELECT .+$"
description = "select"
risk_tier = "low"
human_approval = false
extract_target = "rows"

[session.commands.select.args.table]
type = "string"
required = true

[session.child_detection]
pattern = "^\\\\$ $"
type = "shell"
manifest = "child.clad.toml"

[output]
format = "text"
`);
    const m = loadManifest(path);
    assertCovers(sortedKeys(m.session), "session");
    assertCovers(sortedKeys(m.session.interaction), "session.interaction");
    assertCovers(unionKeys(m.session.commands), "session.commands");
    assertCovers(sortedKeys(m.session.child_detection), "session.child_detection");
    assert.equal(m.tool.mode, "session");
    assert.equal(m.session.commands.select.args.table.type, "string");
  });

  it("accepts every [browser]/[browser.*] key", () => {
    const path = writeTmp(`
[tool]
name = "b"
description = "browser"
mode = "browser"

[browser]
engine = "cdp"
headless = true
connect = "launch"
extract_mode = "accessibility_tree"
startup_timeout_seconds = 10
session_timeout_seconds = 600
idle_timeout_seconds = 60
max_interactions = 100

[browser.defaults]
extract_mode = "text"

[browser.scope]
allowed_domains = ["*.example.com"]
blocked_domains = ["evil.example.com"]
allow_external = false

[browser.commands.navigate]
description = "navigate"
risk_tier = "medium"
human_approval = false

[browser.commands.navigate.args.url]
type = "url"
required = true

[browser.state]
fields = ["url", "title"]

[output]
format = "json"
`);
    const m = loadManifest(path);
    assertCovers(sortedKeys(m.browser), "browser");
    assertCovers(sortedKeys(m.browser.defaults), "browser.defaults");
    assertCovers(sortedKeys(m.browser.scope), "browser.scope");
    assertCovers(unionKeys(m.browser.commands), "browser.commands");
    assertCovers(sortedKeys(m.browser.state), "browser.state");
    assert.equal(m.tool.mode, "browser");
    assert.equal(m.browser.commands.navigate.args.url.type, "url");
  });

  it("accepts every [http] key, with headers as an open map", () => {
    const path = writeTmp(`
[tool]
name = "h"
description = "http"

[args.q]
type = "string"
required = true

[http]
method = "GET"
url = "https://api.example.com/search?q={q}"
body_template = ""
success_status = [200]
error_status = [500]

[http.headers]
Accept = "application/json"
X-Custom = "{q}"

[output]
format = "json"
`);
    const m = loadManifest(path);
    assertCovers(sortedKeys(m.http), "http");
    assert.equal(m.http.headers["X-Custom"], "{q}");
  });

  it("accepts every [mcp] key, with field_map as an open map", () => {
    const path = writeTmp(`
[tool]
name = "m"
description = "mcp"

[args.target]
type = "string"
required = true

[mcp]
server = "scanner"
tool = "scan"

[mcp.field_map]
target = "host"
`);
    const m = loadManifest(path);
    assertCovers(sortedKeys(m.mcp), "mcp");
    assert.equal(m.mcp.field_map.target, "host");
  });

  it("findUnknownKeys leaves open maps and opaque data alone", () => {
    const parsed = TOML.parse(`
[tool]
name = "t"

[command.defaults]
anything_goes = "1"

[command.mappings.scan]
whatever = "-x"

[output.schema.properties.deep.items.properties.nested]
type = "string"

[http.headers]
X-Anything = "v"

[mcp.field_map]
ours = "theirs"

[session.commands.c.args.a]
unchecked = true

[browser.commands.c.args.a]
unchecked = true
`);
    assert.deepEqual(findUnknownKeys(parsed), []);
  });

  it("findUnknownKeys flags every unknown key and nothing else", () => {
    const parsed = TOML.parse(`
[tool]
name = "t"
bogus = 1

[tool.cedar]
resource = "r"
actoin = "a"

[args.x]
type = "string"
tpye = "string"

[browser.scope]
allowed_domains = []
allowed_domain = []
`);
    assert.deepEqual(findUnknownKeys(parsed), [
      "args.x.tpye",
      "browser.scope.allowed_domain",
      "tool.bogus",
      "tool.cedar.actoin",
    ]);
  });
});

// --- W2 tool.mode and inert defaults ------------------------------------------

describe("W2 tool.mode", () => {
  it("derives oneshot when absent and no backend section is present", () => {
    const m = loadManifest(writeTmp(BASE));
    assert.equal(m.tool.mode, "oneshot");
  });

  it("derives session and browser from the backend section", () => {
    const s = loadManifest(
      writeTmp(`${TOOL_HEAD}\n[session]\nstartup_command = "cat"\n${OUTPUT}`)
    );
    assert.equal(s.tool.mode, "session");
    const b = loadManifest(
      writeTmp(`${TOOL_HEAD}\n[browser]\nengine = "cdp"\n${OUTPUT}`)
    );
    assert.equal(b.tool.mode, "browser");
  });

  it("keeps an explicit mode", () => {
    const m = loadManifest(writeTmp(`${TOOL_HEAD}mode = "oneshot"\n${ARGS}${COMMAND}${OUTPUT}`));
    assert.equal(m.tool.mode, "oneshot");
  });

  it("refuses an invalid mode value", () => {
    const path = writeTmp(`${TOOL_HEAD}mode = "batch"\n${ARGS}${COMMAND}${OUTPUT}`);
    assert.throws(
      () => loadManifest(path),
      /^Error: Invalid manifest: invalid tool\.mode 'batch', must be one of oneshot, session, browser$/
    );
  });
});

describe("W2 registered keys - inert defaults", () => {
  it("defaults network_egress, allow_interpreter and output.max_bytes", () => {
    const m = loadManifest(writeTmp(BASE));
    assert.equal(m.tool.network_egress, false);
    assert.equal(m.tool.allow_interpreter, false);
    assert.equal(m.output.max_bytes, 8388608);
    assert.equal(m.tool.evidence, undefined);
    assert.equal(m.tool.limits, undefined);
  });

  it("defaults tool.evidence.screenshots when [tool.evidence] is present", () => {
    const m = loadManifest(
      writeTmp(`${TOOL_HEAD}\n[tool.evidence]\ncapture = true\n${ARGS}${COMMAND}${OUTPUT}`)
    );
    assert.equal(m.tool.evidence.screenshots, false);
  });

  it("refuses a non-boolean network_egress", () => {
    const path = writeTmp(`${TOOL_HEAD}network_egress = "yes"\n${ARGS}${COMMAND}${OUTPUT}`);
    assert.throws(() => loadManifest(path), /tool\.network_egress must be a boolean/);
  });

  it("refuses a non-integer output.max_bytes and tool.limits value", () => {
    assert.throws(
      () => loadManifest(writeTmp(`${TOOL_HEAD}${ARGS}${COMMAND}${OUTPUT}max_bytes = "8MB"\n`)),
      /output\.max_bytes must be an integer/
    );
    assert.throws(
      () =>
        loadManifest(
          writeTmp(`${TOOL_HEAD}\n[tool.limits]\nnproc = "many"\n${ARGS}${COMMAND}${OUTPUT}`)
        ),
      /tool\.limits\.nproc must be an integer/
    );
  });
});

// --- Unknown argument names at call time --------------------------------------

describe("unknown argument names at call time", () => {
  it("dry run refuses an undeclared argument instead of dropping it", () => {
    const m = execManifest(["echo", "{target}"], {
      target: { type: "string", required: true },
    });
    assert.throws(
      () => execute(m, { target: "host", extra_flags: "-iL /etc/passwd" }, { dryRun: true }),
      /^Error: unknown argument 'extra_flags' \(declared arguments: target\)$/
    );
  });

  it("lists the declared arguments sorted", () => {
    const m = execManifest(["echo", "{b}", "{a}"], {
      b: { type: "string", required: true },
      a: { type: "string", required: true },
    });
    assert.throws(
      () => execute(m, { a: "1", b: "2", zzz: "3" }, { dryRun: true }),
      /^Error: unknown argument 'zzz' \(declared arguments: a, b\)$/
    );
  });

  it("applies to the MCP proxy backend", () => {
    const m = {
      tool: { name: "m", description: "d" },
      args: { target: { type: "string", required: true } },
      mcp: { server: "s", tool: "t" },
    };
    assert.throws(
      () => executeMcp(m, { target: "host", bogus: "x" }),
      /^Error: unknown argument 'bogus' \(declared arguments: target\)$/
    );
  });

  it("still runs when every supplied argument is declared", () => {
    const m = execManifest(["echo", "{target}"], {
      target: { type: "string", required: true },
    });
    const r = execute(m, { target: "host" }, { dryRun: true });
    assert.equal(r.status, "dry_run");
    assert.deepEqual(r.argv, ["echo", "host"]);
  });
});
