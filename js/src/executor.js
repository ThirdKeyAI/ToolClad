import { spawn } from "node:child_process";
import { randomBytes, createHash } from "node:crypto";
import {
  accessSync,
  chmodSync,
  closeSync,
  constants as fsConstants,
  fstatSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  rmdirSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { isAbsolute, join, resolve as resolvePath } from "node:path";
import TOML from "@iarna/toml";
import { validateArgIn } from "./validator.js";
import { scopeForManifest } from "./scope.js";

/** Same symbol manifest.js uses for the manifest's custom type map. */
const CUSTOM_TYPES = Symbol.for("toolclad.customTypes");
import { validateJsonSchema } from "./schema.js";
import { parseCanonicalIp, enforceIpPolicy, internalNameReason, embeddedIpv4Literal } from "./hostpolicy.js";

/**
 * One left-to-right pass over a token: `{{` and `}}` are escapes for literal
 * braces and `{name}` is a placeholder. Escapes are never placeholders.
 */
const BRACE_PASS_RE = /\{\{|\}\}|\{(\w+)\}/g;

/** A token that consists solely of one placeholder. */
const WHOLE_PLACEHOLDER_RE = /^\{(\w+)\}$/;

/** Variables the executor injects into every command context. */
const EXECUTOR_VARS = ["_scan_id", "_output_file", "_evidence_dir"];

const TEMPLATE_DEPRECATION_WARNING =
  "warning: [command] template is deprecated and will be removed in the next minor release; use exec = [...]";

/**
 * Binaries that connect to a network destination derived from their
 * arguments — the ones for which an unconstrained target is an SSRF surface.
 * Kept identical to the Rust runtime's list so the lint reads the same in
 * every runtime; it is deliberately not extended here.
 */
export const EGRESS_BINARIES = Object.freeze([
  "curl",
  "wget",
  "nmap",
  "nc",
  "ncat",
  "netcat",
  "masscan",
  "telnet",
  "ssh",
  "ping",
  "fping",
  "httpie",
  "http",
  "wfuzz",
  "ffuf",
  "hydra",
  "nikto",
]);

/** Argument types whose value names a network target. */
const NETWORK_TARGET_TYPES = new Set(["scope_target", "url", "ip_address", "cidr"]);

/** The last path component of a command, lowercased (`/usr/bin/Curl` → `curl`). */
function commandBasename(command) {
  const parts = String(command).split(/[/\\]/);
  return parts[parts.length - 1].toLowerCase();
}

/**
 * True if the manifest describes a tool that reaches the network: the author
 * declared `tool.network_egress = true`, the backend is `[http]` or
 * `[browser]`, or the dispatched binary — `tool.binary`, `exec[0]`, or the
 * template's first token — is one of EGRESS_BINARIES.
 *
 * An `executor`-only manifest cannot be inspected for a binary: the script
 * may run anything. It is an egress manifest only when the author says so
 * (`network_egress = true`) or uses `[http]` / `[browser]`. That escape
 * hatch is the author's responsibility.
 *
 * @param {object} manifest - Parsed or in-memory manifest
 * @returns {boolean}
 */
export function isEgressManifest(manifest) {
  const tool = manifest.tool || {};
  if (tool.network_egress === true) return true;
  if (manifest.http || manifest.browser) return true;

  const command = manifest.command || {};
  const names = [];
  if (typeof tool.binary === "string" && tool.binary !== "") {
    names.push(commandBasename(tool.binary));
  }
  if (Array.isArray(command.exec) && command.exec.length > 0) {
    names.push(commandBasename(command.exec[0]));
  }
  if (typeof command.template === "string") {
    const first = command.template.trim().split(/\s+/)[0];
    if (first) names.push(commandBasename(first));
  }
  return names.some((name) => EGRESS_BINARIES.includes(name));
}

/**
 * Egress lint (TC-15), applied at load and before any in-memory build. For
 * an egress manifest every argument whose type names a network target must
 * set `block_internal = true`, so internal / SSRF addresses are denied by
 * default rather than by the author remembering. When the custom type map
 * is available, an argument whose custom type has a network-target base is
 * refused outright: a custom type definition cannot carry `block_internal`.
 *
 * @param {object} manifest - Parsed or in-memory manifest
 * @param {object} [customTypes] - Map of custom type name to definition
 * @throws {Error} naming the first offending argument
 */
export function lintNetworkEgress(manifest, customTypes) {
  if (!isEgressManifest(manifest)) return;
  for (const [name, def] of Object.entries(manifest.args || {})) {
    if (!def || typeof def !== "object") continue;
    const type = def.type;
    if (NETWORK_TARGET_TYPES.has(type)) {
      if (def.block_internal !== true) {
        throw new Error(
          `argument '${name}' is a network target for an egress binary but block_internal is not set; set block_internal = true to default-deny internal/SSRF targets`
        );
      }
      continue;
    }
    if (customTypes && Object.hasOwn(customTypes, type)) {
      const base = customTypes[type].base;
      if (NETWORK_TARGET_TYPES.has(base)) {
        throw new Error(
          `argument '${name}' uses custom type '${type}' as a network target; custom types cannot carry block_internal — use the built-in ${base} type`
        );
      }
    }
  }
}

/**
 * The fixed PATH every child receives and against which a bare `argv[0]` is
 * resolved. Never inherited: an inherited PATH is how a renamed binary that
 * appears earlier in the search path wins.
 */
export const FIXED_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/** Parent variables copied into the child environment, only when set. */
const PASSTHROUGH_ENV = ["HOME", "LANG", "LC_ALL", "TZ", "TERM"];

/**
 * `argv[0]` basenames refused at load unless `[tool] allow_interpreter = true`:
 * each one turns a validated argument into code.
 */
export const INTERPRETER_BINARIES = Object.freeze([
  "sh", "bash", "zsh", "dash", "ksh", "csh", "tcsh", "fish", "ash", "busybox",
  "env", "eval", "xargs", "python", "python2", "python3", "perl", "ruby",
  "node", "deno", "bun", "lua", "php", "awk",
]);

const DEFAULT_TIMEOUT_SECONDS = 60;
const DEFAULT_KILL_GRACE_MS = 2000;
/** Default `[output] max_bytes`: 8 MiB for stdout and for stderr, each. */
export const DEFAULT_OUTPUT_MAX_BYTES = 8388608;
/** Upper bound for `[output] max_bytes`: 1 GiB. */
export const OUTPUT_MAX_BYTES_LIMIT = 1073741824;

/** The `builtin:*` output parsers; any other `parser` value is refused. */
export const BUILTIN_PARSERS = Object.freeze([
  "builtin:json",
  "builtin:jsonl",
  "builtin:csv",
  "builtin:xml",
  "builtin:text",
]);

/**
 * Build a child environment from the allowlist: the fixed PATH, plus HOME,
 * LANG, LC_ALL, TZ and TERM when the parent has them, plus `extra`.
 * `TOOLCLAD_SECRET_*` is filtered out last, so no edit to the allowlist or to
 * `extra` can hand a secret to a child.
 *
 * @param {object} [extra] - Additional variables (executor hatch only)
 * @returns {object} The complete child environment
 */
export function buildChildEnv(extra = {}) {
  const env = { PATH: FIXED_PATH };
  for (const name of PASSTHROUGH_ENV) {
    if (process.env[name] !== undefined) env[name] = process.env[name];
  }
  Object.assign(env, extra);
  for (const name of Object.keys(env)) {
    if (name.startsWith("TOOLCLAD_SECRET_")) delete env[name];
  }
  return env;
}

/**
 * Read `TOOLCLAD_SECRETS_FILE`: a TOML file of top-level `name = "value"`
 * pairs. Refused when group or others can read it — that check is what makes
 * the file better than an environment variable.
 *
 * @param {string} path
 * @returns {object} name -> value
 */
function readSecretsFile(path) {
  const fd = openSync(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  try {
    const mode = fstatSync(fd).mode & 0o777;
    if ((mode & 0o077) !== 0) {
      throw new Error(
        `TOOLCLAD_SECRETS_FILE '${path}' is readable by group or others (mode ${mode.toString(8).padStart(4, "0")}); chmod 600 it`
      );
    }
    const parsed = TOML.parse(readFileSync(fd, "utf-8"));
    const secrets = Object.create(null);
    for (const [name, value] of Object.entries(parsed)) {
      if (typeof value === "string") secrets[name] = value;
    }
    return secrets;
  } finally {
    closeSync(fd);
  }
}

/**
 * A secret resolver for one call. The secrets file, when configured, is read
 * at most once (lazily, on the first reference) and wins over the matching
 * `TOOLCLAD_SECRET_<NAME>` environment variable. A missing secret is an error.
 *
 * @returns {(name: string) => string}
 */
export function makeSecretResolver() {
  const file = process.env.TOOLCLAD_SECRETS_FILE;
  let fileSecrets = null;
  return (name) => {
    if (file) {
      if (fileSecrets === null) fileSecrets = readSecretsFile(file);
      if (Object.hasOwn(fileSecrets, name)) return fileSecrets[name];
    }
    const envKey = `TOOLCLAD_SECRET_${name.toUpperCase()}`;
    const val = process.env[envKey];
    if (val === undefined) {
      const where = file ? ` and no '${name}' entry in TOOLCLAD_SECRETS_FILE` : "";
      throw new Error(`Missing environment variable: ${envKey}${where}`);
    }
    return val;
  };
}

/**
 * Replace {_secret:name} placeholders from TOOLCLAD_SECRETS_FILE or the
 * TOOLCLAD_SECRET_<NAME> environment variable.
 * @param {string} template - Template string with optional {_secret:name} vars
 * @param {(name: string) => string} [resolveSecret] - Resolver shared across one call
 * @returns {string} Template with secrets injected
 */
export function injectTemplateVars(template, resolveSecret = makeSecretResolver()) {
  return template.replace(/\{_secret:(\w+)\}/g, (_match, name) => resolveSecret(name));
}

/** The basename of a command path (separators `/` and `\`), case preserved. */
function rawBasename(command) {
  const parts = String(command).split(/[/\\]/);
  return parts[parts.length - 1];
}

/**
 * Load-time `argv[0]` checks for the exec/template/executor forms: the
 * interpreter denylist, and for exec/template a basename match against a
 * non-empty `tool.binary`. Skipped for callback dispatch.
 */
function checkArgv0(manifest) {
  const tool = manifest.tool || {};
  const command = manifest.command || {};
  if (tool.dispatch === "callback") return;

  let argv0;
  let isExecutor = false;
  if (typeof command.executor === "string" && command.executor !== "") {
    argv0 = command.executor;
    isExecutor = true;
  } else if (Array.isArray(command.exec) && command.exec.length > 0) {
    argv0 = command.exec[0];
  } else {
    return;
  }

  const base = rawBasename(argv0);
  if (INTERPRETER_BINARIES.includes(base) && tool.allow_interpreter !== true) {
    throw new Error(
      `command argv[0] '${argv0}' is an interpreter; set allow_interpreter = true to permit it`
    );
  }
  if (!isExecutor && typeof tool.binary === "string" && tool.binary !== "") {
    if (base !== rawBasename(tool.binary)) {
      throw new Error(
        `command argv[0] '${argv0}' does not match tool.binary '${tool.binary}'`
      );
    }
  }
}

/**
 * `tool.timeout_seconds`, defaulting to 60; zero or negative is refused.
 * @param {object} manifest
 * @returns {number} seconds
 */
export function timeoutSeconds(manifest) {
  const value = (manifest.tool || {}).timeout_seconds;
  if (value === undefined || value === null) return DEFAULT_TIMEOUT_SECONDS;
  if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) {
    throw new Error("timeout_seconds must be greater than zero");
  }
  return value;
}

/**
 * The manifest's `[output] max_bytes` (default 8 MiB). An integer outside
 * 1..=1 GiB is refused here as well as at load, for in-memory manifests.
 *
 * @param {object} manifest
 * @returns {number} bytes
 */
export function outputMaxBytes(manifest) {
  const value = (manifest.output || {}).max_bytes;
  if (value === undefined || value === null) return DEFAULT_OUTPUT_MAX_BYTES;
  if (!Number.isInteger(value) || value < 1 || value > OUTPUT_MAX_BYTES_LIMIT) {
    throw new Error(
      `output.max_bytes must be an integer between 1 and ${OUTPUT_MAX_BYTES_LIMIT}`
    );
  }
  return value;
}

/**
 * Refuse an `[output] parser` that is not one of the `builtin:*` names.
 *
 * @param {object} manifest
 * @throws {Error} on a custom parser
 */
export function checkOutputParser(manifest) {
  const parser = (manifest.output || {}).parser;
  if (parser === undefined || parser === null) return;
  if (!BUILTIN_PARSERS.includes(parser)) {
    throw new Error(
      `custom output parsers are not supported by the reference runtimes (parser = "${parser}")`
    );
  }
}

/** `TOOLCLAD_KILL_GRACE_MS` as a non-negative integer; anything else -> 2000. */
function killGraceMs() {
  const raw = process.env.TOOLCLAD_KILL_GRACE_MS;
  if (raw === undefined || !/^\d+$/.test(raw.trim())) return DEFAULT_KILL_GRACE_MS;
  const n = Number(raw.trim());
  return Number.isSafeInteger(n) ? n : DEFAULT_KILL_GRACE_MS;
}

/** `<unix_seconds>-<32 hex chars>`: 128 bits from a CSPRNG. */
export function newScanId() {
  return `${Math.floor(Date.now() / 1000)}-${randomBytes(16).toString("hex")}`;
}

const OUTPUT_EXTENSIONS = new Set(["xml", "json", "csv", "jsonl"]);

/**
 * The evidence paths for one invocation.
 *
 * - evidenceDir: `TOOLCLAD_EVIDENCE_DIR`, else `<tmpdir>/toolclad-evidence`
 * - outputDir: `[tool.evidence] output_dir` with `{evidence_dir}` and
 *   `{scan_id}` substituted, else `<evidenceDir>/<scanId>-<tool name>`
 * - outputFile: `<outputDir>/scan.<ext>` (`ext` from output.format)
 *
 * @param {object} manifest
 * @param {string} scanId
 * @returns {{ evidenceDir: string, outputDir: string, outputFile: string }}
 */
export function evidencePaths(manifest, scanId) {
  const evidenceDir =
    process.env.TOOLCLAD_EVIDENCE_DIR || join(tmpdir(), "toolclad-evidence");
  const configured = manifest.tool?.evidence?.output_dir;
  const outputDir =
    typeof configured === "string" && configured !== ""
      ? configured
          .replaceAll("{evidence_dir}", evidenceDir)
          .replaceAll("{scan_id}", scanId)
      : join(evidenceDir, `${scanId}-${manifest.tool?.name ?? "tool"}`);
  const format = manifest.output?.format;
  const ext = OUTPUT_EXTENSIONS.has(format) ? format : "txt";
  return { evidenceDir, outputDir, outputFile: join(outputDir, `scan.${ext}`) };
}

/** Refuse a path that exists as a symbolic link. */
function refuseSymlink(path) {
  let st;
  try {
    st = lstatSync(path);
  } catch (err) {
    if (err.code === "ENOENT") return;
    throw err;
  }
  if (st.isSymbolicLink()) {
    throw new Error(`refusing to use '${path}': it is a symbolic link`);
  }
}

/**
 * Create a directory (and parents) mode 0700 and force the mode on the leaf,
 * refusing a symlink at the leaf.
 */
export function ensurePrivateDir(path) {
  refuseSymlink(path);
  mkdirSync(path, { recursive: true, mode: 0o700 });
  refuseSymlink(path);
  chmodSync(path, 0o700);
}

/**
 * Create a file the runtime writes: refuse a pre-planted symlink, then open
 * with `wx` (O_CREAT | O_EXCL) and mode 0600, so the write can never be
 * redirected or land in an existing file.
 *
 * @param {string} path
 * @param {string|Buffer} [data=""]
 */
export function createPrivateFile(path, data = "") {
  refuseSymlink(path);
  const fd = openSync(path, "wx", 0o600);
  try {
    if (data.length > 0) writeFileSync(fd, data);
  } finally {
    closeSync(fd);
  }
}

/**
 * Resolve `argv[0]` for spawning: a name without a separator is searched on
 * FIXED_PATH; a path with a separator is used as given (made absolute
 * against the runtime's working directory, since the child runs in a
 * scratch directory).
 *
 * @param {string} argv0
 * @returns {string} Absolute path
 */
export function resolveBinary(argv0) {
  if (argv0.includes("/")) {
    return isAbsolute(argv0) ? argv0 : resolvePath(argv0);
  }
  for (const dir of FIXED_PATH.split(":")) {
    const candidate = join(dir, argv0);
    try {
      if (statSync(candidate).isFile()) {
        accessSync(candidate, fsConstants.X_OK);
        return candidate;
      }
    } catch {
      // Not here; keep searching.
    }
  }
  throw new Error(`cannot resolve command '${argv0}' on PATH ${FIXED_PATH}`);
}

/**
 * Tokenize a manifest command template into an argv-style token array.
 *
 * Runs on trusted manifest text only; substituted values are never re-split.
 * Honors single and double quotes and backslash escapes. A placeholder may
 * not appear inside quotes (it must be a whole, unquoted token), but the
 * `{{` escape for a literal brace is allowed anywhere.
 *
 * @param {string} template - The template text
 * @param {string} [where="command template"] - Label used in error messages
 * @returns {string[]} Tokens, with `{{`/`}}` escapes left intact for substitution
 */
export function tokenizeTemplate(template, where = "command template") {
  const s = String(template);
  const tokens = [];
  let cur = "";
  let started = false;
  let inSingle = false;
  let inDouble = false;

  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === "\\" && !inSingle) {
      if (i + 1 >= s.length) {
        throw new Error(`trailing backslash in ${where}`);
      }
      cur += s[++i];
      started = true;
    } else if (c === "'" && !inDouble) {
      inSingle = !inSingle;
      started = true;
    } else if (c === '"' && !inSingle) {
      inDouble = !inDouble;
      started = true;
    } else if (c === "{" && (inSingle || inDouble)) {
      if (s[i + 1] === "{") {
        cur += "{{";
        started = true;
        i++;
      } else {
        throw new Error(
          `${where} places a placeholder inside quotes at offset ${i}; placeholders must be whole, unquoted tokens (use exec = [...])`
        );
      }
    } else if (/\s/.test(c) && !inSingle && !inDouble) {
      if (started) {
        tokens.push(cur);
        cur = "";
        started = false;
      }
    } else {
      cur += c;
      started = true;
    }
  }

  if (inSingle || inDouble) {
    throw new Error(`unbalanced quote in ${where}`);
  }
  if (started) {
    tokens.push(cur);
  }
  return tokens;
}

function defineHidden(obj, key, value) {
  Object.defineProperty(obj, key, {
    value,
    enumerable: false,
    writable: true,
    configurable: true,
  });
}

/**
 * Compile `[command]` into its canonical exec form. Idempotent: safe to call
 * from loadManifest and again from the build path for in-memory manifests.
 *
 * - `exec` is used as-is (one element = one token, never split).
 * - `template` is tokenized into `exec` at load; `template` is kept for
 *   display and a deprecation warning is emitted once per compile.
 * - Every conditional template is tokenized into a hidden token array.
 * - `end_of_options` must be exactly "--" when present.
 * - Every placeholder must name a declared variable.
 * - An egress manifest must set `block_internal` on every network target
 *   argument (lintNetworkEgress).
 *
 * Sets the hidden flag `command._execWasDeclared` (true only when the manifest
 * declared `exec` directly), which selects exec-mode validation.
 *
 * @param {object} manifest - Parsed manifest (mutated in place)
 * @returns {object} The same manifest
 */
export function compileCommand(manifest) {
  const command = manifest.command;
  if (!command || command._compiled) return manifest;

  if (
    Object.hasOwn(command, "end_of_options") &&
    command.end_of_options !== "--"
  ) {
    throw new Error(
      `Invalid manifest: command.end_of_options must be exactly "--" (got ${JSON.stringify(command.end_of_options)})`
    );
  }

  if (command.template !== undefined && typeof command.template !== "string") {
    throw new Error("Invalid manifest: command.template must be a string");
  }

  const hasExec = command.exec !== undefined && command.exec !== null;
  if (hasExec) {
    if (
      !Array.isArray(command.exec) ||
      command.exec.length === 0 ||
      !command.exec.every((e) => typeof e === "string")
    ) {
      throw new Error(
        "Invalid manifest: command.exec must be a non-empty array of strings"
      );
    }
    defineHidden(command, "_execWasDeclared", true);
  } else if (typeof command.template === "string" && command.template.length > 0) {
    command.exec = tokenizeTemplate(command.template);
    defineHidden(command, "_execWasDeclared", false);
    console.warn(TEMPLATE_DEPRECATION_WARNING);
  } else {
    defineHidden(command, "_execWasDeclared", false);
  }

  if (command.conditionals) {
    for (const [name, cond] of Object.entries(command.conditionals)) {
      if (!cond || typeof cond !== "object") {
        throw new Error(
          `Invalid manifest: command.conditionals.${name} must be a table`
        );
      }
      if (typeof cond.when !== "string") {
        throw new Error(
          `Invalid manifest: command.conditionals.${name} requires a 'when' expression`
        );
      }
      if (typeof cond.template !== "string") {
        throw new Error(
          `Invalid manifest: command.conditionals.${name} requires a 'template'`
        );
      }
      defineHidden(
        cond,
        "_tokens",
        tokenizeTemplate(cond.template, `command.conditionals.${name} template`)
      );
    }
  }

  if (command.mappings) {
    const argDefs = manifest.args || {};
    for (const [argName, mapping] of Object.entries(command.mappings)) {
      if (!mapping || typeof mapping !== "object" || Array.isArray(mapping)) {
        throw new Error(
          `Invalid manifest: command.mappings.${argName} must be a table`
        );
      }
      const def = argDefs[argName];
      // An enum's mapping table must cover every allowed value; map a value
      // to "" to mean "no flags". A missing case fails here, not silently.
      if (def && def.type === "enum" && Array.isArray(def.allowed)) {
        const missing = def.allowed.filter(
          (v) => !Object.hasOwn(mapping, String(v))
        );
        if (missing.length > 0) {
          throw new Error(
            `Invalid manifest: [command.mappings.${argName}] does not cover enum values: ${missing.join(", ")} (map a value to "" for no flags)`
          );
        }
      }
    }
  }

  checkPlaceholders(manifest);
  checkArgv0(manifest);
  lintNetworkEgress(manifest);
  defineHidden(command, "_compiled", true);
  return manifest;
}

/**
 * The two variable classes a command may reference.
 * - single: one argv token's worth of text (args, command.defaults, executor vars)
 * - multi: a token vector spliced into argv (mappings as `_<arg>_flags`,
 *   conditionals as `_<cond>`)
 */
function declaredVariables(manifest) {
  const command = manifest.command || {};
  const single = new Set([
    ...Object.keys(manifest.args || {}),
    ...Object.keys(command.defaults || {}),
    ...EXECUTOR_VARS,
  ]);
  const multi = new Set();
  for (const argName of Object.keys(command.mappings || {})) {
    multi.add(`_${argName}_flags`);
  }
  for (const condName of Object.keys(command.conditionals || {})) {
    multi.add(`_${condName}`);
  }
  return { single, multi };
}

/**
 * Load-time check: every placeholder in exec and in conditional templates
 * must name a declared variable, and multi-token variables must stand alone.
 */
function checkPlaceholders(manifest) {
  const command = manifest.command;
  const { single, multi } = declaredVariables(manifest);

  const scan = (tokens, where) => {
    for (const token of tokens) {
      const whole = WHOLE_PLACEHOLDER_RE.test(token);
      for (const m of token.matchAll(BRACE_PASS_RE)) {
        if (m[0] === "{{" || m[0] === "}}") continue;
        const name = m[1];
        if (multi.has(name)) {
          if (!whole) {
            throw new Error(
              `placeholder '{${name}}' expands to multiple tokens and must be a whole token in ${where}`
            );
          }
          continue;
        }
        if (!single.has(name)) {
          throw new Error(
            `Invalid manifest: unresolved placeholder '{${name}}' in ${where}`
          );
        }
      }
    }
  };

  if (Array.isArray(command.exec)) {
    scan(command.exec, "command");
  }
  for (const [name, cond] of Object.entries(command.conditionals || {})) {
    scan(cond._tokens, `command.conditionals.${name}`);
  }
}

/**
 * Resolve all argument values: refuse undeclared names, apply defaults,
 * validate types.
 *
 * @param {object} manifest - Parsed manifest
 * @param {object} args - User-supplied arguments (key=value)
 * @param {boolean} [execMode=false] - true only when the manifest declared exec
 * @returns {object} Validated argument map
 */
function resolveArgs(manifest, args, execMode = false) {
  const argDefs = manifest.args || {};
  const supplied = args || {};
  const resolved = {};
  // The scope is discovered (once per manifest object) only when some
  // argument asks for it; a missing file is passed down as null so the
  // validator refuses fail-closed.
  const needsScope = Object.values(argDefs).some((def) => def && def.scope_check === true);
  const scope = needsScope ? scopeForManifest(manifest) : null;
  const customTypes = manifest[CUSTOM_TYPES] || {};

  // A supplied name that [args] does not declare is refused rather than
  // silently dropped, so a caller learns when its argument never reached the
  // command.
  const declared = Object.keys(argDefs).sort();
  for (const name of Object.keys(supplied).sort()) {
    if (!Object.hasOwn(argDefs, name)) {
      const list = declared.length > 0 ? declared.join(", ") : "none";
      throw new Error(
        `unknown argument '${name}' (declared arguments: ${list})`
      );
    }
  }

  for (const [name, def] of Object.entries(argDefs)) {
    let value = supplied[name];

    // Apply default if missing
    if (value === undefined || value === null) {
      if (def.required && def.default === undefined) {
        throw new Error(`Missing required argument: ${name}`);
      }
      value = def.default;
      if (value === undefined) continue;
    }

    resolved[name] = validateArgIn(def, value, { execMode, scope, customTypes });
  }

  return resolved;
}

function lookupSingle(vars, name, where) {
  if (!Object.hasOwn(vars, name) || vars[name] === undefined || vars[name] === null) {
    throw new Error(`unresolved placeholder '{${name}}' in ${where}`);
  }
  return String(vars[name]);
}

/**
 * Substitute variables into a compiled token array, producing argv elements.
 *
 * - A token that is exactly `{name}` naming a multi-token var splices that
 *   var's tokens (0..n elements).
 * - Otherwise every `{name}` in the token is replaced textually, in one pass
 *   that also unescapes `{{`/`}}`. The result is never re-split.
 * - A token that was exactly one placeholder resolving to "" is dropped.
 * - An unknown placeholder throws.
 *
 * @param {string[]} tokens
 * @param {object} vars - Single-token variables
 * @param {object} multi - Multi-token variables (name -> string[])
 * @param {object} [opts]
 * @param {Set<string>} [opts.userArgs] - Declared arg names (for end_of_options)
 * @param {boolean} [opts.endOfOptions] - Insert `--` before the first user-arg token
 * @param {string} [opts.where="command"] - Label for error messages
 * @returns {string[]} argv elements
 */
function substituteTokens(tokens, vars, multi, opts = {}) {
  const { userArgs = null, endOfOptions = false, where = "command" } = opts;
  const argv = [];
  let separatorInserted = false;

  for (const token of tokens) {
    const whole = WHOLE_PLACEHOLDER_RE.exec(token);
    if (whole) {
      const name = whole[1];
      if (Object.hasOwn(multi, name)) {
        argv.push(...multi[name]);
        continue;
      }
      const value = lookupSingle(vars, name, where);
      if (value === "") continue;
      if (endOfOptions && !separatorInserted && userArgs && userArgs.has(name)) {
        argv.push("--");
        separatorInserted = true;
      }
      argv.push(value);
      continue;
    }

    const out = token.replace(BRACE_PASS_RE, (m, name) => {
      if (m === "{{") return "{";
      if (m === "}}") return "}";
      if (Object.hasOwn(multi, name)) {
        throw new Error(
          `placeholder '{${name}}' expands to multiple tokens and must be a whole token in ${where}`
        );
      }
      return lookupSingle(vars, name, where);
    });
    argv.push(out);
  }

  return argv;
}

/**
 * Resolve the full substitution context: validated args, single-token vars
 * (args, command.defaults, executor-injected), and multi-token vars
 * (mappings as `_<arg>_flags`, conditionals as `_<cond>`).
 *
 * @param {object} manifest - Parsed manifest
 * @param {object} args - User-supplied arguments (key=value)
 * @param {object} [opts]
 * @param {string} [opts.scanId] - The invocation's scan id (generated when absent)
 * @returns {{ resolvedArgs: object, vars: object, multi: object, userArgs: Set<string>, execMode: boolean, scanId: string, paths: object }}
 */
function resolveContext(manifest, args, opts = {}) {
  compileCommand(manifest);
  const command = manifest.command;
  const execMode = command._execWasDeclared === true;
  const resolvedArgs = resolveArgs(manifest, args, execMode);
  const argDefs = manifest.args || {};

  const vars = Object.create(null);
  // Declared-but-unset optionals resolve to "" so their tokens disappear.
  for (const name of Object.keys(argDefs)) {
    vars[name] = "";
  }
  for (const [name, value] of Object.entries(resolvedArgs)) {
    vars[name] = value;
  }
  if (command.defaults) {
    for (const [key, val] of Object.entries(command.defaults)) {
      if (!Object.hasOwn(resolvedArgs, key)) {
        vars[key] = val;
      }
    }
  }

  const scanId = opts.scanId || newScanId();
  const paths = evidencePaths(manifest, scanId);
  vars._scan_id = scanId;
  vars._output_file = paths.outputFile;
  vars._evidence_dir = paths.evidenceDir;

  const multi = Object.create(null);
  if (command.mappings) {
    for (const [argName, mapping] of Object.entries(command.mappings)) {
      const key = `_${argName}_flags`;
      // An absent optional (no value, no default) contributes nothing.
      if (!Object.hasOwn(resolvedArgs, argName)) {
        multi[key] = [];
        continue;
      }
      // A value that exists but has no entry is an error, never an empty splice.
      const mapKey = String(resolvedArgs[argName]);
      if (!Object.hasOwn(mapping, mapKey)) {
        throw new Error(
          `no mapping for argument '${argName}' value '${mapKey}' in [command.mappings.${argName}]`
        );
      }
      // Mapping values are manifest-controlled text, so splitting is safe.
      multi[key] = tokenizeTemplate(
        String(mapping[mapKey]),
        `command.mappings.${argName} value`
      );
    }
  }

  if (command.conditionals) {
    for (const [name, cond] of Object.entries(command.conditionals)) {
      const key = `_${name}`;
      multi[key] = evaluateCondition(cond.when, vars)
        ? substituteTokens(cond._tokens, vars, multi, {
            where: `command.conditionals.${name}`,
          })
        : [];
    }
  }

  const userArgs = new Set(Object.keys(argDefs));
  return { resolvedArgs, vars, multi, userArgs, execMode, scanId, paths };
}

/**
 * Build an argv array from the manifest's compiled exec form and validated
 * args. Each token is substituted independently and never re-split, so a
 * value containing whitespace stays one argv element.
 *
 * @param {object} manifest - Parsed manifest
 * @param {object} args - User-supplied arguments (key=value)
 * @param {object} [opts]
 * @param {string} [opts.scanId] - The invocation's scan id (generated when absent)
 * @returns {{ argv: string[], resolvedArgs: object, scanId: string, paths: object }}
 */
export function buildCommandArgv(manifest, args, opts = {}) {
  compileCommand(manifest);
  const command = manifest.command;
  const execArray = command.exec;
  if (!Array.isArray(execArray) || execArray.length === 0) {
    throw new Error("Manifest has no exec array");
  }

  const ctx = resolveContext(manifest, args, opts);
  const argv = substituteTokens(execArray, ctx.vars, ctx.multi, {
    userArgs: ctx.userArgs,
    endOfOptions: command.end_of_options === "--",
    where: "command",
  });

  if (argv.length === 0 || argv[0] === "") {
    throw new Error("exec array produced empty argv");
  }

  return { argv, resolvedArgs: ctx.resolvedArgs, scanId: ctx.scanId, paths: ctx.paths };
}

/**
 * Build the command for a manifest. The authoritative result is `argv`;
 * `command` is a display string (argv joined by single spaces).
 *
 * @param {object} manifest - Parsed manifest
 * @param {object} args - User-supplied arguments (key=value)
 * @param {object} [opts]
 * @param {string} [opts.scanId] - The invocation's scan id (generated when absent)
 * @returns {{ command: string, argv: string[], resolvedArgs: object, isExecutor: boolean, scanId: string, paths: object }}
 */
export function buildCommand(manifest, args, opts = {}) {
  compileCommand(manifest);
  const command = manifest.command;

  // Escape hatch: a wrapper script receives validated args via env vars.
  if (command.executor) {
    const resolvedArgs = resolveArgs(manifest, args, false);
    const scanId = opts.scanId || newScanId();
    return {
      command: command.executor,
      argv: [command.executor],
      resolvedArgs,
      isExecutor: true,
      scanId,
      paths: evidencePaths(manifest, scanId),
    };
  }

  const { argv, resolvedArgs, scanId, paths } = buildCommandArgv(manifest, args, opts);
  return {
    command: argv.join(" "),
    argv,
    resolvedArgs,
    isExecutor: false,
    scanId,
    paths,
  };
}

/**
 * Interpolate {placeholder} references in an HTTP template string.
 * `{{`/`}}` are literal braces; an unknown placeholder throws. Each value is
 * passed through `encode` (identity for headers and the JSON-escaped body).
 */
function interpolate(template, context, encode = (v) => v) {
  return template.replace(BRACE_PASS_RE, (m, key) => {
    if (m === "{{") return "{";
    if (m === "}}") return "}";
    if (!Object.hasOwn(context, key) || context[key] === undefined) {
      throw new Error(`unresolved placeholder '{${key}}' in template`);
    }
    return encode(String(context[key]));
  });
}

/** RFC 7230 token: the only shape an HTTP header name may take. */
const HEADER_NAME_RE = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;

/**
 * Load-time (and pre-request) checks on `[http]`:
 *
 * - `http.url` may not interpolate into the scheme or the host. The host is
 *   the SSRF boundary and must be manifest-controlled, so any `{` other
 *   than a `{{` escape before the end of the authority is refused (this
 *   covers `{_secret:…}` too).
 * - The literal host is held to the host policy: always-blocked addresses
 *   are refused, and when any argument declares `block_internal = true` the
 *   internal ranges and internal names are refused as well. Loopback is
 *   allowed by default.
 * - Every header name must be an RFC 7230 token.
 *
 * @param {object} manifest - Manifest with an [http] section
 * @throws {Error} on the first violation
 */
export function checkHttpDefinition(manifest) {
  const httpDef = manifest.http;
  if (!httpDef || typeof httpDef.url !== "string") return;
  const url = httpDef.url;

  const schemeEnd = url.indexOf("://");
  const authorityStart = schemeEnd === -1 ? 0 : schemeEnd + 3;
  const rest = url.slice(authorityStart);
  const pathStart = rest.search(/[/?#]/);
  const authorityEnd = authorityStart + (pathStart === -1 ? rest.length : pathStart);
  const head = url.slice(0, authorityEnd).replace(/\{\{|\}\}/g, "");
  if (head.includes("{")) {
    throw new Error("http.url may not interpolate into the scheme or host");
  }
  if (schemeEnd === -1) {
    throw new Error(`http.url must be an absolute URL (scheme://host): ${url}`);
  }

  let host = url.slice(authorityStart, authorityEnd);
  if (host.includes("@")) {
    throw new Error("http.url must not contain userinfo (user:pass@host)");
  }
  if (host.startsWith("[")) {
    host = host.slice(1, host.indexOf("]") === -1 ? host.length : host.indexOf("]"));
  } else if (host.includes(":")) {
    host = host.slice(0, host.indexOf(":"));
  }
  const blockInternal = Object.values(manifest.args || {}).some(
    (def) => def && def.block_internal === true
  );
  const ip = parseCanonicalIp(host);
  if (ip !== null) {
    enforceIpPolicy(ip, blockInternal);
  } else if (blockInternal) {
    const embedded = embeddedIpv4Literal(host);
    if (embedded !== null) enforceIpPolicy(embedded, true);
    const internal = internalNameReason(host);
    if (internal !== null) throw new Error(`http.url host ${internal}`);
  }

  for (const name of Object.keys(httpDef.headers || {})) {
    if (!HEADER_NAME_RE.test(name)) {
      throw new Error(`http.headers: header name '${name}' is not a valid token`);
    }
  }
}

/**
 * Build the url, headers and body of an [http] request.
 *
 * Order matters (TC-7): `{_secret:name}` references are expanded on the
 * manifest template FIRST, and only then are the validated arguments
 * interpolated. Argument values are never scanned for secret references, so
 * a value such as `https://attacker.example/?k={_secret:api_key}` is sent
 * verbatim rather than carrying the secret out. This holds for `http.url`,
 * every `http.headers` value and `http.body_template`, independently of the
 * metacharacter check that also refuses braces in most argument types.
 *
 * Values interpolated into `http.url` are percent-encoded with
 * `encodeURIComponent` in both the path and the query, so `/`, `?`, `#`,
 * `&`, `=`, `%` and `..` can never change the URL's structure. Header values
 * are refused if they contain CR or LF after interpolation.
 *
 * @param {object} httpDef - The manifest's [http] section
 * @param {object} context - Validated arguments for url and headers
 * @param {object} bodyContext - Validated arguments for body_template
 * @returns {{ url: string, headers: object, body: string|undefined }}
 */
function buildHttpRequest(httpDef, context, bodyContext) {
  // One resolver per request: TOOLCLAD_SECRETS_FILE is read at most once.
  const secret = makeSecretResolver();
  const url = interpolate(
    injectTemplateVars(httpDef.url, secret),
    context,
    encodeURIComponent
  );

  const headers = {};
  if (httpDef.headers) {
    for (const [key, val] of Object.entries(httpDef.headers)) {
      if (!HEADER_NAME_RE.test(key)) {
        throw new Error(`http.headers: header name '${key}' is not a valid token`);
      }
      const value = interpolate(injectTemplateVars(String(val), secret), context);
      if (/[\r\n\0]/.test(value)) {
        throw new Error(`header '${key}' contains CR, LF or NUL after interpolation`);
      }
      headers[key] = value;
    }
  }

  let body = undefined;
  if (httpDef.body_template) {
    body = interpolate(injectTemplateVars(httpDef.body_template, secret), bodyContext);
  }

  return { url, headers, body };
}

/**
 * Evaluate a simple condition expression against the context.
 * Supports: "key != value", "key == value", "key != '' and other_key == ''"
 *
 * SECURITY: This evaluator uses a closed-vocabulary parser.
 * Never use eval() or equivalent dynamic code execution for conditions.
 */
function evaluateCondition(expr, context) {
  // Split on " and " for compound conditions
  const parts = expr.split(/\s+and\s+/);
  return parts.every((part) => evaluateSingleCondition(part.trim(), context));
}

function evaluateSingleCondition(expr, context) {
  // Match: key != 'value' or key != value or key == 'value' etc.
  const match = expr.match(/^(\w+)\s*(!=|==)\s*(.+)$/);
  if (!match) return false;

  const [, key, op, rawVal] = match;
  const contextVal = context[key] !== undefined ? String(context[key]) : "";
  // Strip quotes from comparison value
  const compareVal = rawVal.replace(/^['"]|['"]$/g, "");

  if (op === "!=") return contextVal !== compareVal;
  if (op === "==") return contextVal === compareVal;
  return false;
}

/**
 * Policy gate seam (TC-9).
 *
 * A gate is `(manifest, validatedArgs) => GateDecision`. It is consulted
 * after argument validation (so it sees the cleaned values and cannot be
 * used to probe validity) and before anything is spawned, any HTTP request
 * is made, or any MCP envelope is built. A dry run is not gated: it executes
 * nothing, and it is how an operator decides whether to approve.
 *
 * `[tool.cedar]` declares the resource and action for an embedding
 * runtime's Cedar evaluator. ToolClad does not evaluate Cedar policy itself;
 * wiring such an evaluator into a gate passed to `execute` is the embedder's
 * job.
 */
export const GateDecision = Object.freeze({
  /** @returns {{ allowed: true }} */
  allow() {
    return Object.freeze({ allowed: true });
  },
  /**
   * @param {string} reason
   * @returns {{ allowed: false, reason: string }}
   */
  deny(reason) {
    return Object.freeze({ allowed: false, reason: String(reason) });
  },
});

/** Thrown when a gate denies a call; the message starts `policy gate denied: `. */
export class PolicyGateError extends Error {
  constructor(reason) {
    super(`policy gate denied: ${reason}`);
    this.name = "PolicyGateError";
    this.reason = reason;
  }
}

/**
 * The deny-by-default gate: denies a manifest that sets
 * `human_approval = true` or whose `risk_tier` is `high` or `critical`.
 *
 * @param {object} manifest
 * @param {object} _args - Validated arguments (unused)
 * @returns {object} GateDecision
 */
export function defaultGate(manifest, _args) {
  const tool = manifest.tool || {};
  if (tool.human_approval === true) {
    return GateDecision.deny("manifest requires human approval (human_approval = true)");
  }
  const tier = tool.risk_tier;
  if (typeof tier === "string" && ["high", "critical"].includes(tier.toLowerCase())) {
    return GateDecision.deny(`risk_tier '${tier}' requires explicit approval`);
  }
  return GateDecision.allow();
}

/** The allow-all gate behind `{ approve: true }` and `run --approve`. */
export function approveGate(_manifest, _args) {
  return GateDecision.allow();
}

function selectGate(options) {
  const { gate, approve } = options || {};
  const hasGate = gate !== undefined && gate !== null;
  if (hasGate && approve) {
    throw new Error("pass either a gate or approve: true, not both");
  }
  if (approve === true) return approveGate;
  if (!hasGate) return defaultGate;
  if (typeof gate !== "function") {
    throw new TypeError("gate must be a function (manifest, args) => GateDecision");
  }
  return gate;
}

/**
 * Consult the selected gate; throw PolicyGateError unless it allows.
 * Anything other than an explicit allow decision denies (fail closed).
 */
function consultGate(manifest, resolvedArgs, options) {
  const gate = selectGate(options);
  const decision = gate(manifest, Object.freeze({ ...resolvedArgs }));
  if (decision && typeof decision.then === "function") {
    throw new PolicyGateError("gate must return a GateDecision synchronously");
  }
  if (!decision || decision.allowed !== true) {
    const reason =
      decision && typeof decision.reason === "string" && decision.reason !== ""
        ? decision.reason
        : "gate returned no allow decision";
    throw new PolicyGateError(reason);
  }
}

/**
 * The declared, unexpanded command for an executed envelope (design issue
 * 9): the `exec` array as written joined by single spaces, the legacy
 * template string as written, or `<executor> (custom executor)`. Executor
 * paths and secrets therefore never reach the agent or the evidence file.
 *
 * @param {object} manifest - A compiled manifest
 * @returns {string}
 */
export function declaredCommand(manifest) {
  const command = manifest.command || {};
  if (command.executor) return `${command.executor} (custom executor)`;
  if (command._execWasDeclared === true) return command.exec.join(" ");
  if (typeof command.template === "string") return command.template;
  return Array.isArray(command.exec) ? command.exec.join(" ") : "";
}

/**
 * Execute a tool using its manifest and supplied arguments.
 * Validates args, consults the policy gate, builds argv, spawns the process,
 * and wraps its output in an evidence envelope. Asynchronous: the deadline is
 * enforced by a timer and a process-group kill, which a synchronous spawn
 * cannot do.
 *
 * @param {object} manifest - Parsed manifest
 * @param {object} args - User-supplied arguments (key=value)
 * @param {object} [options] - Execution options
 * @param {boolean} [options.dryRun=false] - If true, build command but don't execute (not gated)
 * @param {Function} [options.gate] - `(manifest, validatedArgs) => GateDecision`; defaults to defaultGate
 * @param {boolean} [options.approve=false] - Use the allow-all gate (exclusive with `gate`)
 * @returns {Promise<object>} Evidence envelope with results
 * @throws {PolicyGateError} when the gate denies the call
 */
export async function execute(manifest, args, options = {}) {
  selectGate(options);

  // Gate unimplemented modes
  if (manifest.session) {
    throw new Error(
      "session mode is parsed but not yet executable in the reference implementation — use the Symbiont runtime for session execution"
    );
  }
  if (manifest.browser) {
    throw new Error(
      "browser mode is parsed but not yet executable in the reference implementation — use the Symbiont runtime for browser execution"
    );
  }

  // Route to the HTTP backend (fetch).
  if (manifest.http) {
    return executeHttp(manifest, args, options);
  }

  // Route to MCP proxy backend
  if (manifest.mcp) {
    return executeMcp(manifest, args, options);
  }

  compileCommand(manifest);
  checkOutputParser(manifest);
  const maxBytes = outputMaxBytes(manifest);
  const timeoutMs = timeoutSeconds(manifest) * 1000;
  const built = buildCommand(manifest, args, { scanId: newScanId() });
  const { argv: cmdParts, command: commandDisplay, resolvedArgs, isExecutor, scanId, paths } = built;

  if (options.dryRun) {
    return {
      status: "dry_run",
      scan_id: scanId,
      tool: manifest.tool.name,
      command: commandDisplay,
      argv: cmdParts,
      resolvedArgs,
    };
  }

  // After validation, before anything touches the filesystem or spawns.
  consultGate(manifest, resolvedArgs, options);

  // Evidence root, output directory and per-invocation scratch cwd, all 0700
  // and created before the spawn. The output file is pre-created 0600 with
  // O_EXCL so the tool writes into a private file and a planted symlink
  // cannot redirect it (Node cannot set a umask for the child; this is the
  // substitute for the output file).
  ensurePrivateDir(paths.evidenceDir);
  ensurePrivateDir(paths.outputDir);
  createPrivateFile(paths.outputFile);
  const workDir = join(paths.evidenceDir, `${scanId}-work`);
  ensurePrivateDir(workDir);

  let env;
  if (isExecutor) {
    // Escape hatch: validated args reach the wrapper as environment
    // variables. buildChildEnv drops TOOLCLAD_SECRET_* regardless.
    const extra = {};
    for (const [key, val] of Object.entries(resolvedArgs)) {
      extra[`TOOLCLAD_ARG_${key.toUpperCase()}`] = String(val);
    }
    extra.TOOLCLAD_SCAN_ID = scanId;
    extra.TOOLCLAD_TOOL_NAME = manifest.tool.name;
    extra.TOOLCLAD_EVIDENCE_DIR = paths.evidenceDir;
    extra.TOOLCLAD_OUTPUT_DIR = paths.outputDir;
    env = buildChildEnv(extra);
  } else {
    env = buildChildEnv();
  }

  const binary = resolveBinary(cmdParts[0]);
  const startTime = Date.now();
  let result;
  try {
    result = await runWithDeadline(binary, cmdParts.slice(1), {
      env,
      cwd: workDir,
      timeoutMs,
      graceMs: killGraceMs(),
      maxBytes,
    });
  } finally {
    // Remove the scratch directory only when empty: anything the tool wrote
    // there is evidence.
    try {
      rmdirSync(workDir);
    } catch {
      // Not empty (or already gone): keep it.
    }
  }

  const durationMs = Date.now() - startTime;
  const { stdout, stderr, timedOut, truncated } = result;
  const exitCode = timedOut ? -1 : result.exitCode;
  const outputHash = createHash("sha256").update(stdout).digest("hex");

  // Build evidence envelope with exit_code and stderr on all paths. The
  // command is the declared form, never the resolved argv.
  const envelope = {
    status: timedOut ? "timeout" : exitCode === 0 ? "success" : "error",
    scan_id: scanId,
    tool: manifest.tool.name,
    command: declaredCommand(manifest),
    exit_code: exitCode ?? -1,
    stderr,
    duration_ms: durationMs,
    timestamp: new Date(startTime).toISOString(),
    output_hash: `sha256:${outputHash}`,
  };
  if (truncated) envelope.output_truncated = true;

  if (timedOut) {
    envelope.error = `Process timed out after ${timeoutMs / 1000}s`;
    envelope.results = { raw_output: stdout };
  } else if (exitCode !== 0) {
    envelope.error = stderr || `Process exited with code ${exitCode}`;
    envelope.results = { raw_output: stdout };
  } else {
    const finished = finishResults(manifest, stdout);
    envelope.status = finished.status;
    envelope.results = finished.results;
  }

  return envelope;
}

/**
 * Removed synchronous entry point. Throws so a caller still using it fails
 * loudly instead of silently getting the old, unenforceable timeout.
 */
export function executeSync() {
  throw new Error("executeSync was removed: execute() is async; await execute(...)");
}

/** Length of the longest prefix of `buf` that ends on a UTF-8 boundary. */
function utf8Boundary(buf) {
  let i = buf.length - 1;
  let continuation = 0;
  while (i >= 0 && continuation < 3 && (buf[i] & 0xc0) === 0x80) {
    i--;
    continuation++;
  }
  if (i < 0) return buf.length;
  const lead = buf[i];
  const need = lead >= 0xf0 ? 4 : lead >= 0xe0 ? 3 : lead >= 0xc0 ? 2 : 1;
  return need > buf.length - i ? i : buf.length;
}

/** Decode captured chunks; a capped capture drops a split trailing character. */
function decodeCapped(chunks, truncated) {
  let buf = Buffer.concat(chunks);
  if (truncated) buf = buf.subarray(0, utf8Boundary(buf));
  return buf.toString("utf-8");
}

/**
 * Spawn `binary` with `args` in its own process group and enforce a deadline.
 *
 * stdin is /dev/null; stdout and stderr are captured up to `maxBytes` each.
 * Past the cap, chunks are discarded but the pipe keeps being read so the
 * child never blocks on a full pipe, and `truncated` is set. On the deadline:
 * SIGTERM to the group, then SIGKILL to the group after `graceMs`; resolves
 * on `close`, keeping whatever output was captured before the kill.
 *
 * Node cannot set a umask or resource limits for a child process portably
 * (there is no pre-exec hook), so neither is applied here; the Rust and
 * Python runtimes set them.
 *
 * @returns {Promise<{ stdout: string, stderr: string, exitCode: number|null, signal: string|null, timedOut: boolean, truncated: boolean }>}
 */
function runWithDeadline(binary, args, { env, cwd, timeoutMs, graceMs, maxBytes = DEFAULT_OUTPUT_MAX_BYTES }) {
  return new Promise((resolve, reject) => {
    let child;
    try {
      child = spawn(binary, args, {
        shell: false,
        detached: true,
        stdio: ["ignore", "pipe", "pipe"],
        env,
        cwd,
      });
    } catch (err) {
      reject(err);
      return;
    }

    const capture = (stream) => {
      const state = { chunks: [], size: 0, truncated: false };
      stream.on("data", (chunk) => {
        if (state.truncated) return;
        const room = maxBytes - state.size;
        if (chunk.length > room) {
          if (room > 0) state.chunks.push(chunk.subarray(0, room));
          state.size = maxBytes;
          state.truncated = true;
          return;
        }
        state.chunks.push(chunk);
        state.size += chunk.length;
      });
      return state;
    };
    const out = capture(child.stdout);
    const err = capture(child.stderr);

    const killGroup = (signal) => {
      try {
        process.kill(-child.pid, signal);
      } catch {
        // The group is already gone.
      }
    };

    let timedOut = false;
    let graceTimer = null;
    // The kill is cleanup, not containment: a child that calls setsid()
    // leaves the process group and escapes both signals in every language.
    // Escape-proof cleanup needs a cgroup, which is out of scope here.
    const deadline = setTimeout(() => {
      timedOut = true;
      killGroup("SIGTERM");
      graceTimer = setTimeout(() => {
        killGroup("SIGKILL");
        // A process outside the group may still hold the pipes open; stop
        // waiting on them so `close` fires and the call returns.
        child.stdout.destroy();
        child.stderr.destroy();
      }, graceMs);
    }, timeoutMs);

    child.on("error", (spawnErr) => {
      clearTimeout(deadline);
      if (graceTimer) clearTimeout(graceTimer);
      reject(spawnErr);
    });

    child.on("close", (code, signal) => {
      clearTimeout(deadline);
      if (timedOut && graceTimer) {
        // The direct child is gone, but group members that ignored SIGTERM
        // may remain: kill the group now rather than waiting out the grace.
        clearTimeout(graceTimer);
        killGroup("SIGKILL");
      }
      resolve({
        stdout: decodeCapped(out.chunks, out.truncated),
        stderr: decodeCapped(err.chunks, err.truncated),
        exitCode: code,
        signal,
        timedOut,
        truncated: out.truncated || err.truncated,
      });
    });
  });
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/**
 * Parse tool output based on the manifest's output.format / output.parser,
 * normalized so `results` is always an object: json objects pass through and
 * any other json value is wrapped as `{parsed_output}`; jsonl and csv give
 * `{parsed_output: [...]}`; text gives `{raw_output}`.
 *
 * @param {object} manifest - Parsed manifest
 * @param {string} raw - Raw output string
 * @returns {object} Parsed results
 * @throws {Error} when the output does not parse
 */
function parseOutputJs(manifest, raw) {
  checkOutputParser(manifest);
  const format = manifest.output?.format || "text";
  const parser = manifest.output?.parser || `builtin:${format}`;

  switch (parser) {
    case "builtin:json": {
      let value;
      try {
        value = JSON.parse(raw);
      } catch (err) {
        throw new Error(`invalid JSON output: ${err.message}`);
      }
      return isPlainObject(value) ? value : { parsed_output: value };
    }
    case "builtin:jsonl": {
      const lines = raw.split("\n").filter((l) => l.trim());
      return {
        parsed_output: lines.map((line, i) => {
          try {
            return JSON.parse(line);
          } catch (err) {
            throw new Error(`invalid JSON on output line ${i + 1}: ${err.message}`);
          }
        }),
      };
    }
    case "builtin:csv":
      return { parsed_output: parseCsv(raw) };
    case "builtin:xml":
      return parseXmlToJson(raw);
    default:
      return { raw_output: raw };
  }
}

/**
 * Parse and schema-check raw output, fail closed (TC-14). A parse failure
 * gives status `parse_error`, a schema mismatch `schema_error`; both keep the
 * raw output under `results.raw_output`. Without `[output.schema]` the
 * schema is `{type: "object"}`, which every normalized result satisfies.
 *
 * @param {object} manifest
 * @param {string} raw
 * @returns {{ status: string, results: object }}
 */
function finishResults(manifest, raw) {
  let parsed;
  try {
    parsed = parseOutputJs(manifest, raw);
  } catch (err) {
    return { status: "parse_error", results: { parse_error: err.message, raw_output: raw } };
  }
  const schema = manifest.output?.schema ?? { type: "object" };
  const failure = validateJsonSchema(schema, parsed);
  if (failure !== null) {
    return { status: "schema_error", results: { schema_error: failure, raw_output: raw } };
  }
  return { status: "success", results: parsed };
}

/**
 * Parse CSV text into an array of objects using the first row as headers.
 * Auto-detects delimiter (comma, tab, pipe) and performs basic type inference.
 */
function parseCsv(raw) {
  const lines = raw.trim().split("\n").filter(l => l.trim());
  if (lines.length === 0) return [];

  const firstLine = lines[0];
  // Auto-detect delimiter
  const delimiter = firstLine.includes("\t") ? "\t" :
    (firstLine.includes("|") && !firstLine.includes(",")) ? "|" : ",";

  const headers = splitCsvLine(firstLine, delimiter).map(h => h.trim());
  return lines.slice(1).map(line => {
    const fields = splitCsvLine(line, delimiter);
    const obj = {};
    headers.forEach((h, i) => {
      const val = (fields[i] || "").trim();
      // Type inference
      if (val.toLowerCase() === "true" || val.toLowerCase() === "false") {
        obj[h] = val.toLowerCase() === "true";
      } else if (/^-?\d+$/.test(val)) {
        obj[h] = parseInt(val, 10);
      } else if (/^-?\d+\.\d+$/.test(val)) {
        obj[h] = parseFloat(val);
      } else {
        obj[h] = val;
      }
    });
    return obj;
  });
}

/**
 * Split a CSV line by delimiter, respecting double-quoted fields.
 */
function splitCsvLine(line, delimiter) {
  const fields = [];
  let current = "";
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (c === '"') {
      if (inQuotes && i + 1 < line.length && line[i + 1] === '"') {
        current += '"';
        i++;
      } else {
        inQuotes = !inQuotes;
      }
    } else if (c === delimiter && !inQuotes) {
      fields.push(current);
      current = "";
    } else {
      current += c;
    }
  }
  fields.push(current);
  return fields;
}

/**
 * Simple XML-to-JSON parser. Handles elements, attributes, text content,
 * and self-closing tags. Input carrying a DOCTYPE or ENTITY declaration is
 * refused before parsing, and a malformed document throws (fail closed).
 */
function parseXmlToJson(xml) {
  const trimmed = xml.trim();
  if (!trimmed) return { raw_output: "" };
  if (/<!\s*(DOCTYPE|ENTITY)/i.test(trimmed)) {
    throw new Error(
      "XML output contains a DOCTYPE or ENTITY declaration; refusing to parse"
    );
  }
  const closeOf = (from) => {
    const end = trimmed.indexOf(">", from);
    if (end === -1) throw new Error("invalid XML output: unterminated tag");
    return end;
  };

  {
    let pos = 0;
    // Skip XML declaration
    if (trimmed.startsWith("<?xml")) {
      const end = trimmed.indexOf("?>");
      if (end !== -1) pos = end + 2;
    }

    const stack = [];
    let currentName = "";
    let currentObj = {};
    let textBuf = "";

    while (pos < trimmed.length) {
      if (trimmed[pos] === "<") {
        // Flush text
        const text = textBuf.trim();
        if (text && currentName) {
          currentObj["#text"] = text;
        }
        textBuf = "";
        pos++;

        if (trimmed[pos] === "/") {
          // Closing tag
          pos++;
          const tagEnd = closeOf(pos);
          pos = tagEnd + 1;

          const finishedObj = { ...currentObj };
          if (stack.length > 0) {
            const [parentName, parentObj] = stack.pop();
            if (parentObj[currentName]) {
              if (!Array.isArray(parentObj[currentName])) {
                parentObj[currentName] = [parentObj[currentName]];
              }
              parentObj[currentName].push(finishedObj);
            } else {
              parentObj[currentName] = finishedObj;
            }
            currentName = parentName;
            currentObj = parentObj;
          }
        } else if (trimmed[pos] === "!" || trimmed[pos] === "?") {
          pos = closeOf(pos) + 1;
        } else {
          // Opening tag
          const tagEnd = closeOf(pos);
          let tagContent = trimmed.substring(pos, tagEnd);
          const selfClosing = tagContent.endsWith("/");
          if (selfClosing) tagContent = tagContent.slice(0, -1);

          const spaceIdx = tagContent.indexOf(" ");
          const tagName = spaceIdx === -1 ? tagContent : tagContent.substring(0, spaceIdx);
          const attrStr = spaceIdx === -1 ? "" : tagContent.substring(spaceIdx);

          const attrs = {};
          const attrRe = /(\w+)\s*=\s*["']([^"']*)["']/g;
          let m;
          while ((m = attrRe.exec(attrStr)) !== null) {
            attrs[`@${m[1]}`] = m[2];
          }

          if (selfClosing) {
            if (currentObj[tagName]) {
              if (!Array.isArray(currentObj[tagName])) {
                currentObj[tagName] = [currentObj[tagName]];
              }
              currentObj[tagName].push(attrs);
            } else {
              currentObj[tagName] = attrs;
            }
          } else {
            stack.push([currentName, currentObj]);
            currentName = tagName;
            currentObj = attrs;
          }
          pos = tagEnd + 1;
        }
      } else {
        textBuf += trimmed[pos];
        pos++;
      }
    }

    if (stack.length > 0 || currentName) {
      throw new Error(`invalid XML output: unclosed element <${currentName}>`);
    }
    return currentObj;
  }
}

/**
 * Deprecated alias of `executeHttp`. The old implementation ran curl with
 * every header and the URL on its command line, where any local user could
 * read them from `/proc/<pid>/cmdline`. It now delegates to the fetch-based
 * `executeHttp` and therefore returns a Promise: await it.
 *
 * @deprecated Use `await executeHttp(manifest, args, options)`.
 * @param {object} manifest - Parsed manifest with http section
 * @param {object} args - User-supplied arguments (key=value)
 * @param {object} [options] - Same options as executeHttp
 * @returns {Promise<object>} Evidence envelope with http_status
 */
export function executeHttpSync(manifest, args, options = {}) {
  return executeHttp(manifest, args, options);
}

/**
 * Read at most `maxBytes` of a fetch response body through its stream
 * reader. If more arrives, the stream is cancelled and `truncated` is set.
 */
async function readCappedBody(response, maxBytes) {
  if (!response.body) return { text: "", truncated: false };
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  let truncated = false;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      const room = maxBytes - size;
      if (value.length > room) {
        if (room > 0) chunks.push(Buffer.from(value.subarray(0, room)));
        size = maxBytes;
        truncated = true;
        break;
      }
      chunks.push(Buffer.from(value));
      size += value.length;
    }
  } finally {
    if (truncated) {
      await reader.cancel().catch(() => {});
    } else {
      reader.releaseLock();
    }
  }
  return { text: decodeCapped(chunks, truncated), truncated };
}

/**
 * Execute a tool via HTTP when the manifest has an [http] section.
 * Uses Node 18+ built-in fetch. Redirects are never followed: a 3xx gives
 * status `redirect_blocked` with the `Location` header under
 * `results.location`. The body is read up to `[output] max_bytes`.
 *
 * @param {object} manifest - Parsed manifest with http section
 * @param {object} args - User-supplied arguments (key=value)
 * @param {object} [options] - Execution options
 * @param {boolean} [options.dryRun=false] - If true, build request but don't execute (not gated)
 * @param {Function} [options.gate] - Policy gate; defaults to defaultGate
 * @param {boolean} [options.approve=false] - Use the allow-all gate
 * @returns {Promise<object>} Evidence envelope with http_status
 */
export async function executeHttp(manifest, args, options = {}) {
  selectGate(options);
  const httpDef = manifest.http;
  if (!httpDef || !httpDef.url) {
    throw new Error("Manifest missing [http] section or http.url");
  }

  // An [http] manifest is an egress manifest by definition; an in-memory one
  // never passes through loadManifest, so check and lint it here.
  checkHttpDefinition(manifest);
  lintNetworkEgress(manifest);
  checkOutputParser(manifest);
  const maxBytes = outputMaxBytes(manifest);
  const timeoutMs = timeoutSeconds(manifest) * 1000;
  const resolvedArgs = resolveArgs(manifest, args);
  const context = { ...resolvedArgs };

  // JSON-escape values for safe interpolation into body templates.
  const escaped = {};
  for (const [k, v] of Object.entries(context)) {
    escaped[k] = JSON.stringify(String(v)).slice(1, -1);
  }

  // Secrets are expanded on the template before any argument is
  // interpolated (TC-7); see buildHttpRequest.
  const { url, headers, body } = buildHttpRequest(httpDef, context, escaped);

  const method = (httpDef.method || "GET").toUpperCase();
  const scanId = newScanId();

  if (options.dryRun) {
    return {
      status: "dry_run",
      scan_id: scanId,
      tool: manifest.tool.name,
      command: `${method} ${url}`,
      http_method: method,
      http_url: url,
      http_headers: headers,
      http_body: body,
      resolvedArgs,
    };
  }

  consultGate(manifest, resolvedArgs, options);

  const startTime = Date.now();

  const fetchOptions = {
    method,
    headers,
    redirect: "manual",
    signal: AbortSignal.timeout(timeoutMs),
  };
  if (body && method !== "GET" && method !== "HEAD") {
    fetchOptions.body = body;
  }

  const response = await fetch(url, fetchOptions);
  const { text: responseBody, truncated } = await readCappedBody(response, maxBytes);
  const durationMs = Date.now() - startTime;
  const outputHash = createHash("sha256").update(responseBody).digest("hex");

  const successStatus = httpDef.success_status || [200, 201, 202, 204];
  const isSuccess = successStatus.includes(response.status);

  // The declared request, never the expanded URL: secrets and interpolated
  // values stay out of the envelope.
  const envelope = {
    status: isSuccess ? "success" : "error",
    scan_id: scanId,
    tool: manifest.tool.name,
    command: `${method} ${httpDef.url}`,
    http_status: response.status,
    duration_ms: durationMs,
    timestamp: new Date(startTime).toISOString(),
    output_hash: `sha256:${outputHash}`,
  };
  if (truncated) envelope.output_truncated = true;

  if (response.status >= 300 && response.status < 400) {
    envelope.status = "redirect_blocked";
    envelope.error = `HTTP ${response.status}: redirect not followed`;
    envelope.results = {
      location: response.headers.get("location") ?? "",
      raw_output: responseBody,
    };
  } else if (isSuccess) {
    const finished = finishResults(manifest, responseBody);
    envelope.status = finished.status;
    envelope.results = finished.results;
  } else {
    envelope.error = `HTTP ${response.status}: ${responseBody.slice(0, 500)}`;
    envelope.results = { raw_output: responseBody };
  }

  return envelope;
}

/**
 * Proxy a tool invocation to an MCP server when the manifest has an [mcp] section.
 * Performs field mapping and returns a delegated envelope. The policy gate
 * is consulted before the envelope is built.
 *
 * @param {object} manifest - Parsed manifest with mcp section
 * @param {object} args - User-supplied arguments (key=value)
 * @param {object} [options] - `{ gate, approve }`, as for execute
 * @returns {object} Evidence envelope with status "delegation_preview"
 */
export function executeMcp(manifest, args, options = {}) {
  selectGate(options);
  const mcpDef = manifest.mcp;
  if (!mcpDef || !mcpDef.server || !mcpDef.tool) {
    throw new Error("Manifest missing [mcp] section or mcp.server/mcp.tool");
  }

  const resolvedArgs = resolveArgs(manifest, args);
  consultGate(manifest, resolvedArgs, options);

  // Apply field_map: translate our arg names to the MCP tool's expected names
  const mappedArgs = {};
  if (mcpDef.field_map) {
    for (const [ourName, theirName] of Object.entries(mcpDef.field_map)) {
      if (resolvedArgs[ourName] !== undefined) {
        mappedArgs[theirName] = resolvedArgs[ourName];
      }
    }
  } else {
    // No field_map: pass args through as-is
    Object.assign(mappedArgs, resolvedArgs);
  }

  const startTime = Date.now();
  const scanId = newScanId();

  return {
    status: "delegation_preview",
    scan_id: scanId,
    tool: manifest.tool.name,
    command: `mcp://${mcpDef.server}/${mcpDef.tool}`,
    mcp_server: mcpDef.server,
    mcp_tool: mcpDef.tool,
    mapped_args: mappedArgs,
    timestamp: new Date(startTime).toISOString(),
  };
}

/**
 * Generate an MCP-compatible JSON schema from a manifest.
 *
 * @param {object} manifest - Parsed manifest
 * @returns {object} MCP tool schema
 */
export function generateMcpSchema(manifest) {
  const properties = {};
  const required = [];

  const argDefs = manifest.args || {};
  for (const [name, def] of Object.entries(argDefs)) {
    const typeInfo = mcpTypeAndConstraints(def.type, def);
    const prop = {
      ...typeInfo,
      description: def.description || "",
    };
    if (def.type === "enum" && def.allowed) {
      prop.enum = def.allowed;
    }
    if (def.default !== undefined) {
      prop.default = def.default;
    }
    properties[name] = prop;
    if (def.required) {
      required.push(name);
    }
  }

  const schema = {
    name: manifest.tool.name,
    description: manifest.tool.description || "",
    inputSchema: {
      type: "object",
      properties,
      required,
    },
  };

  // Include outputSchema from manifest if available
  if (manifest.output && manifest.output.schema) {
    schema.outputSchema = buildOutputSchema(manifest);
  }

  return schema;
}

function mcpTypeAndConstraints(toolcladType, argDef) {
  switch (toolcladType) {
    case "integer":
      return { type: "integer" };
    case "number": {
      const out = { type: "number" };
      if (argDef && argDef.min_float !== undefined) out.minimum = argDef.min_float;
      if (argDef && argDef.max_float !== undefined) out.maximum = argDef.max_float;
      return out;
    }
    case "port":
      return { type: "integer", minimum: 1, maximum: 65535 };
    case "boolean":
      return { type: "boolean" };
    case "ip_address":
      return { type: "string", format: "ipv4" };
    case "cidr":
      return {
        type: "string",
        pattern: String.raw`^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$`,
      };
    case "url":
      return { type: "string", format: "uri" };
    case "duration":
      return {
        type: "string",
        pattern: String.raw`^(\d+|(?:\d+h)?(?:\d+m)?(?:\d+s)?(?:\d+ms)?)$`,
      };
    default:
      return { type: "string" };
  }
}

function buildOutputSchema(manifest) {
  const results = manifest.output.schema || { type: "object" };

  if (manifest.output.envelope !== false) {
    return {
      type: "object",
      properties: {
        status: {
          type: "string",
          enum: ["success", "error", "timeout", "schema_error", "parse_error", "redirect_blocked"],
        },
        scan_id: { type: "string" },
        tool: { type: "string" },
        command: { type: "string" },
        exit_code: { type: "integer" },
        stderr: { type: "string" },
        duration_ms: { type: "integer" },
        timestamp: { type: "string", format: "date-time" },
        output_hash: { type: "string" },
        output_truncated: { type: "boolean" },
        results,
      },
    };
  }

  return results;
}
