import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import TOML from "@iarna/toml";
import {
  checkHttpDefinition,
  checkOutputParser,
  compileCommand,
  lintNetworkEgress,
  outputMaxBytes,
  timeoutSeconds,
} from "./executor.js";
import { validateDefaultValue } from "./validator.js";
import { MANIFEST_DIR, SCOPE_CHECK_TYPES } from "./scope.js";

/**
 * Hidden property every loader sets to the custom type map the manifest was
 * checked against (discovered from `toolclad.toml` or supplied by the caller).
 * The executor validates arguments with it, so a custom type works on every
 * path that validates arguments, not only in the dry run.
 */
export const CUSTOM_TYPES = Symbol.for("toolclad.customTypes");

/** Allowed keys inside a `[types.<n>]` table of toolclad.toml. */
const CUSTOM_TYPE_KEYS = new Set([
  "base", "allowed", "pattern", "min", "max", "min_float", "max_float",
]);

/** Built-in argument types; anything else is a custom type from toolclad.toml. */
export const BUILTIN_TYPES = new Set([
  "string", "integer", "number", "port", "boolean", "enum", "scope_target",
  "url", "path", "ip_address", "cidr", "msf_options", "credential_file",
  "duration", "regex_match",
]);

/**
 * Complete manifest key allowlist, one entry per section, in the order of the
 * normative table so the two can be diffed line by line.
 *
 * A section path ending in `<n>` is keyed by author-chosen names whose
 * contents are checked against the listed keys (`[args.<n>]`,
 * `[command.conditionals.<n>]`, `[session.commands.<n>]`,
 * `[browser.commands.<n>]`). A known key whose value is a table but that has
 * no entry of its own here is an open map or opaque data and is not walked:
 * `command.defaults`, `command.mappings`, `output.schema`, `http.headers`,
 * `mcp.field_map`, and the `args` of a session or browser command.
 */
export const MANIFEST_KEYS = Object.freeze({
  "tool":
    "name version binary description timeout_seconds risk_tier " +
    "human_approval dispatch mode network_egress allow_interpreter " +
    "cedar evidence limits",
  "tool.cedar": "resource action",
  "tool.evidence": "output_dir capture hash screenshots",
  "tool.limits": "nproc nofile fsize_bytes address_space_bytes cpu_seconds",
  "args.<n>":
    "position required type description default allowed pattern " +
    "sanitize min max min_float max_float clamp schemes " +
    "scope_check block_internal allow_leading_dash allow_whitespace",
  "command":
    "template exec executor defaults mappings conditionals " +
    "end_of_options",
  "command.conditionals.<n>": "when template",
  "output": "format parser envelope schema max_bytes",
  "http": "method url headers body_template success_status error_status",
  "mcp": "server tool field_map",
  "session":
    "startup_command ready_pattern startup_timeout_seconds " +
    "idle_timeout_seconds session_timeout_seconds max_interactions " +
    "interaction commands child_detection",
  "session.interaction": "input_sanitize output_max_bytes output_wait_ms",
  "session.commands.<n>":
    "pattern description risk_tier human_approval " +
    "extract_target args",
  "session.child_detection": "pattern type manifest",
  "browser":
    "engine headless connect extract_mode startup_timeout_seconds " +
    "session_timeout_seconds idle_timeout_seconds max_interactions " +
    "scope commands state defaults",
  "browser.defaults": "extract_mode",
  "browser.scope": "allowed_domains blocked_domains allow_external",
  "browser.commands.<n>": "description risk_tier human_approval args",
  "browser.state": "fields",
});

// Section path -> Set of allowed keys. The root entry ("") is derived from the
// table's first path components so the top-level section list cannot drift
// from it.
const SECTION_KEYS = new Map(
  Object.entries(MANIFEST_KEYS).map(([section, keys]) => [
    section,
    new Set(keys.split(" ")),
  ])
);
SECTION_KEYS.set(
  "",
  new Set([...SECTION_KEYS.keys()].map((section) => section.split(".")[0]))
);

const TOOL_MODES = ["oneshot", "session", "browser"];
const LIMIT_KEYS = ["nproc", "nofile", "fsize_bytes", "address_space_bytes", "cpu_seconds"];

function isTable(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    !(value instanceof Date)
  );
}

/**
 * Walk a parsed manifest and return every key the allowlist does not know, as
 * sorted concrete dotted paths (e.g. `args.target.block_internal_typo`).
 *
 * @param {object} manifest - Raw TOML.parse result
 * @returns {string[]} Sorted unknown key paths; empty when the manifest is clean
 */
export function findUnknownKeys(manifest) {
  const unknown = [];
  walkTable(manifest, "", "", unknown);
  return unknown.sort();
}

function walkTable(table, section, path, unknown) {
  const allowed = SECTION_KEYS.get(section);
  if (allowed) {
    for (const [key, value] of Object.entries(table)) {
      const keyPath = path === "" ? key : `${path}.${key}`;
      if (!allowed.has(key)) {
        unknown.push(keyPath);
        continue;
      }
      if (isTable(value)) {
        walkTable(value, section === "" ? key : `${section}.${key}`, keyPath, unknown);
      }
    }
    return;
  }

  // A section keyed by author-chosen names: check each entry's contents.
  const named = `${section}.<n>`;
  if (SECTION_KEYS.has(named)) {
    for (const [name, value] of Object.entries(table)) {
      if (isTable(value)) {
        walkTable(value, named, `${path}.${name}`, unknown);
      }
    }
    return;
  }

  // Open map or opaque data: not walked.
}

function takeBool(table, section, key, fallback) {
  const value = table[key];
  if (value === undefined) return fallback;
  if (typeof value !== "boolean") {
    throw new Error(`Invalid manifest: ${section}.${key} must be a boolean`);
  }
  return value;
}

function takeInt(table, section, key, fallback) {
  const value = table[key];
  if (value === undefined) return fallback;
  if (!Number.isInteger(value)) {
    throw new Error(`Invalid manifest: ${section}.${key} must be an integer`);
  }
  return value;
}

function requireTable(value, section) {
  if (value !== undefined && !isTable(value)) {
    throw new Error(`Invalid manifest: ${section} must be a table`);
  }
  return value;
}

/**
 * Load and parse a .clad.toml manifest file. Always strict: an unknown key in
 * any section is a load error.
 * @param {string} path - Path to the .clad.toml file
 * @returns {object} Parsed manifest object
 */
export function loadManifest(path) {
  return loadManifestWithOptions(path, {});
}

/**
 * Load a manifest with loader options. Library callers should use
 * `loadManifest`; this entry point exists for the CLI's `--allow-unknown-keys`
 * escape hatch.
 *
 * @param {string} path - Path to the .clad.toml file
 * @param {object} [options]
 * @param {boolean} [options.allowUnknownKeys=false] - Downgrade unknown keys
 *   from a load error to a warning on stderr
 * @param {object} [options.customTypes] - Custom type map (loadCustomTypes) to
 *   use instead of discovering `toolclad.toml`: `TOOLCLAD_CONFIG_FILE` if set
 *   (an unreadable path is an error), else `toolclad.toml` searched upward
 *   from the manifest's directory. Absent means no custom types.
 * @returns {object} Parsed manifest object
 */
export function loadManifestWithOptions(path, options = {}) {
  const content = readFileSync(path, "utf-8");
  return parseManifest(content, dirname(resolve(path)), options);
}

/**
 * Load a manifest from TOML source text. Same checks as `loadManifest`
 * (strict unless `allowUnknownKeys` is set); `toolclad.toml` and
 * `scope/scope.toml` are discovered upward from `options.baseDir`, which
 * defaults to the current working directory.
 *
 * @param {string} content - The .clad.toml source
 * @param {object} [options] - See loadManifestWithOptions, plus
 * @param {string} [options.baseDir=process.cwd()] - Directory discovery starts from
 * @returns {object} Parsed manifest object
 */
export function loadManifestFromString(content, options = {}) {
  return parseManifest(String(content), resolve(options.baseDir ?? process.cwd()), options);
}

function parseManifest(content, baseDir, options) {
  const { allowUnknownKeys = false } = options;
  const manifest = TOML.parse(content);

  // Key check runs on the raw parse result, before any structural validation,
  // so a typo cannot be masked by a default and every unknown key is reported.
  const unknown = findUnknownKeys(manifest);
  if (unknown.length > 0) {
    const messages = unknown.map((key) => `unknown key '${key}' in manifest`);
    if (!allowUnknownKeys) {
      throw new Error(messages.join("; "));
    }
    for (const message of messages) {
      console.warn(`warning: ${message}`);
    }
  }

  if (!manifest.tool || !manifest.tool.name) {
    throw new Error(`Invalid manifest: missing [tool] section or tool.name`);
  }
  const tool = manifest.tool;

  // Default and validate dispatch mode.
  const dispatch = tool.dispatch ?? "exec";
  if (dispatch !== "exec" && dispatch !== "callback") {
    throw new Error(
      `Invalid manifest: invalid dispatch '${dispatch}', must be 'exec' or 'callback'`
    );
  }
  tool.dispatch = dispatch;

  // tool.mode is advisory: when absent it follows the backend section present.
  if (tool.mode === undefined) {
    tool.mode = manifest.session ? "session" : manifest.browser ? "browser" : "oneshot";
  } else if (!TOOL_MODES.includes(tool.mode)) {
    throw new Error(
      `Invalid manifest: invalid tool.mode '${tool.mode}', must be one of ${TOOL_MODES.join(", ")}`
    );
  }

  // timeout_seconds defaults to 60; zero or negative is a load error.
  timeoutSeconds(manifest);

  // Keys registered ahead of the waves that enforce them: accept them, check
  // their shape, and give them inert defaults.
  tool.network_egress = takeBool(tool, "tool", "network_egress", false);
  tool.allow_interpreter = takeBool(tool, "tool", "allow_interpreter", false);
  if (requireTable(tool.evidence, "tool.evidence")) {
    tool.evidence.screenshots = takeBool(tool.evidence, "tool.evidence", "screenshots", false);
  }
  if (requireTable(tool.limits, "tool.limits")) {
    for (const key of LIMIT_KEYS) {
      takeInt(tool.limits, "tool.limits", key, undefined);
    }
  }
  if (requireTable(manifest.output, "output")) {
    // 1..=1 GiB, default 8 MiB; a custom parser is refused (TC-12, TC-14).
    try {
      manifest.output.max_bytes = outputMaxBytes(manifest);
      checkOutputParser(manifest);
    } catch (err) {
      throw new Error(`Invalid manifest: ${err.message}`);
    }
  }
  if (requireTable(manifest.http, "http")) {
    // No interpolation into the scheme or host; literal host policy; header
    // names are tokens (TC-16).
    try {
      checkHttpDefinition(manifest);
    } catch (err) {
      throw new Error(`Invalid manifest: ${err.message}`);
    }
  }

  // Per-argument policy keys. `block_internal` is a real field with a false
  // default so the validator reads one value per argument instead of
  // guessing; `schemes` must be a list so the url allowlist never iterates
  // a string.
  if (requireTable(manifest.args, "args")) {
    for (const [name, def] of Object.entries(manifest.args)) {
      const section = `args.${name}`;
      if (!isTable(def)) {
        throw new Error(`Invalid manifest: ${section} must be a table`);
      }
      def.block_internal = takeBool(def, section, "block_internal", false);
      def.scope_check = takeBool(def, section, "scope_check", false);
      if (def.scope_check && BUILTIN_TYPES.has(def.type) && !SCOPE_CHECK_TYPES.includes(def.type)) {
        throw new Error(
          `Invalid manifest: ${section}: scope_check is not supported for type '${def.type}'`
        );
      }
      if (
        def.schemes !== undefined &&
        (!Array.isArray(def.schemes) ||
          !def.schemes.every((scheme) => typeof scheme === "string"))
      ) {
        throw new Error(
          `Invalid manifest: ${section}.schemes must be an array of strings`
        );
      }
    }
  }

  const isCallback = dispatch === "callback";

  // Callback dispatch is for validator-only embeddings — no backend or
  // [output] block is required because dispatch happens in-process.
  if (!isCallback) {
    const hasHttp = !!manifest.http;
    const hasMcp = !!manifest.mcp;
    const hasSession = !!manifest.session;
    const hasBrowser = !!manifest.browser;

    if (!hasHttp && !hasMcp && !hasSession && !hasBrowser) {
      if (!tool.binary && !(manifest.command && manifest.command.executor)) {
        throw new Error(
          `Invalid manifest: must specify tool.binary, command.executor, [http], [mcp], [session], or [browser] (or set tool.dispatch = "callback" for validator-only manifests)`
        );
      }
      if (!manifest.command) {
        throw new Error(`Invalid manifest: missing [command] section`);
      }
      if (!manifest.command.template && !manifest.command.exec && !manifest.command.executor) {
        throw new Error(
          `Invalid manifest: [command] must have template, exec, or executor`
        );
      }
      if (!manifest.output) {
        throw new Error(`Invalid manifest: missing [output] section (or set tool.dispatch = "callback" for validator-only manifests)`);
      }
    }
  }

  // Compile [command] into its canonical exec form: tokenize a legacy
  // template, tokenize conditionals, check end_of_options, and verify every
  // placeholder names a declared variable.
  if (manifest.command) {
    compileCommand(manifest);
  }

  // Egress lint on every load. compileCommand already applied it to a
  // [command] manifest; an [http] / [browser] manifest may have no [command]
  // at all and is an egress manifest by definition.
  lintNetworkEgress(manifest);

  // Every declared type must be a built-in or a custom type from
  // toolclad.toml; then the checks that need the custom types (egress lint
  // with custom bases resolved, defaults, scope_check on custom types).
  const customTypes =
    options.customTypes !== undefined && options.customTypes !== null
      ? checkCustomTypeMap(options.customTypes, "customTypes option")
      : discoverCustomTypes(baseDir);
  checkArgTypes(manifest, customTypes);
  validateManifestWithCustomTypes(manifest, customTypes);

  // Recorded for scope discovery (scope/scope.toml is searched upward from
  // here); hidden so it never shows up in serialization or key walks.
  Object.defineProperty(manifest, MANIFEST_DIR, {
    value: baseDir,
    enumerable: false,
  });

  return manifest;
}

/**
 * Refuse any `[args.<n>].type` (including the args of `[session.commands.*]`
 * and `[browser.commands.*]`) that is neither built-in nor a custom type.
 * @param {object} manifest
 * @param {object} customTypes
 */
function checkArgTypes(manifest, customTypes) {
  const check = (args) => {
    if (!isTable(args)) return;
    for (const [name, def] of Object.entries(args)) {
      if (!isTable(def)) continue;
      const type = def.type;
      if (BUILTIN_TYPES.has(type)) continue;
      if (typeof type === "string" && Object.hasOwn(customTypes, type)) continue;
      throw new Error(`Invalid manifest: unknown type '${type}' for argument '${name}'`);
    }
  };
  check(manifest.args);
  for (const section of ["session", "browser"]) {
    const commands = manifest[section] && manifest[section].commands;
    if (!isTable(commands)) continue;
    for (const cmd of Object.values(commands)) {
      if (isTable(cmd)) check(cmd.args);
    }
  }
}

/**
 * Find and load `toolclad.toml`: `TOOLCLAD_CONFIG_FILE` first (an unreadable
 * path is an error), else `toolclad.toml` searched upward from `startDir` to
 * the filesystem root. No file means no custom types.
 * @param {string} [startDir=process.cwd()]
 * @returns {object} Custom type map (empty when no file exists)
 */
export function discoverCustomTypes(startDir) {
  const env = process.env.TOOLCLAD_CONFIG_FILE;
  if (env !== undefined && env !== "") {
    return loadCustomTypes(resolve(env));
  }
  let dir = resolve(startDir ?? process.cwd());
  for (;;) {
    const candidate = join(dir, "toolclad.toml");
    if (existsSync(candidate)) {
      return loadCustomTypes(candidate);
    }
    const parent = dirname(dir);
    if (parent === dir) return {};
    dir = parent;
  }
}

/**
 * Validate every declared `[args.<n>].default` through the strict pipeline:
 * a default that fails its own type is a manifest bug and a load error.
 * Custom types are checked when the custom type map is supplied.
 * @param {object} manifest
 * @param {object} [customTypes]
 */
function validateArgDefaults(manifest, customTypes) {
  for (const [name, def] of Object.entries(manifest.args || {})) {
    if (def.default === undefined) continue;
    if (!BUILTIN_TYPES.has(def.type) && !(customTypes && Object.hasOwn(customTypes, def.type))) {
      continue;
    }
    if (def.type === "string" && def.default === "") continue;
    try {
      validateDefaultValue(def, def.default, customTypes);
    } catch (err) {
      throw new Error(`Invalid manifest: args.${name}.default is invalid: ${err.message}`);
    }
  }
}

/**
 * Manifest checks that need the custom type map, run after loading: the
 * egress lint with custom types resolved, so an egress manifest whose
 * network target is declared through a custom type is refused (a custom
 * type definition cannot carry `block_internal`). Every loader runs it with
 * the discovered (or supplied) custom types; it is exported for embedders
 * that build a manifest in memory.
 *
 * @param {object} manifest - A loaded or in-memory manifest
 * @param {object} customTypes - Map from loadCustomTypes
 * @returns {object} The same manifest
 */
export function validateManifestWithCustomTypes(manifest, customTypes) {
  if (manifest.command) {
    compileCommand(manifest);
  }
  lintNetworkEgress(manifest, customTypes || {});
  validateArgDefaults(manifest, customTypes || {});
  for (const [name, def] of Object.entries(manifest.args || {})) {
    const custom = customTypes && Object.hasOwn(customTypes, def.type) ? customTypes[def.type] : null;
    if (def.scope_check === true && custom && !SCOPE_CHECK_TYPES.includes(custom.base)) {
      throw new Error(
        `Invalid manifest: args.${name}: scope_check is not supported for type '${def.type}'`
      );
    }
  }
  // Argument validation (execute, dry run, HTTP, MCP) uses this map.
  Object.defineProperty(manifest, CUSTOM_TYPES, {
    value: customTypes || {},
    enumerable: false,
    writable: true,
    configurable: true,
  });
  return manifest;
}

/**
 * Load custom type definitions from a toolclad.toml file. Strict: an unknown
 * top-level key or `[types.<n>]` key is refused, and every `base` must be a
 * built-in type (a custom type cannot build on another custom type).
 * @param {string} path - Path to toolclad.toml
 * @returns {object} Map of type name to custom type definition
 */
export function loadCustomTypes(path) {
  let content;
  try {
    content = readFileSync(path, "utf-8");
  } catch (err) {
    throw new Error(`cannot read custom type file ${path}: ${err.message}`);
  }
  let config;
  try {
    config = TOML.parse(content);
  } catch (err) {
    throw new Error(`${path}: ${err.message}`);
  }
  for (const key of Object.keys(config)) {
    if (key !== "types") {
      throw new Error(`${path}: unknown key '${key}' in toolclad.toml`);
    }
  }
  if (config.types !== undefined && !isTable(config.types)) {
    throw new Error(`${path}: types must be a table`);
  }
  try {
    return checkCustomTypeMap(config.types || {}, path);
  } catch (err) {
    throw new Error(err.message.startsWith(path) ? err.message : `${path}: ${err.message}`);
  }
}

/**
 * Validate and normalize a custom type map (from toolclad.toml or supplied
 * by an embedder).
 * @param {object} raw
 * @param {string} where - Source named in error messages
 * @returns {object} Normalized map
 */
function checkCustomTypeMap(raw, where) {
  if (!isTable(raw)) {
    throw new Error(`${where}: custom types must be a table`);
  }
  const types = {};
  for (const [name, def] of Object.entries(raw)) {
    if (!isTable(def)) {
      throw new Error(`${where}: types.${name} must be a table`);
    }
    for (const key of Object.keys(def)) {
      if (!CUSTOM_TYPE_KEYS.has(key)) {
        throw new Error(`${where}: unknown key 'types.${name}.${key}' in toolclad.toml`);
      }
    }
    if (BUILTIN_TYPES.has(name)) {
      throw new Error(`${where}: custom type '${name}' shadows a built-in type`);
    }
    if (!def.base) {
      throw new Error(`Custom type '${name}' missing required 'base' field`);
    }
    if (!BUILTIN_TYPES.has(def.base)) {
      throw new Error(
        `Custom type '${name}' has base '${def.base}', which is not a built-in type`
      );
    }
    if (def.allowed !== undefined && (!Array.isArray(def.allowed) || !def.allowed.every((v) => typeof v === "string"))) {
      throw new Error(`${where}: types.${name}.allowed must be an array of strings`);
    }
    if (def.pattern !== undefined && typeof def.pattern !== "string") {
      throw new Error(`${where}: types.${name}.pattern must be a string`);
    }
    for (const key of ["min", "max", "min_float", "max_float"]) {
      if (def[key] !== undefined && typeof def[key] !== "number") {
        throw new Error(`${where}: types.${name}.${key} must be a number`);
      }
    }
    types[name] = {
      base: def.base,
      allowed: def.allowed || undefined,
      pattern: def.pattern || undefined,
      min: def.min ?? undefined,
      max: def.max ?? undefined,
      min_float: def.min_float ?? undefined,
      max_float: def.max_float ?? undefined,
    };
  }
  return types;
}
