import { spawnSync } from "node:child_process";
import { randomBytes, createHash } from "node:crypto";
import { validateArg } from "./validator.js";

/**
 * Resolve all argument values: apply defaults, validate types, resolve mappings.
 *
 * @param {object} manifest - Parsed manifest
 * @param {object} args - User-supplied arguments (key=value)
 * @returns {object} Validated argument map
 */
function resolveArgs(manifest, args) {
  const argDefs = manifest.args || {};
  const resolved = {};

  for (const [name, def] of Object.entries(argDefs)) {
    let value = args[name];

    // Apply default if missing
    if (value === undefined || value === null) {
      if (def.required && def.default === undefined) {
        throw new Error(`Missing required argument: ${name}`);
      }
      value = def.default;
      if (value === undefined) continue;
    }

    resolved[name] = validateArg(def, value);
  }

  return resolved;
}

/**
 * Build the final command string from a manifest template and validated args.
 *
 * @param {object} manifest - Parsed manifest
 * @param {object} args - User-supplied arguments (key=value)
 * @returns {{ command: string, resolvedArgs: object }} The constructed command and resolved args
 */
export function buildCommand(manifest, args) {
  const resolvedArgs = resolveArgs(manifest, args);
  const command = manifest.command;

  // If using an executor script, return that info
  if (command.executor) {
    return { command: command.executor, resolvedArgs, isExecutor: true };
  }

  let template = command.template;

  // Build the interpolation context from resolved args + defaults
  const context = { ...resolvedArgs };

  // Apply command.defaults
  if (command.defaults) {
    for (const [key, val] of Object.entries(command.defaults)) {
      if (context[key] === undefined) {
        context[key] = val;
      }
    }
  }

  // Generate executor-injected variables
  const scanId = `${Math.floor(Date.now() / 1000)}-${randomBytes(2).toString("hex")}`;
  context._scan_id = scanId;
  context._output_file = `/tmp/toolclad-${scanId}-output`;
  context._evidence_dir = process.env.TOOLCLAD_EVIDENCE_DIR || "/tmp/toolclad-evidence";

  // Resolve mappings: e.g. scan_type -> _scan_flags
  if (command.mappings) {
    for (const [argName, mapping] of Object.entries(command.mappings)) {
      const argValue = context[argName];
      if (argValue !== undefined && mapping[argValue] !== undefined) {
        // Convention: mapping resolves to _{argName}_flags or the first
        // underscore-prefixed placeholder that references this mapping
        context[`_${argName}_flags`] = mapping[argValue];
        // Also try the generic _scan_flags for backward compat
        context["_scan_flags"] = mapping[argValue];
      }
    }
  }

  // Resolve conditionals
  if (command.conditionals) {
    for (const [name, cond] of Object.entries(command.conditionals)) {
      const result = evaluateCondition(cond.when, context);
      context[`_cond_${name}`] = result ? interpolate(cond.template, context) : "";
    }
  }

  // Interpolate the template
  const result = interpolate(template, context);

  // Clean up multiple spaces
  return {
    command: result.replace(/\s+/g, " ").trim(),
    resolvedArgs,
    isExecutor: false,
  };
}

/**
 * Interpolate {placeholder} references in a template string.
 */
function interpolate(template, context) {
  return template.replace(/\{(\w+)\}/g, (match, key) => {
    const val = context[key];
    if (val === undefined) return "";
    return String(val);
  });
}

/**
 * Evaluate a simple condition expression against the context.
 * Supports: "key != value", "key == value", "key != '' and other_key == ''"
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
 * Execute a tool using its manifest and supplied arguments.
 * Validates args, builds command, spawns process, wraps output in evidence envelope.
 *
 * @param {object} manifest - Parsed manifest
 * @param {object} args - User-supplied arguments (key=value)
 * @param {object} [options] - Execution options
 * @param {boolean} [options.dryRun=false] - If true, build command but don't execute
 * @returns {object} Evidence envelope with results
 */
export function execute(manifest, args, options = {}) {
  const { command, resolvedArgs, isExecutor } = buildCommand(manifest, args);

  if (options.dryRun) {
    return {
      status: "dry_run",
      tool: manifest.tool.name,
      command,
      resolvedArgs,
    };
  }

  const timeoutMs = (manifest.tool.timeout_seconds || 30) * 1000;
  const startTime = Date.now();

  let result;

  if (isExecutor) {
    // Escape hatch: pass validated args as env vars
    const env = { ...process.env };
    for (const [key, val] of Object.entries(resolvedArgs)) {
      env[`TOOLCLAD_ARG_${key.toUpperCase()}`] = String(val);
    }
    env.TOOLCLAD_SCAN_ID = `${Math.floor(Date.now() / 1000)}-${randomBytes(2).toString("hex")}`;
    env.TOOLCLAD_EVIDENCE_DIR =
      process.env.TOOLCLAD_EVIDENCE_DIR || "/tmp/toolclad-evidence";

    result = spawnSync(command, {
      shell: true,
      timeout: timeoutMs,
      env,
      encoding: "utf-8",
      maxBuffer: 10 * 1024 * 1024,
    });
  } else {
    result = spawnSync(command, {
      shell: true,
      timeout: timeoutMs,
      encoding: "utf-8",
      maxBuffer: 10 * 1024 * 1024,
    });
  }

  const durationMs = Date.now() - startTime;
  const stdout = result.stdout || "";
  const stderr = result.stderr || "";
  const exitCode = result.status;

  const scanId = `${Math.floor(startTime / 1000)}-${randomBytes(2).toString("hex")}`;
  const outputHash = createHash("sha256").update(stdout).digest("hex");

  // Build evidence envelope
  const envelope = {
    status: exitCode === 0 ? "success" : "error",
    scan_id: scanId,
    tool: manifest.tool.name,
    command,
    duration_ms: durationMs,
    timestamp: new Date(startTime).toISOString(),
    output_hash: `sha256:${outputHash}`,
  };

  if (exitCode !== 0) {
    envelope.error = stderr || `Process exited with code ${exitCode}`;
    envelope.results = { raw_output: stdout };
  } else {
    envelope.results = { raw_output: stdout };
  }

  return envelope;
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
    const prop = {
      type: mcpType(def.type),
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

function mcpType(toolcladType) {
  switch (toolcladType) {
    case "integer":
    case "port":
      return "integer";
    case "boolean":
      return "boolean";
    default:
      return "string";
  }
}

function buildOutputSchema(manifest) {
  const results = manifest.output.schema || { type: "object" };

  if (manifest.output.envelope !== false) {
    return {
      type: "object",
      properties: {
        status: { type: "string", enum: ["success", "error"] },
        scan_id: { type: "string" },
        tool: { type: "string" },
        command: { type: "string" },
        duration_ms: { type: "integer" },
        timestamp: { type: "string", format: "date-time" },
        output_hash: { type: "string" },
        results,
      },
    };
  }

  return results;
}
