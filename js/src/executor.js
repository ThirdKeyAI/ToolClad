import { spawnSync } from "node:child_process";
import { randomBytes, createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { validateArg } from "./validator.js";

/**
 * Replace {_secret:name} placeholders with TOOLCLAD_SECRET_<NAME> env vars.
 * @param {string} template - Template string with optional {_secret:name} vars
 * @returns {string} Template with secrets injected from environment
 */
export function injectTemplateVars(template) {
  return template.replace(/\{_secret:(\w+)\}/g, (_match, name) => {
    const envKey = `TOOLCLAD_SECRET_${name.toUpperCase()}`;
    const val = process.env[envKey];
    if (val === undefined) {
      throw new Error(`Missing environment variable: ${envKey}`);
    }
    return val;
  });
}

/**
 * Split a command string into an array of arguments, respecting quoted strings.
 * This avoids shell interpretation when passing to spawnSync.
 * @param {string} cmd - The command string to split
 * @returns {string[]} Array of arguments
 */
function splitCommand(cmd) {
  const args = [];
  let current = "";
  let inSingle = false;
  let inDouble = false;
  for (let i = 0; i < cmd.length; i++) {
    const c = cmd[i];
    if (c === "'" && !inDouble) {
      inSingle = !inSingle;
    } else if (c === '"' && !inSingle) {
      inDouble = !inDouble;
    } else if (c === " " && !inSingle && !inDouble) {
      if (current.length > 0) {
        args.push(current);
        current = "";
      }
    } else {
      current += c;
    }
  }
  if (current.length > 0) {
    args.push(current);
  }
  return args;
}

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
 * Resolve all template variables: args, defaults, mappings, conditionals,
 * and executor-injected variables into a single interpolation context.
 *
 * @param {object} manifest - Parsed manifest
 * @param {object} args - User-supplied arguments (key=value)
 * @returns {{ resolvedArgs: object, context: object }}
 */
function resolveContext(manifest, args) {
  const resolvedArgs = resolveArgs(manifest, args);
  const command = manifest.command;
  const context = { ...resolvedArgs };

  if (command.defaults) {
    for (const [key, val] of Object.entries(command.defaults)) {
      if (context[key] === undefined) {
        context[key] = val;
      }
    }
  }

  const scanId = `${Math.floor(Date.now() / 1000)}-${randomBytes(2).toString("hex")}`;
  context._scan_id = scanId;
  context._output_file = `/tmp/toolclad-${scanId}-output`;
  context._evidence_dir = process.env.TOOLCLAD_EVIDENCE_DIR || join(tmpdir(), "toolclad-evidence");

  if (command.mappings) {
    for (const [argName, mapping] of Object.entries(command.mappings)) {
      const argValue = context[argName];
      if (argValue !== undefined && mapping[argValue] !== undefined) {
        context[`_${argName}_flags`] = mapping[argValue];
        context["_scan_flags"] = mapping[argValue];
      }
    }
  }

  if (command.conditionals) {
    for (const [name, cond] of Object.entries(command.conditionals)) {
      const result = evaluateCondition(cond.when, context);
      context[`_cond_${name}`] = result ? interpolate(cond.template, context) : "";
    }
  }

  return { resolvedArgs, context };
}

/**
 * Build an argv array from the manifest's exec field and validated args.
 * Each element is interpolated independently, preserving argument boundaries.
 * This avoids the template→string→split round-trip that breaks when values
 * contain spaces or quote characters.
 *
 * @param {object} manifest - Parsed manifest
 * @param {object} args - User-supplied arguments (key=value)
 * @returns {{ argv: string[], resolvedArgs: object }}
 */
export function buildCommandArgv(manifest, args) {
  const execArray = manifest.command.exec;
  if (!execArray || execArray.length === 0) {
    throw new Error("Manifest has no exec array");
  }

  const { resolvedArgs, context } = resolveContext(manifest, args);
  const argv = execArray.map((element) => interpolate(element, context));

  if (argv.length === 0 || !argv[0]) {
    throw new Error("exec array produced empty argv");
  }

  return { argv, resolvedArgs };
}

/**
 * Build the final command string from a manifest template and validated args.
 * For new manifests, prefer buildCommandArgv with the exec array format.
 *
 * @param {object} manifest - Parsed manifest
 * @param {object} args - User-supplied arguments (key=value)
 * @returns {{ command: string, resolvedArgs: object }} The constructed command and resolved args
 */
export function buildCommand(manifest, args) {
  const command = manifest.command;

  // If using an executor script, return that info
  if (command.executor) {
    const resolvedArgs = resolveArgs(manifest, args);
    return { command: command.executor, resolvedArgs, isExecutor: true };
  }

  const { resolvedArgs, context } = resolveContext(manifest, args);
  const result = interpolate(command.template, context);

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

  // Route to HTTP backend (synchronous via curl)
  if (manifest.http) {
    return executeHttpSync(manifest, args, options);
  }

  // Route to MCP proxy backend
  if (manifest.mcp) {
    return executeMcp(manifest, args);
  }

  // Determine if we're using exec array, template, or custom executor.
  let cmdParts;
  let commandDisplay;
  let resolvedArgs;
  let isExecutor = false;

  if (manifest.command.exec && manifest.command.exec.length > 0) {
    // PREFERRED: Array-based command — maps directly to execve, no splitting.
    const built = buildCommandArgv(manifest, args);
    cmdParts = built.argv;
    resolvedArgs = built.resolvedArgs;
    commandDisplay = cmdParts.join(" ");
  } else {
    const built = buildCommand(manifest, args);
    commandDisplay = built.command;
    resolvedArgs = built.resolvedArgs;
    isExecutor = built.isExecutor;
    cmdParts = splitCommand(built.command);
  }

  if (options.dryRun) {
    return {
      status: "dry_run",
      tool: manifest.tool.name,
      command: commandDisplay,
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
      process.env.TOOLCLAD_EVIDENCE_DIR || join(tmpdir(), "toolclad-evidence");

    result = spawnSync(cmdParts[0], cmdParts.slice(1), {
      shell: false,
      timeout: timeoutMs,
      detached: true,
      env,
      encoding: "utf-8",
      maxBuffer: 10 * 1024 * 1024,
    });
  } else {
    result = spawnSync(cmdParts[0], cmdParts.slice(1), {
      shell: false,
      timeout: timeoutMs,
      detached: true,
      encoding: "utf-8",
      maxBuffer: 10 * 1024 * 1024,
    });
  }

  // On timeout, kill the entire process group.
  if (result.signal === "SIGTERM" && result.pid) {
    try {
      process.kill(-result.pid, "SIGKILL");
    } catch {
      // Process group may already be gone.
    }
  }

  const durationMs = Date.now() - startTime;
  const stdout = result.stdout || "";
  const stderr = result.stderr || "";
  const exitCode = result.status;

  const scanId = `${Math.floor(startTime / 1000)}-${randomBytes(2).toString("hex")}`;
  const outputHash = createHash("sha256").update(stdout).digest("hex");

  // Build evidence envelope with exit_code and stderr on all paths.
  const envelope = {
    status: exitCode === 0 ? "success" : "error",
    scan_id: scanId,
    tool: manifest.tool.name,
    command: commandDisplay,
    exit_code: exitCode ?? -1,
    stderr,
    duration_ms: durationMs,
    timestamp: new Date(startTime).toISOString(),
    output_hash: `sha256:${outputHash}`,
  };

  if (exitCode !== 0) {
    envelope.error = stderr || `Process exited with code ${exitCode}`;
    envelope.results = { raw_output: stdout };
  } else {
    envelope.results = parseOutputJs(manifest, stdout);
  }

  return envelope;
}

/**
 * Parse tool output based on the manifest's output.format / output.parser.
 *
 * @param {object} manifest - Parsed manifest
 * @param {string} raw - Raw output string
 * @returns {object} Parsed results
 */
function parseOutputJs(manifest, raw) {
  const format = manifest.output?.format || "text";
  const parser = manifest.output?.parser || `builtin:${format}`;

  switch (parser) {
    case "builtin:json": {
      try {
        return JSON.parse(raw);
      } catch {
        return { raw_output: raw };
      }
    }
    case "builtin:jsonl": {
      try {
        const lines = raw.trim().split("\n").filter(l => l.trim());
        return { parsed_output: lines.map(l => JSON.parse(l)) };
      } catch {
        return { raw_output: raw };
      }
    }
    case "builtin:csv": {
      return { parsed_output: parseCsv(raw) };
    }
    case "builtin:xml": {
      return parseXmlToJson(raw);
    }
    default:
      return { raw_output: raw };
  }
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
 * and self-closing tags. Falls back to raw_output on parse failure.
 */
function parseXmlToJson(xml) {
  const trimmed = xml.trim();
  if (!trimmed) return { raw_output: "" };

  try {
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
          const tagEnd = trimmed.indexOf(">", pos);
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
          const end = trimmed.indexOf(">", pos);
          pos = end + 1;
        } else {
          // Opening tag
          const tagEnd = trimmed.indexOf(">", pos);
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

    if (currentName) {
      const root = {};
      root[currentName] = currentObj;
      return root;
    }
    return currentObj;
  } catch {
    return { raw_output: xml };
  }
}

/**
 * Execute an HTTP manifest synchronously using curl via spawnSync.
 *
 * @param {object} manifest - Parsed manifest with http section
 * @param {object} args - User-supplied arguments (key=value)
 * @param {object} [options] - Execution options
 * @param {boolean} [options.dryRun=false] - If true, build request but don't execute
 * @returns {object} Evidence envelope with http_status
 */
function executeHttpSync(manifest, args, options = {}) {
  const httpDef = manifest.http;
  if (!httpDef || !httpDef.url) {
    throw new Error("Manifest missing [http] section or http.url");
  }

  const resolvedArgs = resolveArgs(manifest, args);
  const context = { ...resolvedArgs };

  let url = interpolate(httpDef.url, context);
  url = injectTemplateVars(url);

  const headers = {};
  if (httpDef.headers) {
    for (const [key, val] of Object.entries(httpDef.headers)) {
      headers[key] = injectTemplateVars(interpolate(val, context));
    }
  }

  let body = undefined;
  if (httpDef.body_template) {
    // JSON-escape values for safe interpolation into body templates
    const escaped = {};
    for (const [k, v] of Object.entries(context)) {
      escaped[k] = JSON.stringify(String(v)).slice(1, -1);
    }
    body = injectTemplateVars(interpolate(httpDef.body_template, escaped));
  }

  const method = (httpDef.method || "GET").toUpperCase();
  const scanId = `${Math.floor(Date.now() / 1000)}-${randomBytes(2).toString("hex")}`;

  if (options.dryRun) {
    return {
      status: "dry_run",
      scan_id: scanId,
      tool: manifest.tool.name,
      command: `${method} ${url}`,
      timestamp: new Date().toISOString(),
    };
  }

  // Build curl arguments for synchronous HTTP execution
  const curlArgs = ["-s", "-S", "-X", method, "-w", "\n%{http_code}"];
  for (const [k, v] of Object.entries(headers)) {
    curlArgs.push("-H", `${k}: ${v}`);
  }
  if (body && method !== "GET" && method !== "HEAD") {
    curlArgs.push("-d", body);
  }
  const timeout = manifest.tool.timeout_seconds || 30;
  curlArgs.push("--max-time", String(timeout));
  curlArgs.push(url);

  const startTime = Date.now();
  const result = spawnSync("curl", curlArgs, {
    encoding: "utf-8",
    timeout: (timeout + 5) * 1000,
  });

  const durationMs = Date.now() - startTime;
  const output = (result.stdout || "").trim();
  const lines = output.split("\n");
  const statusCode = parseInt(lines.pop(), 10) || 0;
  const respBody = lines.join("\n");

  const outputHash = createHash("sha256").update(respBody).digest("hex");

  const successStatus = httpDef.success_status || [200, 201, 202, 204];
  const isSuccess = successStatus.includes(statusCode);

  let status;
  if (isSuccess) {
    status = "success";
  } else if (statusCode >= 400 && statusCode < 500) {
    status = `client_error (HTTP ${statusCode})`;
  } else if (statusCode >= 500 && statusCode < 600) {
    status = `server_error (HTTP ${statusCode})`;
  } else {
    status = `error (HTTP ${statusCode})`;
  }

  return {
    status,
    scan_id: scanId,
    tool: manifest.tool.name,
    command: `${method} ${url}`,
    http_status: statusCode,
    exit_code: result.status ?? -1,
    stderr: result.stderr || "",
    duration_ms: durationMs,
    timestamp: new Date(startTime).toISOString(),
    output_hash: `sha256:${outputHash}`,
    results: parseOutputJs(manifest, respBody),
  };
}

/**
 * Execute a tool via HTTP when the manifest has an [http] section.
 * Uses Node 18+ built-in fetch.
 *
 * @param {object} manifest - Parsed manifest with http section
 * @param {object} args - User-supplied arguments (key=value)
 * @param {object} [options] - Execution options
 * @param {boolean} [options.dryRun=false] - If true, build request but don't execute
 * @returns {Promise<object>} Evidence envelope with http_status
 */
export async function executeHttp(manifest, args, options = {}) {
  const httpDef = manifest.http;
  if (!httpDef || !httpDef.url) {
    throw new Error("Manifest missing [http] section or http.url");
  }

  const resolvedArgs = resolveArgs(manifest, args);
  const context = { ...resolvedArgs };

  // Interpolate URL with args and template vars
  let url = interpolate(httpDef.url, context);
  url = injectTemplateVars(url);

  // Interpolate headers
  const headers = {};
  if (httpDef.headers) {
    for (const [key, val] of Object.entries(httpDef.headers)) {
      headers[key] = injectTemplateVars(interpolate(val, context));
    }
  }

  // Interpolate body
  let body = undefined;
  if (httpDef.body_template) {
    body = injectTemplateVars(interpolate(httpDef.body_template, context));
  }

  const method = (httpDef.method || "GET").toUpperCase();

  if (options.dryRun) {
    return {
      status: "dry_run",
      tool: manifest.tool.name,
      http_method: method,
      http_url: url,
      http_headers: headers,
      http_body: body,
      resolvedArgs,
    };
  }

  const startTime = Date.now();
  const scanId = `${Math.floor(startTime / 1000)}-${randomBytes(2).toString("hex")}`;

  const fetchOptions = { method, headers };
  if (body && method !== "GET" && method !== "HEAD") {
    fetchOptions.body = body;
  }

  const response = await fetch(url, fetchOptions);
  const responseBody = await response.text();
  const durationMs = Date.now() - startTime;
  const outputHash = createHash("sha256").update(responseBody).digest("hex");

  const successStatus = httpDef.success_status || [200, 201, 202, 204];
  const isSuccess = successStatus.includes(response.status);

  const envelope = {
    status: isSuccess ? "success" : "error",
    scan_id: scanId,
    tool: manifest.tool.name,
    http_status: response.status,
    duration_ms: durationMs,
    timestamp: new Date(startTime).toISOString(),
    output_hash: `sha256:${outputHash}`,
  };

  if (isSuccess) {
    envelope.results = { raw_output: responseBody };
  } else {
    envelope.error = `HTTP ${response.status}: ${responseBody.slice(0, 500)}`;
    envelope.results = { raw_output: responseBody };
  }

  return envelope;
}

/**
 * Proxy a tool invocation to an MCP server when the manifest has an [mcp] section.
 * Performs field mapping and returns a delegated envelope.
 *
 * @param {object} manifest - Parsed manifest with mcp section
 * @param {object} args - User-supplied arguments (key=value)
 * @returns {object} Evidence envelope with status "delegated"
 */
export function executeMcp(manifest, args) {
  const mcpDef = manifest.mcp;
  if (!mcpDef || !mcpDef.server || !mcpDef.tool) {
    throw new Error("Manifest missing [mcp] section or mcp.server/mcp.tool");
  }

  const resolvedArgs = resolveArgs(manifest, args);

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
  const scanId = `${Math.floor(startTime / 1000)}-${randomBytes(2).toString("hex")}`;

  return {
    status: "delegation_preview",
    scan_id: scanId,
    tool: manifest.tool.name,
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
    const typeInfo = mcpTypeAndConstraints(def.type);
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

function mcpTypeAndConstraints(toolcladType) {
  switch (toolcladType) {
    case "integer":
      return { type: "integer" };
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
        status: { type: "string", enum: ["success", "error"] },
        scan_id: { type: "string" },
        tool: { type: "string" },
        command: { type: "string" },
        exit_code: { type: "integer" },
        stderr: { type: "string" },
        duration_ms: { type: "integer" },
        timestamp: { type: "string", format: "date-time" },
        output_hash: { type: "string" },
        results,
      },
    };
  }

  return results;
}
