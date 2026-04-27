import { readFileSync } from "node:fs";
import TOML from "@iarna/toml";

/**
 * Load and parse a .clad.toml manifest file.
 * @param {string} path - Path to the .clad.toml file
 * @returns {object} Parsed manifest object
 */
export function loadManifest(path) {
  const content = readFileSync(path, "utf-8");
  const manifest = TOML.parse(content);

  if (!manifest.tool || !manifest.tool.name) {
    throw new Error(`Invalid manifest: missing [tool] section or tool.name`);
  }

  // Default and validate dispatch mode.
  const dispatch = manifest.tool.dispatch ?? "exec";
  if (dispatch !== "exec" && dispatch !== "callback") {
    throw new Error(
      `Invalid manifest: invalid dispatch '${dispatch}', must be 'exec' or 'callback'`
    );
  }
  manifest.tool.dispatch = dispatch;

  const isCallback = dispatch === "callback";

  // Callback dispatch is for validator-only embeddings — no backend or
  // [output] block is required because dispatch happens in-process.
  if (!isCallback) {
    const hasHttp = !!manifest.http;
    const hasMcp = !!manifest.mcp;
    const hasSession = !!manifest.session;
    const hasBrowser = !!manifest.browser;

    if (!hasHttp && !hasMcp && !hasSession && !hasBrowser) {
      if (!manifest.tool.binary && !(manifest.command && manifest.command.executor)) {
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

  return manifest;
}

/**
 * Load custom type definitions from a toolclad.toml file.
 * @param {string} path - Path to toolclad.toml
 * @returns {object} Map of type name to custom type definition
 */
export function loadCustomTypes(path) {
  const content = readFileSync(path, "utf-8");
  const config = TOML.parse(content);

  const types = {};
  if (config.types) {
    for (const [name, def] of Object.entries(config.types)) {
      if (!def.base) {
        throw new Error(`Custom type '${name}' missing required 'base' field`);
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
  }

  return types;
}
