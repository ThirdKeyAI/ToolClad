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

  // v0.5.0: http and mcp modes do not require binary or command sections
  const hasHttp = !!manifest.http;
  const hasMcp = !!manifest.mcp;

  if (!hasHttp && !hasMcp) {
    if (!manifest.tool.binary && !(manifest.command && manifest.command.executor)) {
      throw new Error(
        `Invalid manifest: must specify tool.binary, command.executor, [http], or [mcp]`
      );
    }
    if (!manifest.command) {
      throw new Error(`Invalid manifest: missing [command] section`);
    }
    if (!manifest.command.template && !manifest.command.executor) {
      throw new Error(
        `Invalid manifest: [command] must have template or executor`
      );
    }
    if (!manifest.output) {
      throw new Error(`Invalid manifest: missing [output] section`);
    }
  }

  return manifest;
}
