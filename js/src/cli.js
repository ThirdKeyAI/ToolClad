#!/usr/bin/env node

import { Command } from "commander";
import { loadManifest } from "./manifest.js";
import { buildCommand, execute, generateMcpSchema } from "./executor.js";

const program = new Command();

program
  .name("toolclad")
  .description("ToolClad manifest executor")
  .version("0.1.0");

program
  .command("validate <manifest>")
  .description("Validate a .clad.toml manifest file")
  .action((manifestPath) => {
    try {
      const manifest = loadManifest(manifestPath);
      console.log(`${manifestPath}  OK  (tool: ${manifest.tool.name})`);
    } catch (err) {
      console.error(`${manifestPath}  ERROR: ${err.message}`);
      process.exit(1);
    }
  });

program
  .command("run <manifest>")
  .description("Execute a tool using its manifest")
  .option("--arg <args...>", "Arguments as key=value pairs")
  .action((manifestPath, opts) => {
    try {
      const manifest = loadManifest(manifestPath);
      const args = parseArgs(opts.arg);
      const result = execute(manifest, args);
      console.log(JSON.stringify(result, null, 2));
    } catch (err) {
      console.error(`Error: ${err.message}`);
      process.exit(1);
    }
  });

program
  .command("schema <manifest>")
  .description("Output MCP JSON schema for a manifest")
  .action((manifestPath) => {
    try {
      const manifest = loadManifest(manifestPath);
      const schema = generateMcpSchema(manifest);
      console.log(JSON.stringify(schema, null, 2));
    } catch (err) {
      console.error(`Error: ${err.message}`);
      process.exit(1);
    }
  });

program
  .command("test <manifest>")
  .description("Dry run: validate args and show constructed command")
  .option("--arg <args...>", "Arguments as key=value pairs")
  .action((manifestPath, opts) => {
    try {
      const manifest = loadManifest(manifestPath);
      const args = parseArgs(opts.arg);
      const result = execute(manifest, args, { dryRun: true });
      console.log();
      console.log(`  Manifest:  ${manifestPath}`);
      console.log(`  Tool:      ${manifest.tool.name}`);
      console.log(`  Arguments: ${formatArgs(result.resolvedArgs)}`);
      console.log(`  Command:   ${result.command}`);
      if (manifest.tool.cedar) {
        console.log(
          `  Cedar:     ${manifest.tool.cedar.resource} / ${manifest.tool.cedar.action}`
        );
      }
      console.log(`  Timeout:   ${manifest.tool.timeout_seconds || 30}s`);
      console.log();
      console.log("  [dry run -- command not executed]");
      console.log();
    } catch (err) {
      console.error(`Error: ${err.message}`);
      process.exit(1);
    }
  });

function parseArgs(argList) {
  const result = {};
  if (!argList) return result;
  for (const item of argList) {
    const eqIdx = item.indexOf("=");
    if (eqIdx === -1) {
      throw new Error(`Invalid argument format: "${item}" (expected key=value)`);
    }
    result[item.slice(0, eqIdx)] = item.slice(eqIdx + 1);
  }
  return result;
}

function formatArgs(args) {
  return Object.entries(args)
    .map(([k, v]) => `${k}=${v}`)
    .join(", ");
}

program.parse();
