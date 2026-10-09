#!/usr/bin/env node

import { createRequire } from "node:module";
import { Command } from "commander";
import { loadManifest, loadManifestWithOptions } from "./manifest.js";
// loadManifest discovers toolclad.toml (custom types) and checks every
// argument type at load, so validate/run/test/schema all share one path.
import { defaultGate, execute, generateMcpSchema } from "./executor.js";

const { version } = createRequire(import.meta.url)("../package.json");

const program = new Command();

program
  .name("toolclad")
  .description("ToolClad manifest executor")
  .version(version);

program
  .command("validate <manifest>")
  .description("Validate a .clad.toml manifest file")
  .option(
    "--allow-unknown-keys",
    "Downgrade unknown manifest keys from an error to a warning on stderr"
  )
  .action((manifestPath, opts) => {
    try {
      const manifest = loadManifestWithOptions(manifestPath, {
        allowUnknownKeys: opts.allowUnknownKeys === true,
      });
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
  .option(
    "--approve",
    "Approve this call: use the allow-all policy gate instead of the default gate"
  )
  .action(async (manifestPath, opts) => {
    try {
      const manifest = loadManifest(manifestPath);
      const args = parseArgs(opts.arg);
      const result = await execute(manifest, args, { approve: opts.approve === true });
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
  .action(async (manifestPath, opts) => {
    try {
      const manifest = loadManifest(manifestPath);
      const args = parseArgs(opts.arg);
      const result = await execute(manifest, args, { dryRun: true });
      console.log();
      console.log(`  Manifest:  ${manifestPath}`);
      console.log(`  Tool:      ${manifest.tool.name}`);
      console.log(`  Arguments: ${formatArgs(result.resolvedArgs)}`);
      console.log(`  Command:   ${result.command}`);
      if (result.argv) {
        console.log(`  Argv:      ${JSON.stringify(result.argv)}`);
      }
      if (manifest.tool.cedar) {
        console.log(
          `  Cedar:     ${manifest.tool.cedar.resource} / ${manifest.tool.cedar.action}`
        );
      }
      console.log(`  Timeout:   ${manifest.tool.timeout_seconds || 60}s`);
      const gate = defaultGate(manifest, result.resolvedArgs || {});
      console.log(`  Risk tier: ${manifest.tool.risk_tier || "(none)"}`);
      console.log(
        `  Approval:  ${gate.allowed ? "not required" : `required (${gate.reason}); pass --approve to run`}`
      );
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

await program.parseAsync();
