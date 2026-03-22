---
title: Symbiont Integration
description: Using ToolClad with the Symbiont agentic runtime
---

# Symbiont Integration

ToolClad is the `tools/` directory convention for [Symbiont](https://symbiont.dev). The runtime auto-discovers `.clad.toml` manifests, registers them as MCP tools, wires them into the ORGA reasoning loop, and enforces Cedar policies -- all without writing Rust code.

## Runtime Discovery

On startup, the Symbiont runtime scans the `tools/` directory for `.clad.toml` files, the same way it scans `agents/` for `.dsl` files and `policies/` for `.cedar` files:

```
project/
  agents/
    recon.dsl
    enum.dsl
  policies/
    tool-authorization.cedar
    scope.cedar
  tools/
    nmap_scan.clad.toml
    whois_lookup.clad.toml
    nuclei_scan.clad.toml
    browser.clad.toml
  toolclad.toml               # Optional: project-level config, custom types
  symbiont.toml
```

The runtime:

1. Parses each `.clad.toml` file
2. Validates the manifest (required fields, type definitions, template references, output schema)
3. Registers each tool as an MCP tool with `inputSchema` derived from `[args]` and `outputSchema` derived from `[output.schema]`
4. Wires the tool to the ToolClad executor in the `ActionExecutor` pipeline

## DSL Tool Reference Resolution

DSL agents reference tools by name:

```dsl
capabilities = [
    "tool.nmap_scan",
    "tool.whois_lookup",
]
```

The runtime resolves `tool.nmap_scan` by looking up `nmap_scan` in the tool registry. Resolution order:

1. **ToolClad manifests** (`tools/nmap_scan.clad.toml`)
2. **Rust-registered tools** (legacy `register_tools()` in `src/*.rs`)
3. **MCP server tools** (from connected MCP servers in `symbiont.toml`)

ToolClad manifests take priority. This allows gradual migration: existing Rust tool definitions continue to work, and teams can convert them to manifests one at a time.

## MCP Schema Auto-Generation

The `[args]` section maps to MCP `inputSchema` and `[output.schema]` maps to MCP `outputSchema`:

```toml
# From nmap_scan.clad.toml
[args.target]
position = 1
required = true
type = "scope_target"
description = "Target CIDR, IP, or hostname"

[args.scan_type]
position = 2
required = true
type = "enum"
allowed = ["ping", "service", "version", "syn"]
description = "Type of scan to perform"

[output.schema.properties.hosts]
type = "array"
description = "Discovered hosts with open ports and services"
```

Generates:

```json
{
  "name": "nmap_scan",
  "description": "Network port scanning and service detection",
  "inputSchema": {
    "type": "object",
    "properties": {
      "target": {
        "type": "string",
        "description": "Target CIDR, IP, or hostname"
      },
      "scan_type": {
        "type": "string",
        "enum": ["ping", "service", "version", "syn"],
        "description": "Type of scan to perform"
      }
    },
    "required": ["target", "scan_type"]
  },
  "outputSchema": {
    "type": "object",
    "properties": {
      "status": { "type": "string" },
      "scan_id": { "type": "string" },
      "results": {
        "type": "object",
        "properties": {
          "hosts": {
            "type": "array",
            "description": "Discovered hosts with open ports and services"
          }
        }
      }
    }
  }
}
```

The LLM sees both schemas in the Reason phase: `inputSchema` to know what parameters to provide, `outputSchema` to know what data it will receive back.

## Cedar Policy Auto-Generation

The runtime can generate baseline Cedar policies from manifest metadata:

- `risk_tier = "low"` generates a permissive policy (allow for any agent)
- `risk_tier = "medium"` generates a policy requiring phase context
- `risk_tier = "high"` generates a policy requiring human approval

```cedar
# Auto-generated from nmap_scan.clad.toml (risk_tier = "low")
permit (
    principal,
    action == PenTest::Action::"execute_tool",
    resource
)
when {
    resource.tool_name == "nmap_scan"
};
```

Teams refine the generated policies with phase restrictions, environment constraints, and custom approval gates.

## ORGA Loop Integration

The ToolClad executor plugs into the existing ORGA action execution pipeline:

```
Observe: Agent receives input/observations
    |
Reason:  LLM proposes tool calls using MCP schemas (generated from manifests)
    |
Gate:    Cedar evaluates policy using manifest-declared resource/action
    |     + ToolClad validates all arguments against manifest type system
    |
Act:     ToolClad executor constructs command from template, executes,
         parses output, wraps in evidence envelope
    |
Observe: Agent receives structured JSON results
```

The Gate phase has two validation layers:

1. **Cedar policy evaluation**: Is this agent, in this phase, allowed to invoke this tool on this target? (Authorization)
2. **ToolClad argument validation**: Do all parameters satisfy their declared types, ranges, patterns, and scope constraints? (Input correctness)

Both execute outside LLM influence. Both must pass for execution to proceed.

### ActionExecutor Pipeline

```
ProposedAction
  -> ToolInvocationEnforcer (SchemaPin verification check)
  -> Cedar policy evaluation
  -> ToolClad argument validation (if manifest exists)
  -> ToolClad command construction + execution (if manifest exists)
     OR Rust tool function (if legacy registration)
     OR MCP server forwarding (if external MCP tool)
  -> Evidence envelope wrapping
  -> Observation returned to loop
```

## Scope Enforcement

Any parameter with type `scope_target`, `url` (with `scope_check = true`), `cidr`, or `ip_address` is automatically validated against the project's scope definition (`scope/scope.toml`). This replaces manual scope-checking in every wrapper script.

The scope check runs in the executor, after Cedar authorization but before command execution. Even if a Cedar policy bug allows an out-of-scope target, the ToolClad type system catches it.

For browser mode, URL scope enforcement extends to navigation, redirects, and link clicks via `[browser.scope]`.

## Hot-Reload in Dev Mode

- **Development mode** (`symbiont.toml: mode = "development"`): The runtime watches `tools/` for changes and reloads manifests automatically. Useful for iterating on tool definitions.
- **Production mode**: Manifests are loaded at startup and frozen. Changes require a restart. This matches the behavior of Cedar policies, which are also frozen at startup in production.

## `symbi tools` CLI

The Symbiont CLI provides subcommands for working with ToolClad manifests:

### `symbi tools list`

Lists all discovered tools with their source:

```
TOOL                SOURCE              RISK     CEDAR RESOURCE
nmap_scan           tools/nmap_scan     low      PenTest::ScanTarget
hydra_bruteforce    tools/hydra         high     PenTest::ScanTarget
custom_scanner      src/custom.rs       -        Custom::Scanner
mcp_tool            mcp://server/tool   -        (external)
```

### `symbi tools validate`

Validates all `.clad.toml` files in `tools/`:

```
tools/nmap_scan.clad.toml         OK
tools/hydra_bruteforce.clad.toml  OK
tools/broken_tool.clad.toml       ERROR: unknown type "target_ip" (did you mean "ip_address"?)
```

### `symbi tools test <name>`

Dry-run a tool invocation: validates arguments and shows the constructed command without executing:

```
$ symbi tools test nmap_scan --arg target=10.0.1.0/24 --arg scan_type=service

  Manifest:  tools/nmap_scan.clad.toml
  Arguments: target=10.0.1.0/24 (scope_target: OK) scan_type=service (enum: OK)
  Command:   nmap -sT -sV --version-intensity 5 --max-rate 1000 -oX /evidence/...-nmap/scan.xml --no-stylesheet -v  10.0.1.0/24
  Cedar:     PenTest::ScanTarget / execute_tool
  Timeout:   600s

  [dry run -- command not executed]
```

### `symbi tools schema <name>`

Outputs the auto-generated MCP JSON Schema for a tool:

```
$ symbi tools schema nmap_scan
{
  "name": "nmap_scan",
  "description": "Network port scanning and service detection",
  "inputSchema": { ... },
  "outputSchema": { ... }
}
```

### `symbi tools init <name>`

Scaffolds a new `.clad.toml` from a template:

```
$ symbi tools init my_scanner
Created tools/my_scanner.clad.toml -- edit to define your tool interface.
```

### `symbi tools sessions`

Lists active session-mode tool sessions:

```
SESSION                              TOOL                  AGENT         STATE           INTERACTIONS  UPTIME
a1b2c3d4-5678-...                    msfconsole_session    exploit       module_loaded   7             4m 23s
e5f6a7b8-9012-...                    psql_session          data_agent    ready           12            1m 05s
```

## Custom Types via `toolclad.toml`

Define reusable types in `toolclad.toml` at the project root:

```toml
# toolclad.toml
[types.service_protocol]
base = "enum"
allowed = ["ssh", "ftp", "http", "https", "smb", "rdp", "mysql", "postgres"]

[types.severity_level]
base = "enum"
allowed = ["info", "low", "medium", "high", "critical"]

[types.nuclei_template_id]
base = "string"
pattern = "^[a-zA-Z0-9_-]+(/[a-zA-Z0-9_-]+)*$"
```

Reference them in any manifest:

```toml
[args.service]
type = "service_protocol"
```

The runtime resolves custom types by loading `toolclad.toml` at startup and making the definitions available to all manifest validators.

## Session and Browser Executors

The Symbiont runtime includes specialized executors for stateful modes:

- **SessionExecutor**: PTY management, prompt detection, state inference, per-interaction Cedar gating, evidence transcript logging, child session registration
- **BrowserExecutor**: CDP-direct WebSocket, persistent daemon per tab, live browser attachment, accessibility tree extraction, page state inference, redirect interception, screenshot evidence

Both executors plug into the same ORGA loop and Cedar policy infrastructure as oneshot tools. The governance model is identical; only the transport differs.
