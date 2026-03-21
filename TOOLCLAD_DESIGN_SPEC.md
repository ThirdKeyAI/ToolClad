# ToolClad: Declarative Tool Interface Contracts for Agentic Runtimes

**Version**: 0.4.0
**Status**: Draft Design Document
**Author**: Jascha Wanger / ThirdKey AI
**Date**: 2026-03-20
**License**: MIT (protocol specification), Apache 2.0 (Symbiont integration)  

---

## Problem Statement

Every team building agentic systems hits the same wall: "How do I safely let an agent use my CLI tool?" The current answer is "write custom glue code." For each tool, you write a wrapper script (argument sanitization, timeout enforcement, output parsing, evidence capture), define Rust structs for MCP tool registration, implement the tool function, register it with Cedar resource/action mappings, add it to the agent DSL capabilities, write Cedar policies, and optionally write an output parser. That is a 7-step process per tool. It does not scale.

In Symbiont specifically, DSL agents reference tool names (`tool.nmap_scan`, `capabilities = ["tool.nmap_scan"]`) but there is no standard mechanism for the runtime to dispatch those references to actual executables. Users must wire tool dispatch in Rust code. This is the single largest barrier to adoption for non-Rust users who want to wrap existing CLI tools (security tools, data pipelines, devops automation, compliance checkers).

The broader ecosystem has no answer either. OpenShell/NemoClaw sandboxes agent execution and intercepts dangerous syscalls, but that is a deny-list firewall operating after the agent has already formulated an arbitrary shell command. There is no protocol for declaring what a tool accepts, how to invoke it safely, and what it produces.

---

## What ToolClad Is

ToolClad is a declarative manifest format (`.clad.toml`) that defines the complete behavioral contract for a CLI tool: its typed parameters, validation rules, command construction template, output parsing, and metadata for policy integration. A single manifest file replaces wrapper scripts, MCP tool schemas, and execution wiring.

A ToolClad manifest answers three questions:

1. **What can this tool accept?** Typed parameters with validation constraints (enums, ranges, regex, scope checks, injection sanitization).
2. **How do you invoke it?** A command template that interpolates validated parameters. The LLM never generates a command string.
3. **What does it produce?** Output format declaration and parsing rules that normalize raw tool output into structured JSON.

A universal executor reads the manifest, validates arguments against declared types, constructs the command from the template, executes with timeout and resource controls, parses output, and wraps everything in a standard evidence envelope.

---

## The Security Model

ToolClad inverts the security model of sandbox-based approaches.

**Sandbox approach (OpenShell/NemoClaw):**

```
LLM generates shell command -> sandbox intercepts -> allow/deny
```

The agent formulates an arbitrary command string. The sandbox pattern-matches against known-dangerous operations. This is a deny-list. Deny-lists have gaps by definition.

**ToolClad approach:**

```
LLM fills typed parameters -> Cedar Gate evaluates policy ->
  executor validates args against manifest -> constructs command
  from template -> executes in sandbox -> parses output ->
  structured JSON back to agent
```

The agent never sees or generates a command string. It fills in typed fields. The manifest constrains the parameter space to only valid values. This is an allow-list. The dangerous action cannot be expressed because the interface does not permit it.

The manifest enables three properties that unstructured shell execution cannot:

- **Static analysis**: You can determine what any tool can possibly do before it ever runs, by inspecting the manifest. Cedar policies can reference manifest-declared properties.
- **Formal verification**: The parameter space is finite and enumerable for enum types, bounded for numeric types, and regex-constrained for string types. You can prove properties about valid invocations.
- **Automatic policy generation**: A tool with a `target` parameter of type `scope_target` inherently requires scope authorization. Cedar policies can be derived from manifests.

---

## Manifest Format

### Minimal Example

```toml
# tools/whois_lookup.clad.toml
[tool]
name = "whois_lookup"
version = "1.0.0"
binary = "whois"
description = "WHOIS domain/IP registration lookup"
timeout_seconds = 30
risk_tier = "low"

[tool.cedar]
resource = "PenTest::ScanTarget"
action = "execute_tool"

[args.target]
position = 1
required = true
type = "scope_target"
description = "Domain name or IP address to query"

[command]
template = "whois {target}"

[output]
format = "text"
envelope = true

[output.schema]
type = "object"

[output.schema.properties.raw_output]
type = "string"
description = "Raw WHOIS registration data"
```

### Full Example

```toml
# tools/nmap_scan.clad.toml
[tool]
name = "nmap_scan"
version = "1.0.0"
binary = "nmap"
description = "Network port scanning and service detection"
timeout_seconds = 600
risk_tier = "low"

[tool.cedar]
resource = "PenTest::ScanTarget"
action = "execute_tool"

[tool.evidence]
output_dir = "{evidence_dir}/{scan_id}-nmap"
capture = true
hash = "sha256"

# --- Parameters ---

[args.target]
position = 1
required = true
type = "scope_target"
description = "Target CIDR, IP, or hostname"

[args.scan_type]
position = 2
required = true
type = "enum"
allowed = ["ping", "service", "version", "syn", "os_detect", "aggressive", "vuln_script"]
description = "Type of scan to perform"

[args.extra_flags]
position = 3
required = false
type = "string"
sanitize = ["injection"]
default = ""
description = "Additional nmap flags (must pass Gate approval)"

# --- Command Construction ---

[command]
template = "nmap {_scan_flags} --max-rate {max_rate} -oX {_output_file} --no-stylesheet -v {extra_flags} {target}"

[command.defaults]
max_rate = 1000

[command.mappings.scan_type]
ping = "-sn -PE"
service = "-sT -sV --version-intensity 5"
version = "-sV --version-all --top-ports 1000"
syn = "-sS --top-ports 1000"
os_detect = "-sS -O --osscan-guess"
aggressive = "-A -T4 --top-ports 10000"
vuln_script = "-sV --script=vuln --script-timeout 60s"

# --- Output ---

[output]
format = "xml"
parser = "builtin:xml"
# OR: parser = "scripts/parse-outputs/parse-nmap-xml.py"
envelope = true

[output.schema]
type = "object"

[output.schema.properties.hosts]
type = "array"
description = "Discovered hosts with open ports and services"

[output.schema.properties.hosts.items.properties.ip]
type = "string"

[output.schema.properties.hosts.items.properties.ports]
type = "array"

[output.schema.properties.hosts.items.properties.ports.items.properties.port]
type = "integer"

[output.schema.properties.hosts.items.properties.ports.items.properties.protocol]
type = "string"

[output.schema.properties.hosts.items.properties.ports.items.properties.service]
type = "string"

[output.schema.properties.hosts.items.properties.ports.items.properties.version]
type = "string"
```

### Complex Example with Escape Hatch

```toml
# tools/metasploit_run.clad.toml
[tool]
name = "metasploit_run"
version = "1.0.0"
binary = "msfconsole"
description = "Metasploit Framework module execution"
timeout_seconds = 900
risk_tier = "high"
human_approval = true

[tool.cedar]
resource = "PenTest::ScanTarget"
action = "execute_tool"

[tool.evidence]
output_dir = "{evidence_dir}/{scan_id}-msf"
capture = true
hash = "sha256"

[args.module]
position = 1
required = true
type = "string"
pattern = "^(exploit|auxiliary|post)/[a-zA-Z0-9_/]+$"
description = "Metasploit module path"

[args.target]
position = 2
required = true
type = "scope_target"
description = "Target IP or hostname (RHOSTS)"

[args.port]
position = 3
required = false
type = "port"
default = 0
description = "Target port (RPORT)"

[args.payload]
position = 4
required = true
type = "string"
pattern = "^(cmd|generic|java|linux|osx|php|python|ruby|windows)/[a-zA-Z0-9_/]+$"
description = "Payload module path"

[args.lhost]
position = 5
required = true
type = "ip_address"
description = "Listener IP (LHOST)"

[args.lport]
position = 6
required = false
type = "port"
default = 4444
description = "Listener port (LPORT)"

[args.options]
position = 7
required = false
type = "msf_options"
description = "Additional set KEY VALUE options, semicolon-delimited"

# Escape hatch: this tool has session detection and module validation
# logic that exceeds what the template engine can express.
[command]
executor = "scripts/tool-wrappers/msf-wrapper.sh"

[output]
format = "text"
parser = "scripts/parse-outputs/parse-msf.py"
envelope = true

[output.schema]
type = "object"

[output.schema.properties.sessions]
type = "array"
description = "Established Metasploit sessions"

[output.schema.properties.sessions.items.properties.session_id]
type = "integer"

[output.schema.properties.sessions.items.properties.type]
type = "string"
description = "Session type (meterpreter, shell, etc.)"

[output.schema.properties.sessions.items.properties.target]
type = "string"

[output.schema.properties.module_output]
type = "string"
description = "Raw module execution output"
```

---

## Type System

Built-in validation types cover the patterns repeated across all existing wrapper scripts. Every type includes injection sanitization (shell metacharacter rejection) by default. Types are designed so that "valid according to the type" means "safe to interpolate into a shell command."

### Core Types

| Type | Validates | Examples |
|------|-----------|---------|
| `string` | Non-empty, injection-safe | General text arguments |
| `integer` | Numeric, optional `min`/`max` with clamping | Thread counts, retry limits |
| `port` | Numeric, 1-65535 | Network ports |
| `boolean` | Exactly `"true"` or `"false"` | Feature flags |
| `enum` | Value in declared `allowed` list | Scan types, protocols, severity levels |
| `scope_target` | Injection-safe + scope validation + block wildcards | IPs, CIDRs, hostnames |
| `url` | Valid URL structure, host extracted for scope validation | Web application targets |
| `path` | No traversal (`../`), optionally must exist | Wordlists, config files, output dirs |
| `ip_address` | Valid IPv4 or IPv6 | Listener addresses, bind addresses |
| `cidr` | Valid CIDR notation | Network ranges |

### Extended Types

| Type | Validates | Use Case |
|------|-----------|----------|
| `msf_options` | Semicolon-delimited `set KEY VALUE` pairs, no shell metacharacters | Metasploit extra options |
| `credential_file` | Path type + must exist + read-only check | Username/password lists |
| `duration` | Integer with suffix (s/m/h) or bare seconds | Timeout overrides |
| `regex_match` | Matches a declared `pattern` (PCRE) | Module paths, format strings |

### Type Composition

Types can be extended with additional constraints:

```toml
[args.threads]
type = "integer"
min = 1
max = 64
clamp = true       # Values outside range are clamped, not rejected
default = 4
description = "Concurrent threads"

[args.service]
type = "enum"
allowed = ["ssh", "ftp", "http-get", "http-post-form", "smb", "rdp", "mysql", "postgres"]
description = "Target service protocol"

[args.target_url]
type = "url"
schemes = ["http", "https"]       # Only these URL schemes
scope_check = true                 # Extract host for scope validation
description = "Target web application URL"

[args.module_path]
type = "string"
pattern = "^(exploit|auxiliary|post)/[a-zA-Z0-9_/]+$"
sanitize = ["injection"]
description = "Metasploit module path"
```

### Custom Types

Projects can define reusable custom types in a `toolclad.toml` at the project root:

```toml
# toolclad.toml -- project-level ToolClad configuration

[types.service_protocol]
base = "enum"
allowed = ["ssh", "ftp", "http", "https", "smb", "rdp", "mysql", "postgres", "mssql", "vnc"]

[types.severity_level]
base = "enum"
allowed = ["info", "low", "medium", "high", "critical"]

[types.nuclei_template_id]
base = "string"
pattern = "^[a-zA-Z0-9_-]+(/[a-zA-Z0-9_-]+)*$"
```

Then reference them in tool manifests:

```toml
[args.service]
type = "service_protocol"
```

---

## Command Construction

The command template is the core mechanism that prevents LLMs from generating arbitrary shell commands. The template is a string with `{placeholder}` references that are interpolated with validated parameter values.

### Template Variables

| Variable | Source |
|----------|--------|
| `{arg_name}` | Validated parameter value |
| `{_scan_flags}` | Resolved from `[command.mappings]` |
| `{_output_file}` | Auto-generated evidence output path |
| `{_scan_id}` | Auto-generated scan/invocation ID |
| `{_evidence_dir}` | Evidence directory from runtime config |

Variables prefixed with `_` are injected by the executor, not provided by the agent.

### Mappings

Mappings translate logical parameter values to actual CLI flags:

```toml
[command.mappings.scan_type]
ping = "-sn -PE"
service = "-sT -sV --version-intensity 5"
syn = "-sS --top-ports 1000"
```

The template references the mapped value as `{_scan_flags}` (derived from `scan_type`). The naming convention: `_{arg_name}_flags` or a custom name declared in the mapping.

### Conditional Sections

For tools where some flags are only present when certain parameters are set:

```toml
[command]
template = "hydra {_service_flags} {_credential_flags} {_thread_flags} {target}"

[command.conditionals]
# Only include -s PORT if port != 0
service_port = { when = "port != 0", template = "-s {port}" }
# Only include -L/-P if files are provided
username_file = { when = "username_file != ''", template = "-L {username_file}" }
password_file = { when = "password_file != ''", template = "-P {password_file}" }
# Only include -l/-p if single credentials are provided
single_user = { when = "username != '' and username_file == ''", template = "-l {username}" }
single_pass = { when = "password != '' and password_file == ''", template = "-p {password}" }
```

### Escape Hatch

When a tool's invocation logic exceeds what the template engine can express, the manifest can delegate to a custom executor:

```toml
[command]
executor = "scripts/tool-wrappers/msf-wrapper.sh"
```

The custom executor receives validated, typed arguments as environment variables (`TOOLCLAD_ARG_MODULE`, `TOOLCLAD_ARG_TARGET`, etc.) and the standard executor variables (`TOOLCLAD_SCAN_ID`, `TOOLCLAD_OUTPUT_DIR`, `TOOLCLAD_EVIDENCE_DIR`). It still benefits from:

- Parameter validation (before the executor is called)
- Scope enforcement (on scope_target args)
- Timeout enforcement (the executor is wrapped in a process timeout)
- Evidence envelope (the executor's stdout is captured and wrapped)
- Cedar policy evaluation (before anything executes)

The escape hatch is for command construction only. All other ToolClad guarantees still apply.

---

## Output Handling

### Built-in Parsers

| Parser | Produces | Use Case |
|--------|----------|----------|
| `builtin:json` | Passes through as-is | Tools with native JSON output |
| `builtin:xml` | Converts to JSON | nmap, Nessus, OWASP ZAP |
| `builtin:csv` | Array of objects | Spreadsheet exports, log files |
| `builtin:text` | `{ "raw_output": "..." }` | Simple tools with unstructured output |
| `builtin:jsonl` | Array of JSON objects | Nuclei, streaming tools |

### Custom Parsers

```toml
[output]
parser = "scripts/parse-outputs/parse-nmap-xml.py"
```

Custom parsers receive the raw output file path as argv[1] and must emit JSON to stdout. The parser's output is validated against the declared `[output.schema]` before it reaches the agent.

### Output Schema (Mandatory)

Every manifest must declare the expected shape of its parsed results in `[output.schema]`. This serves two purposes:

1. **MCP `outputSchema` generation**: The LLM sees what data shape it will receive *before* proposing a tool call. This enables more effective reasoning about whether and how to use a tool.
2. **Parser output validation**: The executor validates parsed results against the schema. Malformed parser output is rejected before it reaches the agent, preventing corrupted state in the ORGA loop.

```toml
[output.schema]
type = "object"

[output.schema.properties.hosts]
type = "array"
description = "Discovered hosts with open ports and services"

[output.schema.properties.hosts.items.properties.ip]
type = "string"
description = "Host IP address"

[output.schema.properties.hosts.items.properties.hostname]
type = "string"
description = "Resolved hostname (if available)"

[output.schema.properties.hosts.items.properties.ports]
type = "array"
description = "Open ports with service details"

[output.schema.properties.hosts.items.properties.ports.items.properties.port]
type = "integer"

[output.schema.properties.hosts.items.properties.ports.items.properties.protocol]
type = "string"

[output.schema.properties.hosts.items.properties.ports.items.properties.service]
type = "string"

[output.schema.properties.hosts.items.properties.ports.items.properties.version]
type = "string"
```

For tools with simple or opaque output, a minimal schema is acceptable:

```toml
# Simple text tool
[output.schema]
type = "object"

[output.schema.properties.raw_output]
type = "string"
description = "Raw command output text"
```

The schema is intentionally JSON Schema-compatible so it maps directly to MCP `outputSchema` with no transformation. The same schema definition feeds both the LLM (via MCP) and the executor (for validation).

### Evidence Envelope

When `envelope = true` (default), the executor wraps parsed output in a standard envelope:

```json
{
  "status": "success",
  "scan_id": "1711929600-12345",
  "tool": "nmap_scan",
  "command": "nmap -sT -sV --max-rate 1000 -oX /evidence/... 10.0.1.0/24",
  "duration_ms": 4523,
  "timestamp": "2026-03-20T12:00:00Z",
  "output_file": "/evidence/1711929600-12345-nmap/scan.xml",
  "output_hash": "sha256:a1b2c3...",
  "results": { ... }
}
```

This is the JSON the agent receives. Every field is deterministic and machine-readable. The `output_hash` provides tamper detection for the evidence chain. The `results` field contains the parsed output, validated against the declared `[output.schema]`.

---

## Symbiont Integration

### Runtime Discovery

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
    hydra_bruteforce.clad.toml
  toolclad.toml             # Optional: project-level config, custom types
  symbiont.toml
```

The runtime:

1. Parses each `.clad.toml` file
2. Validates the manifest (required fields, type definitions, template references, output schema)
3. Registers each tool as an MCP tool with `inputSchema` derived from `[args]` and `outputSchema` derived from `[output.schema]`
4. Wires the tool to the ToolClad executor in the `ActionExecutor` pipeline

### DSL Tool Reference Resolution

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

### MCP Schema Generation

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
      },
      "extra_flags": {
        "type": "string",
        "description": "Additional nmap flags (must pass Gate approval)",
        "default": ""
      }
    },
    "required": ["target", "scan_type"]
  },
  "outputSchema": {
    "type": "object",
    "properties": {
      "status": { "type": "string", "enum": ["success", "error"] },
      "scan_id": { "type": "string" },
      "tool": { "type": "string" },
      "command": { "type": "string" },
      "duration_ms": { "type": "integer" },
      "timestamp": { "type": "string", "format": "date-time" },
      "output_file": { "type": "string" },
      "output_hash": { "type": "string" },
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

The LLM sees both schemas in the Reason phase: `inputSchema` to know what parameters to provide, `outputSchema` to know what data it will receive back. It can reason about whether a tool's output structure is useful for its current goal *before* proposing the call. It never sees or constructs the actual nmap command.

### Cedar Policy Integration

The `[tool.cedar]` section declares the Cedar resource and action for the tool:

```toml
[tool.cedar]
resource = "PenTest::ScanTarget"
action = "execute_tool"
```

The ORGA Gate builds the Cedar authorization request from the manifest metadata plus the agent's runtime context (phase, environment, agent identity). Existing Cedar policies in `policies/tool-authorization.cedar` work unchanged because they already match on `resource.tool_name`.

**Future: automatic policy generation.** Because the manifest declares the tool's risk tier, parameter types, and Cedar resource, the runtime could generate baseline Cedar policies:

```
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

Teams then refine the generated policies (add phase restrictions, environment constraints, human approval gates).

### ORGA Loop Integration

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

The Gate phase now has two validation layers:

1. **Cedar policy evaluation**: Is this agent, in this phase, allowed to invoke this tool on this target? (Authorization)
2. **ToolClad argument validation**: Do all parameters satisfy their declared types, ranges, patterns, and scope constraints? (Input correctness)

Both execute outside LLM influence. Both must pass for execution to proceed.

### ActionExecutor Pipeline

The `EnforcedActionExecutor` gains a ToolClad dispatch path:

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

### Scope Enforcement

Any parameter with type `scope_target`, `url` (with `scope_check = true`), `cidr`, or `ip_address` is automatically validated against the project's scope definition (`scope/scope.toml`). This replaces the `source /app/scripts/scope-check.sh; validate_scope` pattern in every wrapper script.

The scope check runs in the executor, after Cedar authorization but before command execution. This is the defense-in-depth layer: even if a Cedar policy bug allows an out-of-scope target, the ToolClad type system catches it.

---

## Migration Path from symbi-redteam

The existing symbi-redteam architecture maps cleanly to ToolClad:

| Current (7 steps) | ToolClad (2-3 steps) |
|---|---|
| 1. Write `scripts/tool-wrappers/nmap-wrapper.sh` | 1. Write `tools/nmap_scan.clad.toml` |
| 2. Define `NmapScanInput`/`NmapScanOutput` in `src/recon_tools.rs` | (auto-generated from manifest) |
| 3. Implement `nmap_scan()` function | (ToolClad executor handles this) |
| 4. Register in `register_tools()` with Cedar mappings | (auto-registered from `[tool.cedar]`) |
| 5. Add capability to agent DSL | 2. Add capability to agent DSL (unchanged) |
| 6. Add Cedar policies | 3. Add Cedar policies (unchanged, or auto-generate baseline) |
| 7. Write `scripts/parse-outputs/parse-nmap-xml.py` | (optional, use `builtin:xml` or keep custom parser) |

**Backward compatibility**: Existing Rust-registered tools and wrapper scripts continue to work. The `command.executor` escape hatch lets manifests delegate to existing wrappers during migration. Teams can convert one tool at a time.

### symbi-redteam Conversion Coverage

Of the 19 existing wrapper scripts:

- **~14 are pure template tools**: nmap, whois, dns, whatweb, amass, nikto, gobuster, enum4linux, smbclient, snmpwalk, nuclei, searchsploit, chisel, ligolo. These convert to manifests with no custom executor.
- **~3 need conditional logic**: hydra (credential file vs single credential), sqlmap (detect vs exploit mode), pypykatz (different dump types). These use `[command.conditionals]`.
- **~2 need escape hatches**: metasploit (session detection, module validation, msfconsole -x construction), impacket (multiple sub-tools). These use `command.executor` pointing to simplified wrappers that only handle command construction (validation, timeout, evidence are handled by ToolClad).

---

## Open Protocol Scope

### What is the open spec (MIT)

- The `.clad.toml` manifest format
- The type system and validation semantics
- The command template syntax
- The output envelope schema
- The evidence metadata format
- A reference validator (checks manifest correctness)

### What is the Symbiont implementation (Apache 2.0)

- The universal executor (Rust, integrated with tokio async runtime)
- Cedar policy integration and automatic policy generation
- ORGA Gate integration (two-layer validation)
- Scope enforcement against `scope.toml`
- Evidence chain with SHA-256 hashing and cryptographic audit trail
- MCP schema auto-generation from manifests
- DSL tool reference resolution
- Runtime auto-discovery and hot-reload of manifests

### Ecosystem Value

Tool vendors and security teams publish `.clad.toml` manifests alongside their CLI tools. Agent frameworks consume them. Any runtime that supports the ToolClad format can safely invoke the tool. Symbiont's implementation is the most complete, with Cedar gating, ORGA enforcement, and cryptographic audit, but a minimal executor that just does argument validation and template interpolation is useful on its own.

The manifest pairs naturally with SchemaPin. A tool distribution can include:

- The binary or installation instructions
- A `.clad.toml` manifest (behavioral contract)
- A SchemaPin signature over the manifest (cryptographic identity)

Now you have a single, verifiable package that defines both what the tool is and how to invoke it safely.

---

## CLI Support

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
$ symbi tools test nmap_scan --target 10.0.1.0/24 --scan_type service

  Manifest:  tools/nmap_scan.clad.toml
  Arguments: target=10.0.1.0/24 (scope_target: OK) scan_type=service (enum: OK)
  Command:   nmap -sT -sV --version-intensity 5 --max-rate 1000 -oX /evidence/...-nmap/scan.xml --no-stylesheet -v  10.0.1.0/24
  Cedar:     PenTest::ScanTarget / execute_tool
  Timeout:   600s

  [dry run -- command not executed]
```

### `symbi tools init <name>`

Scaffolds a new `.clad.toml` from a template:

```
$ symbi tools init my_scanner
Created tools/my_scanner.clad.toml -- edit to define your tool interface.
```

### `symbi tools schema <name>`

Outputs the auto-generated MCP JSON Schema for a tool:

```
$ symbi tools schema nmap_scan
{
  "name": "nmap_scan",
  "description": "Network port scanning and service detection",
  "inputSchema": { ... }
}
```

---

## SchemaPin Integration

A ToolClad manifest can include a `[tool.schemapin]` section that ties the behavioral contract to cryptographic identity:

```toml
[tool.schemapin]
public_key_url = "https://thirdkey.ai/.well-known/schemapin/keys/nmap_scan.json"
schema_hash_algorithm = "sha256"
```

The runtime can then:

1. Hash the manifest content
2. Verify the hash against a SchemaPin signature
3. Reject manifests that have been tampered with

This creates a chain: SchemaPin verifies the manifest has not been modified. The manifest constrains what the tool can accept. Cedar authorizes whether this invocation is allowed. The executor constructs and runs the command. Each layer trusts the one before it.

---

## Design Decisions (Resolved)

### Output schema declaration is mandatory

If the manifest generates the MCP `inputSchema`, it must also generate the `outputSchema`. The LLM needs to know what shape of data it will get back to reason effectively *before* execution. This is not optional metadata. It is part of the behavioral contract.

The `[output.schema]` section declares the expected structure of parsed results. The executor validates parser output against this schema and rejects malformed results before they reach the agent. See the Output Handling section for the full specification.

### Hot reload is restricted to development environments

In production, tool contracts changing out from under an active agent loop introduces unpredictable state and security risks. An agent mid-ORGA-loop that suddenly gets a different parameter schema or output format has no way to recover gracefully.

- **Development mode** (`symbiont.toml: mode = "development"`): The runtime watches `tools/` for changes and reloads manifests. Useful for iterating on tool definitions.
- **Production mode**: Manifests are loaded at startup and frozen. Changes require a restart. This is the same contract as Cedar policies, which are also frozen at startup in production.

### Remote manifests are local-only in v1

Fetching `.clad.toml` files from URLs introduces a massive supply chain vulnerability. A compromised manifest server could silently alter parameter validation rules, widen scope constraints, or change command templates. SchemaPin signing mitigates this in theory, but the attack surface is too large for v1.

- **v1**: Local files only. Manifests live in `tools/` and are checked into version control.
- **Future (v2+)**: Remote fetching with mandatory SchemaPin signature verification. The runtime rejects any remote manifest that fails signature check. Discovery could use `.well-known/toolclad/` convention, mirroring SchemaPin's `.well-known/schemapin/`.

### Manifest versioning tracks CLI tool version

The `[tool].version` field tracks the underlying CLI tool version, not the manifest format version. When the manifest changes fundamentally (parameter removed, enum value dropped, output schema restructured), in-flight calls against the old schema are rejected to avoid corrupted state. The runtime compares the loaded manifest version against the version at the time the agent's ORGA loop started. If they diverge (possible only in dev mode with hot reload), the call fails with a clear error directing the agent to re-plan.

Non-breaking changes (new optional parameter with a default, new enum value added) do not trigger rejection.

## Design Principle: Keep Conditionals Simple

The `[command.conditionals]` syntax handles the common case of "include this flag when this parameter is set." It is deliberately not Turing-complete. Tools with deeply nested, mutually exclusive flag dependencies (nmap's full flag matrix, impacket's sub-tool dispatch, metasploit's module/payload/option combinations) will outgrow what TOML conditionals can express cleanly.

**The escape hatch is the intended solution for complex tools.** When you find yourself building elaborate conditional chains in TOML, that is the signal to use `command.executor` and write a focused wrapper script. The wrapper only handles command construction; ToolClad still provides parameter validation, scope enforcement, timeout, evidence capture, and the output envelope.

The 80/20 split from symbi-redteam confirms this: ~14 of 19 tools are pure template tools, ~3 use simple conditionals, and ~2 need escape hatches. If a project has more than 20-30% of tools using escape hatches, the tools themselves are probably complex enough to justify custom wrappers, and ToolClad's value shifts from "eliminate wrappers" to "standardize the contract around them."

## Remaining Open Questions

1. **Bidirectional tools**: Some tools (msfconsole, interactive shells) produce output over time and accept further input. ToolClad v1 targets one-shot invocations. Streaming/interactive tools may need a v2 extension.

2. **Non-CLI backends**: The current design targets CLI tools (`binary` + `template`). HTTP API tools (`curl`-style) and MCP server tools could use similar manifests with different execution sections (`[http]` or `[mcp]` instead of `[command]`).
