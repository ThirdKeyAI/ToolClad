# ToolClad

Declarative tool interface contracts for agentic runtimes.

ToolClad is a manifest format (`.clad.toml`) that defines the complete behavioral contract for a tool: typed parameters, validation rules, invocation mechanism, output parsing, and policy metadata. Three execution modes share a common governance layer:

- **Oneshot** (default): Single CLI command execution
- **Session**: Interactive CLI tools via PTY (msfconsole, psql, redis-cli) with per-interaction Cedar gating
- **Browser**: Governed headless browser via CDP/Playwright with URL scope enforcement and page state policies

## The Problem

Every team building agentic systems writes custom glue code per tool: argument sanitization, timeout enforcement, output parsing, evidence capture, Cedar mappings, DSL capabilities, and policies. That's 7 steps per tool. It doesn't scale.

## The Solution

```toml
# tools/whois_lookup.clad.toml
[tool]
name = "whois_lookup"
version = "1.0.0"
binary = "whois"
description = "WHOIS domain/IP registration lookup"
timeout_seconds = 30
risk_tier = "low"

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
```

The agent fills typed parameters. The executor validates, constructs the command, executes with timeout, and returns structured JSON. The agent never sees or generates a shell command.

## Security Model

ToolClad inverts the sandbox approach:

- **Sandbox**: LLM generates command -> sandbox intercepts -> allow/deny (deny-list)
- **ToolClad**: LLM fills typed parameters -> policy gate -> executor validates -> constructs command from template (allow-list)

The dangerous action cannot be expressed because the interface doesn't permit it.

### Security Features

- **Shell injection prevention**: All string types reject metacharacters (`;|&$\`(){}[]<>!\n\r`) by default
- **Array-based execution**: Commands dispatched via direct `execve` (no `sh -c` shell interpretation)
- **Process group isolation**: Tools spawned in new PGID; timeout kills entire process group (no zombies)
- **Absolute path blocking**: `path` type rejects `/etc/shadow`, `C:\...` style paths
- **Newline injection blocking**: `\n` and `\r` rejected in all string-based types
- **No eval**: Conditional evaluators use closed-vocabulary parsers, never dynamic code execution

## Packages

Install from your language's package registry:

```bash
cargo install toolclad        # Rust / crates.io
pip install toolclad           # Python / PyPI
npm install toolclad           # JavaScript / npm
```

| Language | Registry | Package |
|----------|----------|---------|
| **Rust** | [crates.io](https://crates.io/crates/toolclad) | `cargo install toolclad` |
| **Python** | [PyPI](https://pypi.org/project/toolclad/) | `pip install toolclad` |
| **JavaScript** | [npm](https://www.npmjs.com/package/toolclad) | `npm install toolclad` |
| **Go** | Source | `go install ./go/cmd/toolclad` |

## Reference Implementations

Each implementation provides:

- **Manifest parsing** -- load and validate `.clad.toml` files (oneshot, session, browser modes)
- **14 type validators** -- 10 core + 4 extended, all with injection sanitization
- **Command construction** -- template interpolation with mappings, conditionals, defaults
- **Execution** -- direct argv dispatch, process group kill on timeout, SHA-256 evidence hashing
- **Output parsers** -- builtin:json, builtin:xml, builtin:csv, builtin:jsonl, builtin:text, custom scripts
- **Output schema validation** -- validates parsed results against `[output.schema]`
- **MCP schema generation** -- auto-generate inputSchema + outputSchema for LLM tool use
- **Evidence envelopes** -- structured JSON with scan_id, timestamps, exit_code, stderr, output_hash
- **CLI** -- `validate`, `run`, `schema`, `test` (dry run) subcommands

## Quick Start

```bash
# Rust
cd rust && cargo run -- test ../examples/whois_lookup.clad.toml --arg target=example.com

# Python
cd python && pip install -e . && toolclad test ../examples/whois_lookup.clad.toml --arg target=example.com

# JavaScript
cd js && npm install && node src/cli.js test ../examples/whois_lookup.clad.toml --arg target=example.com

# Go
cd go && go run ./cmd/toolclad test ../examples/whois_lookup.clad.toml --arg target=example.com
```

## Type System

### Core Types

| Type | Validates | Examples |
|------|-----------|---------|
| `string` | Non-empty, injection-safe, optional regex `pattern` | General text |
| `integer` | Numeric, optional `min`/`max` with `clamp` | Thread counts |
| `port` | 1-65535 | Network ports |
| `boolean` | Exactly `"true"` or `"false"` | Feature flags |
| `enum` | Value in declared `allowed` list | Scan types |
| `scope_target` | Injection-safe, no wildcards, valid IP/CIDR/hostname | Targets |
| `url` | Valid URL, optional `schemes` restriction, `scope_check` | Web targets |
| `path` | No traversal (`../`), no absolute paths | File paths |
| `ip_address` | Valid IPv4 or IPv6 | Addresses |
| `cidr` | Valid CIDR notation (IPv4 + IPv6) | Network ranges |

### Extended Types

| Type | Validates | Use Case |
|------|-----------|----------|
| `msf_options` | Semicolon-delimited `set KEY VALUE` pairs | Metasploit options |
| `credential_file` | Relative path + must exist | Username/password lists |
| `duration` | Integer with suffix (`30`, `5m`, `2h`) | Timeout overrides |
| `regex_match` | Matches declared `pattern` (required) | Module paths |

### Custom Types

Define reusable types in `toolclad.toml` at the project root:

```toml
[types.service_protocol]
base = "enum"
allowed = ["ssh", "ftp", "http", "https", "smb", "rdp"]

[types.severity_level]
base = "enum"
allowed = ["info", "low", "medium", "high", "critical"]
```

Reference in manifests: `type = "service_protocol"`

## Output Handling

### Built-in Parsers

| Parser | Use Case |
|--------|----------|
| `builtin:json` | Tools with native JSON output |
| `builtin:xml` | nmap, Nessus, OWASP ZAP |
| `builtin:csv` | Spreadsheet exports, log files |
| `builtin:jsonl` | Nuclei, streaming tools |
| `builtin:text` | Simple unstructured output (default) |

### Custom Parsers

```toml
[output]
parser = "scripts/parse-outputs/parse-nmap-xml.py"
```

Custom parsers receive the raw output file path as `argv[1]` and emit JSON to stdout.

### Evidence Envelope

Every execution returns a structured envelope:

```json
{
  "status": "success",
  "scan_id": "1711929600-12345",
  "tool": "nmap_scan",
  "command": "nmap -sT -sV --max-rate 1000 10.0.1.0/24",
  "duration_ms": 4523,
  "timestamp": "2026-03-20T12:00:00Z",
  "exit_code": 0,
  "stderr": "",
  "output_hash": "sha256:a1b2c3...",
  "results": { "hosts": [...] }
}
```

On error, `exit_code` and `stderr` are included so LLM agents can self-correct.

## Symbiont Integration

ToolClad is the `tools/` directory convention for [Symbiont](https://symbiont.dev):

- Runtime auto-discovers `.clad.toml` files at startup
- Registers each tool as an MCP tool in the ORGA reasoning loop
- Cedar policy evaluation using manifest-declared `[tool.cedar]` resource/action
- Scope enforcement against `scope/scope.toml`
- Cedar policy auto-generation from manifest `risk_tier`
- Hot-reload in development mode
- `symbi tools list/validate/test/schema/init` CLI

```bash
symbi tools list                    # show discovered tools
symbi tools test nmap_scan --arg target=10.0.1.0/24 --arg scan_type=service
symbi tools schema nmap_scan        # output MCP JSON Schema
symbi tools init my_scanner         # scaffold new manifest
```

## SchemaPin Integration

SchemaPin signs `.clad.toml` files directly as first-class artifacts:

```bash
schemapin-sign tools/nmap_scan.clad.toml
```

The signature covers the entire behavioral contract. If anyone tampers with a command template, validation rule, scope constraint, or output schema, the hash changes and verification fails.

See [TOOLCLAD_DESIGN_SPEC.md](https://github.com/ThirdKeyAI/ToolClad/blob/main/TOOLCLAD_DESIGN_SPEC.md) for the full specification.

## License

- Protocol specification (manifest format, type system, evidence envelope): **MIT**
- Symbiont integration (Cedar gating, ORGA enforcement, scope enforcement): **Apache 2.0**
