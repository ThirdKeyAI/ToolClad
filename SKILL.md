---
name: toolclad
title: ToolClad
description: Declarative tool interface contracts for agentic runtimes — oneshot CLI, interactive session (PTY), and browser (CDP/Playwright) modes with typed parameters, per-interaction Cedar gating, evidence envelopes
version: 0.6.0
---

# ToolClad Development Skills Guide

**Purpose**: This guide helps AI assistants create, validate, and use ToolClad manifests to safely wrap CLI tools for agentic systems.

**Full Specification**: See [TOOLCLAD_DESIGN_SPEC.md](https://github.com/ThirdKeyAI/ToolClad/blob/main/TOOLCLAD_DESIGN_SPEC.md)

## What ToolClad Does

ToolClad is a declarative manifest format (`.clad.toml`) that defines the complete behavioral contract for a tool. It supports three execution modes sharing a common governance layer:

- **Oneshot** (default): Execute a single CLI command, return results. Replaces wrapper scripts.
- **Session**: Maintain a running CLI process (PTY) where each interaction is independently validated and policy-gated. For interactive tools like msfconsole, psql, redis-cli.
- **Browser**: Maintain a governed headless browser session where navigation, clicks, form submission, and JS execution are typed, scoped, and policy-gated via CDP/Playwright.

All three modes share:
- **Typed Parameters**: 15 built-in types (11 core + 4 extended) with injection sanitization, plus custom types via `toolclad.toml`
- **Per-Interaction Cedar Gating**: Every command/action evaluated against policies
- **Evidence Envelopes**: Every execution wrapped in JSON with scan_id, timestamps, SHA-256 hash
- **Scope Enforcement**: URL/target scope checking against allow-lists
- **MCP Schema Generation**: Auto-generate `inputSchema`/`outputSchema` from manifests for LLM tool use
- **Cedar Integration**: Declare policy resource/action in the manifest for authorization gating

## When to Create a Manifest

Create a `.clad.toml` when:
- Wrapping an existing CLI tool for agent use (nmap, curl, dig, etc.)
- Need typed argument validation without writing code
- Want MCP tool schemas auto-generated
- Need evidence capture with integrity hashing
- Want Cedar policy metadata for authorization

## Manifest Structure

```toml
# tools/my_tool.clad.toml

[tool]
name = "my_tool"
version = "1.0.0"
binary = "my-binary"
description = "What this tool does"
timeout_seconds = 30
risk_tier = "low"          # low | medium | high | critical
# dispatch = "callback"    # Optional: validator-only embedding (no backend / no [output] required)

[tool.cedar]               # Optional: Cedar policy integration
resource = "Tool::MyTool"
action = "execute_tool"

[tool.evidence]             # Optional: evidence capture
output_dir = "{evidence_dir}/{scan_id}-my-tool"
capture = true
hash = "sha256"

# --- Parameters ---
[args.target]
position = 1
required = true
type = "scope_target"       # Validates IP/CIDR/hostname, blocks injection
description = "Target to scan"

[args.mode]
position = 2
required = false
type = "enum"
allowed = ["fast", "deep", "stealth"]
default = "fast"
description = "Scan mode"

# --- Command ---
[command]
template = "my-binary --mode {mode} {target}"

# OR for complex tools:
# executor = "scripts/wrapper.sh"   # Escape hatch

# --- Output ---
[output]
format = "text"             # text | json | xml | csv | jsonl
parser = "builtin:text"     # Or custom: "scripts/parse.py"
envelope = true

[output.schema]
type = "object"

[output.schema.properties.raw_output]
type = "string"
description = "Tool output"
```

## Type System Quick Reference

| Type | Validates | Key Constraints |
|------|-----------|----------------|
| `string` | Non-empty, injection-safe | `pattern` for regex, `sanitize = ["injection"]` |
| `integer` | Numeric | `min`, `max`, `clamp = true` |
| `number` | Float, rejects NaN/inf | `min_float`, `max_float`, `clamp = true` |
| `port` | 1-65535 | |
| `boolean` | `"true"` or `"false"` only | |
| `enum` | In `allowed` list | Must declare `allowed = [...]` |
| `scope_target` | ASCII-only IP/CIDR/hostname; rejects IDN/punycode and wildcards | Auto scope-checked; gate IDN registration upstream |
| `url` | Valid URL | `schemes = ["http", "https"]`, `scope_check = true` |
| `path` | No traversal (`../`) | |
| `ip_address` | Valid IPv4/IPv6 | |
| `cidr` | Valid CIDR notation | |
| `msf_options` | Semicolon-delimited `set KEY VALUE` | Metasploit options |
| `credential_file` | Relative path + must exist | Username/password lists |
| `duration` | Integer with suffix (`30`, `5m`, `2h`) | Timeout overrides |
| `regex_match` | Matches declared `pattern` (required) | Module paths |

Custom types can be defined in `toolclad.toml` at the project root with a `base` type and additional constraints.

All types reject shell metacharacters (`;|&$\`(){}[]<>!`) by default.

## Command Templates

Templates interpolate validated parameters. The agent never sees the constructed command.

```toml
[command]
template = "nmap {_scan_flags} --max-rate {max_rate} {target}"

[command.defaults]
max_rate = 1000

# Map enum values to CLI flags
[command.mappings.scan_type]
ping = "-sn -PE"
service = "-sT -sV"
aggressive = "-A -T4"

# Conditional fragments
[command.conditionals]
port_flag = { when = "port != 0", template = "-p {port}" }
```

Variables prefixed with `_` are injected by the executor (`_scan_flags`, `_output_file`, `_scan_id`).

## Evidence Envelope Format

```json
{
  "status": "success",
  "scan_id": "1711929600-12345",
  "tool": "nmap_scan",
  "command": "nmap -sT -sV --max-rate 1000 10.0.1.0/24",
  "duration_ms": 4523,
  "timestamp": "2026-03-20T12:00:00Z",
  "output_hash": "sha256:a1b2c3...",
  "results": { "raw_output": "..." }
}
```

## CLI Usage

```bash
# Validate a manifest
toolclad validate tools/nmap_scan.clad.toml

# Dry-run (show constructed command without executing)
toolclad test tools/nmap_scan.clad.toml --arg target=10.0.1.0/24 --arg scan_type=service

# Execute and get evidence envelope
toolclad run tools/nmap_scan.clad.toml --arg target=10.0.1.0/24 --arg scan_type=service

# Output MCP JSON Schema
toolclad schema tools/nmap_scan.clad.toml
```

## Reference Implementations

| Language | Install | Source |
|----------|---------|--------|
| Rust | `cargo install toolclad` | `rust/` |
| Python | `pip install -e python/` | `python/` |
| JavaScript | `cd js && npm install` | `js/` |
| Go | `go install ./go/cmd/toolclad` | `go/` |

## Symbiont Integration

In Symbiont, place `.clad.toml` files in the `tools/` directory. The runtime auto-discovers them at startup:

```
project/
  agents/recon.dsl
  tools/nmap_scan.clad.toml    # Auto-registered as MCP tool
  policies/tool-auth.cedar
  symbiont.toml
```

DSL agents reference tools by name: `capabilities = ["tool.nmap_scan"]`

## Common Patterns

### Simple text tool (whois, dig, ping)
One required `scope_target` arg, text output, `builtin:text` parser.

### Scanner with modes (nmap, nuclei)
`enum` arg for scan type, `[command.mappings]` to translate to flags, XML/JSON output with custom parser.

### Tool requiring approval (metasploit)
Set `human_approval = true` and `risk_tier = "high"`. Cedar policy can gate on `context.has_human_approval`.

### Complex tool (escape hatch)
Set `executor = "scripts/wrapper.sh"` instead of `template`. Validated args passed as `TOOLCLAD_ARG_*` env vars.
