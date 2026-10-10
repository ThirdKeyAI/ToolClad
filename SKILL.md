---
name: toolclad
title: ToolClad
description: "Declarative tool interface contracts for agentic runtimes — executing shell and HTTP backends, plus session (PTY) and browser (CDP) contracts that are parsed and validated for hosting runtimes; typed parameters, policy gating, evidence envelopes. Signs .clad.toml manifests with SchemaPin (recommended v1.4-alpha options: --expires-in for TTL, --schema-version for semver tagging, --previous-hash for lineage chain)."
version: 0.6.2
---

# ToolClad Development Skills Guide

**Purpose**: This guide helps AI assistants create, validate, and use ToolClad manifests to safely wrap CLI tools for agentic systems.

**Full Specification**: See [TOOLCLAD_DESIGN_SPEC.md](https://github.com/ThirdKeyAI/ToolClad/blob/main/TOOLCLAD_DESIGN_SPEC.md)

## What ToolClad Does

ToolClad is a declarative manifest format (`.clad.toml`) that defines the complete behavioral contract for a tool. The reference runtimes in this repository execute two backends:

- **Oneshot shell** (`[command]`, default): Execute a single CLI command via `execve`, return results. Replaces wrapper scripts.
- **HTTP** (`[http]`): Build and send a single HTTP request from the manifest.

Three further contracts are **parsed and validated but not executable by the reference runtimes**:

- **MCP proxy** (`[mcp]`): arguments are validated and field-mapped; `execute` returns a `delegation_preview` envelope and makes no upstream call.
- **Session** (`[session]`): a running CLI process (PTY) where each interaction is independently validated and policy-gated (msfconsole, psql, redis-cli). `validate`/`schema` work; `execute` is refused with "session mode is parsed but not yet executable in the reference implementation".
- **Browser** (`[browser]`): a governed browser session via CDP where navigation, clicks, form submission, and JS execution are typed, scoped, and policy-gated. Same status as session mode.

Executing session and browser contracts is the job of a hosting runtime such as Symbiont. All manifests share:
- **Typed Parameters**: 15 built-in types (11 core + 4 extended) with injection sanitization, plus custom types via `toolclad.toml`
- **Policy Gate**: `human_approval = true` and `risk_tier` `high`/`critical` are denied by default; `--approve` or an explicit gate is required. Cedar evaluation is external.
- **Evidence Envelopes**: Every execution wrapped in JSON with scan_id, timestamps, SHA-256 hash
- **Scope Enforcement**: `scope_check = true` arguments checked against `scope/scope.toml`, fail-closed when no scope file is reachable
- **MCP Schema Generation**: Auto-generate `inputSchema`/`outputSchema` from manifests for LLM tool use
- **Cedar Integration**: Declare policy resource/action in the manifest for an external policy engine
- **Strict loading**: unknown manifest keys are refused at load

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
timeout_seconds = 30       # Must be > 0 (default 60)
risk_tier = "low"          # low | medium | high | critical (high/critical are gated: run --approve)
# human_approval = true    # Default policy gate refuses unless --approve / an approving gate
# network_egress = true    # Tool reaches the network: every network-target arg must set block_internal = true
# allow_interpreter = true # Permit sh/bash/python3/node/... as argv[0] (refused at load otherwise)
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
block_internal = true       # Refuse loopback/private/metadata targets; required for egress tools
# scope_check = true        # Also allowlist against scope/scope.toml (fail-closed)
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
exec = ["my-binary", "--mode", "{mode}", "{target}"]   # One argv element per entry; never re-split
# end_of_options = "--"    # Optional: insert a literal -- before the first user-argument token
# template = "..."         # Deprecated: tokenized into exec at load with a warning

# OR for complex tools:
# executor = "scripts/wrapper.sh"   # Escape hatch

# --- Output ---
[output]
format = "text"             # text | json | xml | csv | jsonl
parser = "builtin:text"     # builtin:* only; custom parser scripts are refused at load
envelope = true
max_bytes = 8388608         # Cap on stdout/stderr (default 8 MiB); overflow sets output_truncated

[output.schema]
type = "object"

[output.schema.properties.raw_output]
type = "string"
description = "Tool output"
```

## Type System Quick Reference

| Type | Validates | Key Constraints |
|------|-----------|----------------|
| `string` | Injection-safe | anchored `pattern`, `sanitize = ["injection"]`, `allow_whitespace`, `allow_leading_dash` |
| `integer` | `^[+-]?\d+$` | `min`, `max`, `clamp = true` |
| `number` | Float, rejects NaN/inf | `min_float`, `max_float`, `clamp = true` |
| `port` | `^\d+$`, 1-65535 | |
| `boolean` | `true`/`false`, case-insensitive, normalized to lowercase | |
| `enum` | In `allowed` list | Must declare `allowed = [...]` |
| `scope_target` | ASCII-only canonical IP/CIDR/hostname; rejects IDN/punycode and wildcards | `block_internal = true`, `scope_check = true` (explicit; not automatic) |
| `url` | `scheme://host[:port]/...`; `http`/`https` by default; no userinfo; dangerous schemes always refused | `schemes = [...]`, `block_internal = true`, `scope_check = true` |
| `path` | No `..` component, no absolute paths | |
| `ip_address` | Canonical IPv4/IPv6 literal | `block_internal = true`, `scope_check = true` |
| `cidr` | Valid IPv4/IPv6 CIDR | `block_internal = true` (overlap check), `scope_check = true` |
| `msf_options` | Semicolon-delimited `set KEY VALUE` | Metasploit options; whitespace allowed as separator |
| `credential_file` | Relative path + must exist | Username/password lists |
| `duration` | `30`, `5m`, `2h`, `1h30m`, `500ms` | Timeout overrides |
| `regex_match` | Matches declared anchored `pattern` (required) | Module paths |

Custom types can be defined in `toolclad.toml` at the project root with a `base` type and additional constraints. The CLIs find `toolclad.toml` by walking up from the manifest's directory. Custom types cannot carry `block_internal` or `scope_check`, so network targets must use the built-in network types.

All string-derived types reject shell metacharacters (`;|&$\`(){}[]<>!`), NUL, control characters, quotes and backslashes, whitespace (unless `allow_whitespace = true` in `exec` mode) and a leading `-`/`+` (unless `allow_leading_dash = true`). NUL is rejected for every type, including `enum`.

## Command Construction

`exec` arrays interpolate validated parameters. Each element is one argv entry; a placeholder must be a whole, unquoted token and substituted values are never re-split. The agent never generates the command.

```toml
[command]
exec = ["nmap", "{_scan_type_flags}", "--max-rate", "{max_rate}", "{_port_flag}", "{target}"]

[command.defaults]
max_rate = 1000

# Map enum values to CLI flags -> exposed as {_scan_type_flags}
[command.mappings.scan_type]
ping = "-sn -PE"
service = "-sT -sV"
aggressive = "-A -T4"

# Conditional fragments -> exposed as {_port_flag}
[command.conditionals]
port_flag = { when = "port != ''", template = "-p {port}" }
```

- Mapping variables are named `_<arg>_flags` only (`{_scan_type_flags}` for `[command.mappings.scan_type]`); conditionals are `_<cond>` (`{_port_flag}`). These are the only placeholders that expand to more than one argv token, and their text comes from the manifest, never from the agent.
- `_scan_id`, `_output_file` and `_evidence_dir` are injected by the executor as single tokens.
- A token that is exactly one placeholder whose value is empty is dropped, so unset optionals disappear.
- `{{` and `}}` are escapes for literal braces (`"%{{http_code}}"` becomes `%{http_code}`).
- `end_of_options = "--"` inserts a literal `--` before the first user-argument token.
- Every placeholder must resolve to a declared arg, default, mapping, conditional, or executor variable, or the manifest is refused at load.
- `template = "..."` is deprecated: it is tokenized into the same `exec` array at load (placeholders inside quotes are refused) and prints a warning.

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

# Execute a tool the default policy gate would refuse (human_approval = true, risk_tier high/critical)
toolclad run tools/nikto_scan.clad.toml --approve --arg target=example.com

# Validate while tolerating unknown keys (printed as warnings instead of refused)
toolclad validate tools/legacy_tool.clad.toml --allow-unknown-keys

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
`enum` arg for scan type, `[command.mappings]` to translate to flags, XML/JSON output with `builtin:xml`/`builtin:json` (custom parser scripts are refused at load). Set `network_egress = true` and `block_internal = true` on the target.

### Tool requiring approval (metasploit, nikto)
Set `human_approval = true` and/or `risk_tier = "high"`. The default policy gate refuses the tool; run it with `--approve` or supply an approving gate from library code. Cedar policy (external to the reference runtimes) can additionally gate on `context.has_human_approval`.

### Complex tool (escape hatch)
Set `executor = "scripts/wrapper.sh"` instead of `exec`. Validated args are passed as `TOOLCLAD_ARG_*` env vars alongside `TOOLCLAD_SCAN_ID`, `TOOLCLAD_TOOL_NAME`, `TOOLCLAD_EVIDENCE_DIR` and `TOOLCLAD_OUTPUT_DIR`; the rest of the environment is the fixed allowlist (`PATH`, `HOME`, `LANG`, `LC_ALL`, `TZ`, `TERM`) and `TOOLCLAD_SECRET_*` is never passed.
