---
title: CLI Reference
description: ToolClad and Symbiont CLI command reference
---

# CLI Reference

ToolClad provides a standalone CLI for working with manifests outside of Symbiont. The Symbiont runtime extends this with additional subcommands under `symbi tools`.

## ToolClad CLI

Install the standalone CLI from your language's package registry:

```bash
cargo install toolclad        # Rust
pip install toolclad           # Python
npm install -g toolclad        # JavaScript
go install ./go/cmd/toolclad   # Go (from source)
```

### `toolclad validate <manifest> [--allow-unknown-keys]`

Parse and validate a `.clad.toml` manifest. Checks required fields, type definitions, placeholder references, the egress lint (`block_internal` on network-target args of egress tools), the interpreter denylist, `timeout_seconds > 0`, the `parser` name, and the output schema. Every section is checked against the manifest key allowlist; an unrecognized key is an error.

```bash
$ toolclad validate tools/nmap_scan.clad.toml
tools/nmap_scan.clad.toml: OK

$ toolclad validate tools/broken_tool.clad.toml
tools/broken_tool.clad.toml: ERROR: unknown type "target_ip" (did you mean "ip_address"?)

$ toolclad validate tools/typo.clad.toml
tools/typo.clad.toml: ERROR: unknown key 'args.target.block_internall' in manifest

$ toolclad validate tools/typo.clad.toml --allow-unknown-keys
warning: unknown key 'args.target.block_internall' in manifest
tools/typo.clad.toml: OK
```

| Flag | Effect |
|------|--------|
| `--allow-unknown-keys` | Downgrade unknown manifest keys from an error to a printed warning. This is the only escape hatch; library loading is always strict. |

If the manifest uses the deprecated `[command] template`, a warning is printed once: `warning: [command] template is deprecated and will be removed in the next minor release; use exec = [...]`.

All subcommands discover a project `toolclad.toml` by walking up from the manifest's directory and pass its custom types into validation and load-time type checking, so manifests that reference custom types validate from the CLI without extra flags.

**Exit codes:**

| Code | Meaning |
|------|---------|
| `0` | Manifest is valid |
| `1` | Validation error (details printed to stderr) |

### `toolclad run <manifest> --arg key=value [--approve]`

Execute a tool with the provided arguments. Validates arguments, runs the policy gate, constructs the command, executes with timeout, parses output, and returns the evidence envelope as JSON.

| Flag | Effect |
|------|--------|
| `--approve` | Switch the policy gate to allow-all for this invocation. Without it, a manifest with `human_approval = true` or `risk_tier` `high`/`critical` is refused before anything is spawned: `policy gate denied: manifest requires human approval (human_approval = true)` or `policy gate denied: risk_tier 'high' requires explicit approval`. |

```bash
$ toolclad run tools/nikto_scan.clad.toml --arg target=example.com
Error: policy gate denied: manifest requires human approval (human_approval = true)

$ toolclad run tools/nikto_scan.clad.toml --approve --arg target=example.com
{ "status": "success", ... }
```

```bash
$ toolclad run tools/whois_lookup.clad.toml --arg target=example.com
{
  "status": "success",
  "scan_id": "1711929600-12345",
  "tool": "whois_lookup",
  "command": "whois example.com",
  "duration_ms": 1523,
  "timestamp": "2026-03-20T12:00:00Z",
  "exit_code": 0,
  "stderr": "",
  "output_hash": "sha256:a1b2c3...",
  "results": {
    "raw_output": "Domain Name: EXAMPLE.COM..."
  }
}
```

Multiple arguments:

```bash
$ toolclad run tools/nmap_scan.clad.toml \
    --arg target=10.0.1.0/24 \
    --arg scan_type=service
```

**Exit codes:**

| Code | Meaning |
|------|---------|
| `0` | Tool executed successfully |
| `1` | Argument validation failed |
| `2` | Command construction failed |
| `3` | Execution error (timeout, process error) |
| `4` | Output parsing or schema validation failed |

Note that a `timeout` or `schema_error` envelope is still printed in full (with partial or raw output preserved) before the process exits non-zero.

**Environment variables read by `run`:**

| Variable | Purpose |
|----------|---------|
| `TOOLCLAD_SCOPE_FILE` | Path to the scope file for `scope_check = true` arguments. When unset, `scope/scope.toml` is searched upward from the manifest's directory; if neither is found, scope-checked arguments are refused. |
| `TOOLCLAD_CONFIG_FILE` | Path to the project `toolclad.toml` holding custom types. When unset, `toolclad.toml` is searched upward from the manifest's directory; absent means no custom types. An unreadable path is an error. |
| `TOOLCLAD_SECRETS_FILE` | TOML file (`name = "value"`) supplying `{_secret:name}` values. Must not be group- or other-readable. Takes precedence over `TOOLCLAD_SECRET_*`. |
| `TOOLCLAD_SECRET_<NAME>` | Fallback source for `{_secret:name}`. Never passed to child processes. |
| `TOOLCLAD_EVIDENCE_DIR` | Evidence root (default `<tmpdir>/toolclad-evidence`), created mode 0700. |
| `TOOLCLAD_KILL_GRACE_MS` | Grace period between `SIGTERM` and `SIGKILL` on timeout. Default `2000`. |

The child process does **not** inherit the CLI's environment. It receives a fixed `PATH`, `HOME`, `LANG`, `LC_ALL`, `TZ`, and `TERM` only (plus `TOOLCLAD_ARG_*`, `TOOLCLAD_SCAN_ID`, `TOOLCLAD_TOOL_NAME`, `TOOLCLAD_EVIDENCE_DIR`, and `TOOLCLAD_OUTPUT_DIR` for `executor` scripts).

### `toolclad test <manifest> --arg key=value`

Dry run: validates arguments and shows the constructed command without executing it. Useful for verifying that a manifest produces the expected command. Scope checks, the host/IP policy (including DNS resolution under `block_internal`), and custom types from `toolclad.toml` all apply during the dry run exactly as they do for `run`; the policy gate is not consulted because nothing executes.

```bash
$ toolclad test tools/nmap_scan.clad.toml \
    --arg target=10.0.1.0/24 \
    --arg scan_type=service

  Manifest:  tools/nmap_scan.clad.toml
  Tool:      nmap_scan (v1.0.0)
  Binary:    nmap

  Arguments:
    target     = 10.0.1.0/24    (scope_target: OK)
    scan_type  = service         (enum: OK)

  Command:   nmap -sT -sV --version-intensity 5 --max-rate 1000 -oX /tmp/toolclad-nmap/scan.xml --no-stylesheet -v  10.0.1.0/24
  Timeout:   600s
  Risk:      low

  [dry run -- command not executed]
```

**Exit codes:**

| Code | Meaning |
|------|---------|
| `0` | Dry run succeeded (arguments valid, command constructed) |
| `1` | Argument validation failed |
| `2` | Command construction failed |

### `toolclad schema <manifest>`

Output the auto-generated MCP JSON Schema for a manifest. Includes both `inputSchema` (from `[args]`) and `outputSchema` (from `[output.schema]`).

```bash
$ toolclad schema tools/nmap_scan.clad.toml
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
      "hosts": {
        "type": "array",
        "description": "Discovered hosts with open ports and services"
      }
    }
  }
}
```

**Exit codes:**

| Code | Meaning |
|------|---------|
| `0` | Schema generated successfully |
| `1` | Manifest validation failed |

## Symbiont CLI

When running inside a Symbiont project, the `symbi tools` subcommands provide project-aware tool management.

### `symbi tools list`

Lists all discovered tools across all sources:

```bash
$ symbi tools list
TOOL                SOURCE              RISK     CEDAR RESOURCE
nmap_scan           tools/nmap_scan     low      PenTest::ScanTarget
hydra_bruteforce    tools/hydra         high     PenTest::ScanTarget
browser_session     tools/browser       medium   Web::BrowserSession
custom_scanner      src/custom.rs       -        Custom::Scanner
mcp_tool            mcp://server/tool   -        (external)
```

### `symbi tools validate`

Validates all `.clad.toml` files in the project's `tools/` directory:

```bash
$ symbi tools validate
tools/nmap_scan.clad.toml         OK
tools/whois_lookup.clad.toml      OK
tools/hydra_bruteforce.clad.toml  OK
tools/broken_tool.clad.toml       ERROR: unknown type "target_ip" (did you mean "ip_address"?)

3 passed, 1 failed
```

### `symbi tools test <name> --arg key=value`

Dry-run a tool by name (not file path). Uses the project's scope and Cedar configuration:

```bash
$ symbi tools test nmap_scan --arg target=10.0.1.0/24 --arg scan_type=service

  Manifest:  tools/nmap_scan.clad.toml
  Arguments: target=10.0.1.0/24 (scope_target: OK) scan_type=service (enum: OK)
  Command:   nmap -sT -sV --version-intensity 5 --max-rate 1000 -oX /evidence/...-nmap/scan.xml --no-stylesheet -v  10.0.1.0/24
  Cedar:     PenTest::ScanTarget / execute_tool
  Timeout:   600s

  [dry run -- command not executed]
```

### `symbi tools schema <name>`

Outputs the MCP JSON Schema for a tool by name:

```bash
$ symbi tools schema nmap_scan
{
  "name": "nmap_scan",
  "description": "Network port scanning and service detection",
  "inputSchema": { ... },
  "outputSchema": { ... }
}
```

### `symbi tools init <name>`

Scaffolds a new `.clad.toml` manifest from a template:

```bash
$ symbi tools init my_scanner
Created tools/my_scanner.clad.toml -- edit to define your tool interface.
```

The generated manifest includes placeholder sections for `[tool]`, `[args]`, `[command]`, and `[output]` with comments explaining each field.

### `symbi tools sessions`

Lists active session-mode and browser-mode sessions:

```bash
$ symbi tools sessions
SESSION                              TOOL                  AGENT         STATE           INTERACTIONS  UPTIME
a1b2c3d4-5678-...                    msfconsole_session    exploit       module_loaded   7             4m 23s
e5f6a7b8-9012-...                    psql_session          data_agent    ready           12            1m 05s
```

### `symbi tools session <id> transcript`

Dumps the full session transcript with timestamps and policy decisions:

```bash
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

## Error Messages

ToolClad provides actionable error messages that include suggestions when possible:

| Error | Meaning |
|-------|---------|
| `unknown type "target_ip"` | Type not recognized. Suggests similar types if available. |
| `unknown key 'tool.foo' in manifest` | A key outside the manifest allowlist. `validate --allow-unknown-keys` downgrades it to a warning. |
| `required argument "target" not provided` | A required parameter is missing. |
| `value "exploit" not in allowed list` | Enum value does not match declared options. Lists allowed values. |
| `shell metacharacter detected in value` | Input contains injection characters. Lists the rejected character. |
| `must not contain whitespace` / `must not contain quote or backslash characters` / `must not contain control characters` / `must not contain NUL bytes` | Value hygiene rejection on a string-derived type. |
| `must not start with '-' or '+' (set allow_leading_dash = true to permit)` | The value would be parsed as an option by the tool. |
| `unresolved placeholder '{name}' in command` | A placeholder in `exec`/`template` has no arg, default, mapping, conditional, or executor variable behind it. |
| `command template places a placeholder inside quotes at offset N; ...` | A deprecated `template` quotes a placeholder; use `exec = [...]`. |
| `timeout_seconds must be greater than zero` | `timeout_seconds = 0` is refused at load. |
| `custom output parsers are not supported by the reference runtimes` | `[output] parser` names a script instead of a `builtin:*` parser. |
| `policy gate denied: ...` | `human_approval = true` or `risk_tier` high/critical without `--approve`. |
| `resolves to an internal name — always blocked` | The host is `localhost`, `*.local`, `*.internal`, `metadata.google.internal`, etc. |
| `could not resolve host '<h>' to verify it is public (block_internal)` | DNS lookup failed under `block_internal`; fail-closed. |
| `target '<v>' is not in scope` | A scope-checked value matched no allowed rule (or matched a blocked one). |
| `scope_check is enabled but no scope/scope.toml was found (set TOOLCLAD_SCOPE_FILE)` | No scope file reachable; the check fails closed. |
| `output schema validation failed` | Parsed output does not match `[output.schema]`. The envelope status is `schema_error` and the raw output is preserved. |
