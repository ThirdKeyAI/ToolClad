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

### `toolclad validate <manifest>`

Parse and validate a `.clad.toml` manifest. Checks required fields, type definitions, template variable references, and output schema.

```bash
$ toolclad validate tools/nmap_scan.clad.toml
tools/nmap_scan.clad.toml: OK

$ toolclad validate tools/broken_tool.clad.toml
tools/broken_tool.clad.toml: ERROR: unknown type "target_ip" (did you mean "ip_address"?)
```

**Exit codes:**

| Code | Meaning |
|------|---------|
| `0` | Manifest is valid |
| `1` | Validation error (details printed to stderr) |

### `toolclad run <manifest> --arg key=value`

Execute a tool with the provided arguments. Validates arguments, constructs the command, executes with timeout, parses output, and returns the evidence envelope as JSON.

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

### `toolclad test <manifest> --arg key=value`

Dry run: validates arguments and shows the constructed command without executing it. Useful for verifying that a manifest produces the expected command.

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
| `required argument "target" not provided` | A required parameter is missing. |
| `value "exploit" not in allowed list` | Enum value does not match declared options. Lists allowed values. |
| `shell metacharacter detected in value` | Input contains injection characters. Lists the rejected character. |
| `template variable {_scan_flags} has no mapping` | A `{_variable}` in the template has no corresponding mapping or default. |
| `output schema validation failed` | Parsed output does not match `[output.schema]`. Shows the specific mismatch. |
| `scope check failed for target` | A scope-checked value is not in the project's allowed scope. |
