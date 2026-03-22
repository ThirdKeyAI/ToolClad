---
title: Output & Evidence
description: Output parsers, evidence envelopes, and SHA-256 hashing
---

# Output & Evidence

Every ToolClad execution produces structured, validated, hash-protected output. The output pipeline has three stages: parsing raw tool output into structured data, validating it against a declared schema, and wrapping it in an evidence envelope.

---

## Output Parsers

### Built-in Parsers

ToolClad ships with five built-in parsers that cover common output formats:

| Parser | Produces | Use Case |
|--------|----------|----------|
| `builtin:json` | Passes through as-is | Tools with native JSON output |
| `builtin:xml` | Converts XML to JSON | nmap, Nessus, OWASP ZAP |
| `builtin:csv` | Array of objects (header row as keys) | Spreadsheet exports, log files |
| `builtin:jsonl` | Array of JSON objects (one per line) | Nuclei, streaming tools |
| `builtin:text` | `{ "raw_output": "..." }` | Simple unstructured output (default) |

Declare the parser in the manifest:

```toml
[output]
format = "xml"
parser = "builtin:xml"
envelope = true
```

When no parser is specified, `builtin:text` is the default.

### Custom Parsers

For tools whose output requires domain-specific parsing, declare an external script:

```toml
[output]
format = "xml"
parser = "scripts/parse-outputs/parse-nmap-xml.py"
envelope = true
```

Custom parsers:

- Receive the raw output file path as `argv[1]`
- Must emit valid JSON to stdout
- Run with the same timeout and process group isolation as the tool itself
- Their output is validated against `[output.schema]` before reaching the agent

The parser's output replaces what would otherwise be the built-in parser's result in the `results` field of the evidence envelope.

---

## Output Schema

Every manifest must declare the expected shape of its parsed results in `[output.schema]`. This is mandatory.

### Purpose

1. **MCP `outputSchema` generation.** The LLM sees what data shape it will receive *before* proposing a tool call. This enables more effective reasoning about whether and how to use a tool.
2. **Parser output validation.** The executor validates parsed results against the schema. Malformed parser output is rejected before it reaches the agent, preventing corrupted state in the reasoning loop.

### Declaration

The schema uses JSON Schema-compatible syntax in TOML:

```toml
[output.schema]
type = "object"

[output.schema.properties.hosts]
type = "array"
description = "Discovered hosts with open ports and services"

[output.schema.properties.hosts.items.properties.ip]
type = "string"
description = "Host IP address"

[output.schema.properties.hosts.items.properties.ports]
type = "array"
description = "Open ports with service details"

[output.schema.properties.hosts.items.properties.ports.items.properties.port]
type = "integer"

[output.schema.properties.hosts.items.properties.ports.items.properties.service]
type = "string"
```

For tools with simple or opaque output, a minimal schema is acceptable:

```toml
[output.schema]
type = "object"

[output.schema.properties.raw_output]
type = "string"
description = "Raw command output text"
```

The schema is JSON Schema-compatible so it maps directly to MCP `outputSchema` with no transformation.

---

## Evidence Envelopes

When `envelope = true` (the default), the executor wraps parsed output in a standard envelope.

### Structure

```json
{
  "status": "success",
  "scan_id": "1711929600-12345",
  "tool": "nmap_scan",
  "command": "nmap -sT -sV --max-rate 1000 -oX /evidence/...-nmap/scan.xml 10.0.1.0/24",
  "duration_ms": 4523,
  "timestamp": "2026-03-20T12:00:00Z",
  "exit_code": 0,
  "stderr": "",
  "output_file": "/evidence/1711929600-12345-nmap/scan.xml",
  "output_hash": "sha256:a1b2c3d4e5f6...",
  "results": {
    "hosts": [
      {
        "ip": "10.0.1.1",
        "ports": [
          { "port": 22, "protocol": "tcp", "service": "ssh", "version": "OpenSSH 8.9" },
          { "port": 80, "protocol": "tcp", "service": "http", "version": "nginx 1.24" }
        ]
      }
    ]
  }
}
```

### Envelope Fields

| Field | Type | Description |
|-------|------|-------------|
| `status` | string | `"success"`, `"error"`, `"timeout"`, or `"delegated"` (MCP proxy) |
| `scan_id` | string | Unique invocation identifier (`unix_timestamp-short_uuid`) |
| `tool` | string | Tool name from the manifest (`[tool].name`) |
| `command` | string | The constructed command that was executed |
| `duration_ms` | integer | Wall-clock execution time in milliseconds |
| `timestamp` | string | ISO 8601 execution timestamp (UTC) |
| `exit_code` | integer | Process exit code (`0` = success, `-1` = timeout/error) |
| `stderr` | string | Standard error output from the process |
| `output_file` | string | Path to the raw output file on disk (if evidence capture enabled) |
| `output_hash` | string | SHA-256 hash of raw output for tamper detection |
| `results` | object | Parsed and schema-validated output |

### HTTP Backend Envelopes

HTTP tool envelopes include additional fields:

| Field | Type | Description |
|-------|------|-------------|
| `http_status` | integer | HTTP response status code |
| `http_method` | string | HTTP method used (GET, POST, etc.) |

### MCP Proxy Envelopes

MCP proxy tools produce delegation envelopes:

| Field | Type | Description |
|-------|------|-------------|
| `status` | string | Always `"delegated"` |
| `mcp_server` | string | Upstream MCP server name |
| `mcp_tool` | string | Upstream MCP tool name |
| `mcp_args` | object | Arguments mapped through `field_map` |

---

## SHA-256 Hashing

The `output_hash` field contains a SHA-256 hash of the raw tool output (before parsing). This provides tamper detection for the evidence chain.

Hash computation:

```
sha256:<hex_digest_of_raw_stdout_bytes>
```

Properties:

- Computed over raw bytes, not the parsed JSON
- Independent of the parser implementation
- Different parsers producing different JSON from the same raw output share the same hash
- Anchors the evidence to the exact output the tool produced

Configure evidence hashing in the manifest:

```toml
[tool.evidence]
output_dir = "{evidence_dir}/{scan_id}-nmap"
capture = true
hash = "sha256"
```

---

## Symbiont Audit Trail Integration

Evidence envelopes integrate directly with Symbiont's cryptographic audit trail:

1. **Every tool invocation** produces an evidence envelope with a unique `scan_id` and `timestamp`.
2. **The `output_hash`** anchors the evidence to the exact output bytes, enabling tamper detection across the evidence chain.
3. **The envelope is stored** in Symbiont's audit log alongside Cedar policy decisions, agent state, and ORGA loop context.
4. **Session and browser mode** produce per-interaction envelopes, creating a complete transcript of every command, response, and policy decision.
5. **The evidence chain** links parent and child sessions via `parent_session_id`, providing full traceability across session boundaries.

The audit trail records:

- Which agent proposed the tool call
- What Cedar policy decisions were made
- What arguments were validated
- What command was constructed and executed
- What output was produced (with hash)
- How long execution took

This enables post-hoc review, compliance reporting, and forensic analysis of agent behavior.

---

## Error Envelopes

When a tool fails, the envelope carries structured error information:

```json
{
  "status": "error",
  "scan_id": "1711929600-12346",
  "tool": "nmap_scan",
  "command": "nmap -sT -sV --max-rate 1000 10.0.1.0/24",
  "duration_ms": 1200,
  "timestamp": "2026-03-20T12:05:00Z",
  "exit_code": 1,
  "stderr": "Failed to resolve \"10.0.1.0/24\": Name or service not known",
  "output_hash": "sha256:0000...",
  "results": null
}
```

The agent receives structured error information:

- `exit_code` tells the agent the tool failed (non-zero)
- `stderr` tells the agent *why* it failed, in the tool's own words
- The agent can reason about the error and adjust its next action

Timeout envelopes set `status = "timeout"` and `exit_code = -1`.
