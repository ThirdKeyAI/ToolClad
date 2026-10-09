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

### Custom Parsers (Not Supported)

The reference runtimes accept only the five `builtin:*` names. A `parser` value naming an external script, such as:

```toml
# REFUSED AT LOAD by the reference runtimes
[output]
parser = "scripts/parse-outputs/parse-nmap-xml.py"
```

is rejected when the manifest is loaded with `custom output parsers are not supported by the reference runtimes`. Earlier releases silently ignored such a value and fell back to the built-in parser; that is no longer the case. There is no code path through which an external script runs in the output pipeline. Tools whose output needs domain-specific post-processing should emit JSON, JSONL, CSV, or XML and let the built-in parser normalize it, with `[output.schema]` describing the result.

### Output Size Cap

`[output] max_bytes` (default `8388608`, 8 MiB) caps captured stdout and stderr **separately**. When either stream exceeds the cap, capture stops, the envelope carries `"output_truncated": true`, and the status is unaffected. The hash and evidence file reflect the captured bytes.

```toml
[output]
format = "text"
envelope = true
max_bytes = 8388608
```

### XML Hardening

Before `builtin:xml` parses anything, input containing `<!DOCTYPE` or `<!ENTITY` (case-insensitive) is refused. This closes entity-expansion attacks against the XML parser in every runtime.

---

## Output Schema

Every manifest must declare the expected shape of its parsed results in `[output.schema]`. This is mandatory.

### Purpose

1. **MCP `outputSchema` generation.** The LLM sees what data shape it will receive *before* proposing a tool call. This enables more effective reasoning about whether and how to use a tool.
2. **Parser output validation.** The executor validates parsed results against the schema, fail-closed. Malformed parser output is never handed to the agent as if it were valid.

### Validation Semantics

Each runtime bundles a minimal JSON-Schema subset validator (no external dependency). Supported keywords:

| Keyword | Notes |
|---------|-------|
| `type` | `object`, `array`, `string`, `number`, `integer`, `boolean`, `null` |
| `properties` | nested property schemas |
| `required` | list of required property names |
| `items` | schema applied to every array element |
| `additionalProperties` | boolean only |
| `enum` | allowed values |
| `minimum` / `maximum` | numeric bounds |
| `minLength` / `maxLength` | string length bounds |
| `pattern` | regex on strings |

Unknown keywords (including `description`) are ignored by the validator and passed through to the MCP `outputSchema`.

Validation is **fail-closed**. When the parsed output violates the schema:

- the envelope `status` becomes `"schema_error"`,
- `results` is replaced with `{"schema_error": "<path>: <message>"}`, and
- the raw output is preserved under `results.raw_output` so nothing is lost for forensics.

```json
{
  "status": "schema_error",
  "scan_id": "1711929600-12347",
  "tool": "nmap_scan",
  "exit_code": 0,
  "results": {
    "schema_error": "hosts[0].ports[1].port: expected integer, got string",
    "raw_output": "<?xml version=\"1.0\"?><nmaprun>...</nmaprun>"
  }
}
```

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
| `status` | string | `"success"`, `"error"`, `"timeout"`, `"schema_error"`, `"client_error"` / `"server_error"` / `"redirect_blocked"` (HTTP), or `"delegation_preview"` (MCP proxy) |
| `scan_id` | string | Unique invocation identifier with 128 bits of entropy |
| `tool` | string | Tool name from the manifest (`[tool].name`) |
| `command` | string | The argv that was executed, joined for display. For HTTP tools this is the **unexpanded** `"<METHOD> <url as written in the manifest>"`, so secrets never appear |
| `output_truncated` | boolean | `true` when stdout or stderr hit `[output] max_bytes` and capture stopped |
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

The reference runtimes do not contact an MCP server. An `[mcp]` manifest produces a preview envelope with `status: "delegation_preview"` that carries the upstream server name, the upstream tool name, and the arguments after `field_map` translation; `duration_ms` is `0` and there is no output hash. A hosting runtime that performs the upstream call replaces this with a real envelope.

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

Timeout envelopes set `status = "timeout"` and `exit_code = -1`; any stdout and stderr captured before the `SIGTERM`/`SIGKILL` sequence are preserved, with `output_truncated` set if the `max_bytes` cap was reached first. Schema violations produce `status = "schema_error"` with the raw output preserved (see [Validation Semantics](#validation-semantics)). A policy-gate denial does not produce an envelope at all: `execute` fails with an error starting `policy gate denied: ` before anything is spawned.
