---
title: Session Mode
description: Interactive CLI sessions with per-interaction governance
---

# Session Mode

Session mode governs interactive CLI tools -- programs that stay alive across multiple interactions and maintain internal state. Tools like `psql`, `msfconsole`, `redis-cli`, `kubectl exec`, and `gdb` accept commands over time, where each command changes the tool's internal state and carries a different risk level.

## What Session Mode Solves

The oneshot model (validate, construct, execute, parse) does not fit interactive tools because:

1. The tool stays alive across multiple agent interactions
2. Each interaction changes the tool's internal state (loaded module, connected database, current context)
3. The agent needs intermediate output to decide its next command
4. Different commands within the same session carry different risk levels

Sandboxing an interactive tool treats the entire session as a black box. An agent with an open `psql` connection could `DROP TABLE` as easily as `SELECT *` because both are text sent to a PTY. ToolClad session mode declares which commands are allowed, validates each one independently, and gates every interaction through Cedar policy evaluation.

## Session Manifest Example

A psql session manifest with read and write commands at different risk tiers:

```toml
# tools/psql_session.clad.toml
[tool]
name = "psql_session"
binary = "psql"
mode = "session"
description = "Governed PostgreSQL interactive session"
risk_tier = "medium"

[tool.cedar]
resource = "Data::Database"
action = "query"

[tool.evidence]
output_dir = "{evidence_dir}/{session_id}-psql"
capture = true
hash = "sha256"

# --- Session Lifecycle ---

[session]
startup_command = "psql -h localhost -U agent_user -d appdb"
ready_pattern = "^[a-zA-Z_]+=>[\\s]*$"
startup_timeout_seconds = 10
idle_timeout_seconds = 300
session_timeout_seconds = 1800
max_interactions = 200

[session.interaction]
input_sanitize = ["injection"]
output_max_bytes = 1048576
output_wait_ms = 2000

# --- Session Commands ---

[session.commands.select_query]
pattern = "^SELECT .+$"
description = "Run a read-only SELECT query"
risk_tier = "low"

[session.commands.insert]
pattern = "^INSERT INTO [a-zA-Z_]+ .+$"
description = "Insert rows into a table"
risk_tier = "medium"

[session.commands.update]
pattern = "^UPDATE [a-zA-Z_]+ SET .+$"
description = "Update rows in a table"
risk_tier = "medium"
human_approval = true

[session.commands.drop_table]
pattern = "^DROP TABLE .+$"
description = "Drop a table (destructive)"
risk_tier = "high"
human_approval = true

# --- Output Schema ---

[output.schema]
type = "object"

[output.schema.properties.prompt]
type = "string"
description = "Current psql prompt (indicates connection state)"

[output.schema.properties.output]
type = "string"
description = "Query result or command output"

[output.schema.properties.session_state]
type = "string"
enum = ["ready", "transaction", "error"]
description = "Inferred session state from prompt analysis"

[output.schema.properties.interaction_count]
type = "integer"
description = "Number of interactions in this session so far"
```

## Session Configuration

### `[session]` Section

| Field | Type | Description |
|-------|------|-------------|
| `startup_command` | string | Command to launch the interactive tool |
| `ready_pattern` | regex | Pattern that matches the tool's input prompt |
| `startup_timeout_seconds` | integer | Max time to wait for the first prompt after launch |
| `idle_timeout_seconds` | integer | Max time between interactions before session is terminated |
| `session_timeout_seconds` | integer | Max total session lifetime |
| `max_interactions` | integer | Maximum number of command/response rounds |

### `[session.interaction]` Section

| Field | Type | Description |
|-------|------|-------------|
| `input_sanitize` | array | Sanitization rules applied to all command input |
| `output_max_bytes` | integer | Maximum bytes to capture from a single interaction |
| `output_wait_ms` | integer | Time to wait for output after sending a command |

### `[session.commands.*]` Section

Each entry under `[session.commands]` declares a permitted operation:

| Field | Type | Description |
|-------|------|-------------|
| `pattern` | regex | Regex the command text must match |
| `description` | string | Human-readable description (shown in MCP tool listing) |
| `risk_tier` | string | `"low"`, `"medium"`, or `"high"` |
| `human_approval` | boolean | Whether this command requires human approval before execution |
| `extract_target` | boolean | If `true`, extract the target value for scope checking |

A command that does not match any declared pattern is rejected before it reaches the PTY.

## Session Commands as Typed MCP Tools

Each `[session.commands.*]` entry becomes a separate MCP tool visible to the LLM. The naming convention is `{tool_name}.{command_name}`:

| MCP Tool Name | LLM Sees | Agent Provides |
|---|---|---|
| `psql_session.select_query` | "Run a read-only SELECT query" | `{ "command": "SELECT * FROM users LIMIT 10" }` |
| `psql_session.insert` | "Insert rows into a table" | `{ "command": "INSERT INTO logs (msg) VALUES ('test')" }` |
| `psql_session.drop_table` | "Drop a table (destructive)" | `{ "command": "DROP TABLE temp_data" }` |

The LLM never sees a free-text input field. It picks from typed operations. The command text is validated against the `pattern` regex, scope-checked if `extract_target = true`, and policy-gated at the command's declared `risk_tier`.

## Per-Interaction ORGA Gating

Session mode turns each round of interaction into its own ORGA cycle:

```
Iteration 1:
  Observe:  "psql is ready, showing dbname=> prompt"
  Reason:   LLM proposes "SELECT * FROM users LIMIT 10"
  Gate:     Cedar checks: is SELECT allowed? Is this agent read-only?
            ToolClad validates: command matches select_query pattern
  Act:      SessionExecutor sends command to PTY, waits for next prompt

Iteration 2:
  Observe:  "Query returned 10 rows, showing dbname=> prompt"
  Reason:   LLM proposes "DROP TABLE users"
  Gate:     Cedar checks: is DROP allowed? -> DENY (or PENDING human approval)
  Act:      (blocked, denial fed back to agent)
```

Every command passes through Cedar policy evaluation and ToolClad pattern validation. The LLM cannot free-type into a terminal.

## Prompt-Based State Inference

The `ready_pattern` regex tells the SessionExecutor when the tool is waiting for input. Different prompts reveal different internal states:

| Prompt | Inferred State |
|---|---|
| `msf6 >` | `ready` (no module loaded) |
| `msf6 exploit(ms17_010) >` | `module_loaded` |
| `dbname=>` | `ready` (psql, standard user) |
| `dbname=#` | `ready` (psql, superuser -- higher risk tier) |

The executor parses prompt changes and reports `session_state` in the output schema. Cedar policies can reference session state for authorization decisions.

## Session Lifecycle

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

Sessions are scoped to a single agent ORGA loop. When the loop completes (task done, timeout, or error), the SessionExecutor terminates the process and finalizes the evidence transcript. Sessions do not persist across agent restarts -- a session is an ephemeral execution context, not durable state.

### SessionExecutor Flow

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

- **PTY allocation**: Spawns the tool in a pseudo-terminal, manages process lifecycle
- **Prompt detection**: Watches stdout for `ready_pattern` matches to know when the tool is waiting for input
- **Output framing**: Extracts meaningful output between the sent command and the next prompt, stripping echoed input and ANSI escape codes
- **State inference**: Parses prompt changes to update `session_state`
- **Timeout enforcement**: Kills the session if `idle_timeout`, `session_timeout`, or `max_interactions` are exceeded
- **Evidence capture**: Logs the full session transcript with timestamps, command/response pairs, and policy decisions

## Evidence Transcript Logging

The SessionExecutor captures a timestamped transcript of every interaction:

```
[00:00.0] STARTUP  psql -h localhost -U agent_user -d appdb
[00:01.2] READY    prompt="appdb=>" state=ready
[00:01.5] INPUT    "SELECT * FROM users LIMIT 10"  cedar=ALLOW  pattern=select_query
[00:02.1] OUTPUT   10 rows returned  prompt="appdb=>" state=ready
[00:02.3] INPUT    "DROP TABLE users"  cedar=DENY  pattern=drop_table
```

This transcript is part of the evidence envelope and provides a complete audit trail of every command the agent sent, whether it was allowed, and what the tool returned.

## Cedar Policy Examples

### Read-only agent

```cedar
// Allow only SELECT queries for read-only agents
permit (
    principal == Data::Agent::"reader",
    action == Data::Action::"query",
    resource
)
when {
    resource.tool_name == "psql_session.select_query"
};
```

### State-aware gating

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

### Interaction count limits

```cedar
// Block all commands after 50 interactions
forbid (
    principal,
    action == Data::Action::"query",
    resource
)
when {
    resource.interaction_count >= 50
};
```

## Session Mode Applications

| Tool | Session Commands | Governance Value |
|---|---|---|
| `psql` / `mysql` | `select_query`, `insert`, `update`, `create_table`, `drop_table` | Read-only agents cannot mutate. DDL requires human approval. |
| `redis-cli` | `get`, `set`, `del`, `keys`, `flushdb` | Agents can read/write keys but `flushdb` requires approval. |
| `kubectl exec` | `get`, `describe`, `logs`, `delete`, `apply` | Agents can inspect but destructive operations are gated. |
| `gdb` / `lldb` | `info`, `backtrace`, `print`, `set`, `continue`, `kill` | Agents can inspect state but `set` and `kill` are gated. |
| `python3` / `node` | REPL commands with import restrictions | Agent can compute but cannot import `os`, `subprocess`, `socket`. |
