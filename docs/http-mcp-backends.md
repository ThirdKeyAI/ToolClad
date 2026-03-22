# HTTP & MCP Backends

ToolClad oneshot mode supports three backends: shell commands (`[command]`), HTTP requests (`[http]`), and MCP proxy calls (`[mcp]`). All three share the same governance layer: argument validation, Cedar policy evaluation, output schema validation, and evidence envelopes. The backend determines how the request is dispatched.

## HTTP Backend

HTTP API tools use an `[http]` section instead of `[command]`. The executor constructs an HTTP request from the manifest, executes it, and wraps the response in a standard evidence envelope.

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

[http]
method = "POST"
url = "https://slack.com/api/chat.postMessage"
headers = { "Authorization" = "Bearer {_secret:slack_token}", "Content-Type" = "application/json" }
body_template = '{"channel": "{channel}", "text": "{message}"}'
success_status = [200]
error_status = [400, 401, 403, 404, 429]

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

### `[http]` Field Reference

| Field | Type | Description |
|-------|------|-------------|
| `method` | string | HTTP method: `GET`, `POST`, `PUT`, `PATCH`, `DELETE` |
| `url` | string | URL template with `{arg}` and `{_secret:name}` placeholders |
| `headers` | table | Header key-value pairs, supports `{_secret:name}` |
| `body_template` | string | Request body template with `{arg}` placeholders |
| `success_status` | array | HTTP status codes that indicate success |
| `error_status` | array | HTTP status codes that indicate known errors |

### HTTP Request Construction

The executor follows this sequence:

1. Interpolate `{arg_name}` placeholders in `url`, `headers`, and `body_template` with validated parameter values
2. Resolve `{_secret:name}` references from secrets management
3. Set method, headers, and body
4. Execute with `timeout_seconds`
5. Check response status against `success_status` / `error_status`
6. Parse response body with the declared parser
7. Validate against `[output.schema]`
8. Wrap in evidence envelope

### Secrets Injection

The `{_secret:name}` syntax references secrets that are resolved at invocation time. Secrets never appear in the manifest, MCP schema, or LLM context.

```toml
[http]
url = "https://api.example.com/v1/{endpoint}?key={_secret:api_key}"
headers = { "Authorization" = "Bearer {_secret:bearer_token}" }
```

Resolution order:

1. `TOOLCLAD_SECRET_<NAME>` environment variable (standalone use)
2. Vault/OpenBao path (Symbiont integration)

The agent proposes `slack_post_message(channel="C01234", message="hello")`. The executor injects the bearer token from the secret store. The agent never sees the token.

### Status Code Validation

```toml
success_status = [200, 201]
error_status = [400, 401, 403, 404, 429]
```

- Status in `success_status`: parse response, return results.
- Status in `error_status`: return error envelope with status code and response body for agent self-correction.
- Status not in either list: return error envelope with "unexpected status code" message.

### HTTP GET Example

```toml
# tools/ip_lookup.clad.toml
[tool]
name = "ip_lookup"
version = "1.0.0"
description = "Look up geolocation data for an IP address"
timeout_seconds = 10
risk_tier = "low"

[args.ip]
type = "ip_address"
required = true
description = "IP address to look up"

[http]
method = "GET"
url = "https://ipapi.co/{ip}/json/"
success_status = [200]
error_status = [429]

[output]
format = "json"
parser = "builtin:json"
envelope = true

[output.schema]
type = "object"

[output.schema.properties.city]
type = "string"

[output.schema.properties.region]
type = "string"

[output.schema.properties.country_name]
type = "string"

[output.schema.properties.org]
type = "string"
description = "ISP or organization"
```

---

## MCP Proxy Backend

The MCP proxy backend wraps an existing MCP server tool in a ToolClad manifest. The manifest applies stricter validation and Cedar policy gating on top of the upstream tool's permissive schema.

### Why Proxy MCP Tools?

MCP tools from marketplaces and third-party servers have permissive JSON Schemas. A GitHub MCP tool might accept any string for a repository name. A database MCP tool might accept any SQL query.

The ToolClad manifest constrains these inputs with the full type system (regex patterns, enums, scope checks) and subjects every invocation to Cedar policy evaluation. Instead of trusting a marketplace MCP tool's self-declared schema, you wrap it in a `.clad.toml` that defines the contract *you* trust.

```
Without proxy:  Agent -> MCP Server (permissive schema, no Cedar)
With proxy:     Agent -> ToolClad (strict types, Cedar) -> MCP Server
```

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

### `[mcp]` Field Reference

| Field | Type | Description |
|-------|------|-------------|
| `server` | string | Named MCP server connection from `symbiont.toml` |
| `tool` | string | Upstream MCP tool name to invoke |
| `field_map` | table | Optional: map ToolClad arg names to upstream param names |

The `server` field references a named MCP server in the runtime configuration:

```toml
# symbiont.toml
[mcp.servers.github-mcp]
command = "npx"
args = ["-y", "@modelcontextprotocol/server-github"]
env = { GITHUB_TOKEN = "${vault:github/api-token}" }
```

### Field Mapping

When ToolClad argument names differ from the upstream MCP tool's parameter names:

```toml
[mcp]
server = "github-mcp"
tool = "create_issue"

[mcp.field_map]
repo = "repository"       # ToolClad "repo" -> upstream "repository"
labels = "label_names"     # ToolClad "labels" -> upstream "label_names"
```

Unmapped fields pass through with the same name. This decouples the ToolClad contract from the upstream tool's naming conventions. You can rename parameters to be clearer for the agent without changing the upstream tool.

### MCP Proxy Execution Flow

1. ToolClad validates all arguments against the manifest's type system (stricter than upstream)
2. Cedar evaluates policy (e.g., "this agent can only create issues in `ThirdKeyAI/*` repos")
3. Executor maps validated arguments to the upstream tool's expected names via `field_map`
4. Executor forwards the call to the MCP server referenced by `server`
5. Response is parsed and validated against `[output.schema]`
6. Wrapped in evidence envelope with audit trail

### Proxy for Database MCP

```toml
# tools/db_query.clad.toml -- Govern a database MCP tool
[tool]
name = "db_read_query"
version = "1.0.0"
description = "Execute a read-only SQL query"
timeout_seconds = 30
risk_tier = "medium"

[tool.cedar]
resource = "Data::Database"
action = "read_query"

[mcp]
server = "postgres-mcp"
tool = "query"

[args.sql]
type = "string"
required = true
pattern = "^SELECT\\s"
sanitize = ["injection"]
description = "SQL SELECT query (read-only)"

[args.database]
type = "enum"
required = true
allowed = ["analytics", "reporting", "staging"]
description = "Target database"

[mcp.field_map]
sql = "query"
database = "db_name"

[output]
format = "json"
parser = "builtin:json"
envelope = true

[output.schema]
type = "object"

[output.schema.properties.rows]
type = "array"
description = "Query result rows"

[output.schema.properties.row_count]
type = "integer"
```

The upstream `postgres-mcp` tool accepts any query string. The ToolClad manifest constrains it to `SELECT` statements only, limits which databases can be targeted, and gates every invocation through Cedar.

## Shared Guarantees

Both HTTP and MCP proxy backends share all ToolClad guarantees with the shell backend:

| Guarantee | Shell | HTTP | MCP Proxy |
|-----------|-------|------|-----------|
| Argument validation | Yes | Yes | Yes |
| Cedar policy evaluation | Yes | Yes | Yes |
| Output schema validation | Yes | Yes | Yes |
| Evidence envelope | Yes | Yes | Yes |
| Timeout enforcement | Yes | Yes | Yes |
| Audit trail | Yes | Yes | Yes |
| Scope enforcement | Yes | Yes | Yes |

The backend is an implementation detail. The governance layer is the same.
