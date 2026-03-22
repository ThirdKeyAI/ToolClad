# Command Construction

ToolClad command templates are the core mechanism that prevents LLMs from generating arbitrary shell commands. The template is a string with `{placeholder}` references that are interpolated with validated parameter values. Commands are dispatched via direct `execve` (no `sh -c`), so shell interpretation never occurs.

## Template Variables

```toml
[command]
template = "nmap {_scan_flags} --max-rate {max_rate} -oX {_output_file} -v {extra_flags} {target}"
```

| Variable Pattern | Source | Example |
|-----------------|--------|---------|
| `{arg_name}` | Validated parameter value | `{target}` -> `10.0.1.0/24` |
| `{_scan_flags}` | Resolved from `[command.mappings]` | `-sT -sV --version-intensity 5` |
| `{_output_file}` | Auto-generated evidence output path | `/evidence/123-nmap/scan.xml` |
| `{_scan_id}` | Auto-generated scan/invocation ID | `1711929600-12345` |
| `{_evidence_dir}` | Evidence directory from runtime config | `/evidence` |
| `{_secret:name}` | Resolved from environment/Vault | (never logged) |

Variables prefixed with `_` are injected by the executor, not provided by the agent. The agent only fills parameters declared in `[args]`.

## Mappings

Mappings translate logical enum values to actual CLI flag strings:

```toml
[args.scan_type]
type = "enum"
allowed = ["ping", "service", "version", "syn", "os_detect"]

[command]
template = "nmap {_scan_flags} {target}"

[command.mappings.scan_type]
ping = "-sn -PE"
service = "-sT -sV --version-intensity 5"
version = "-sV --version-all --top-ports 1000"
syn = "-sS --top-ports 1000"
os_detect = "-sS -O --osscan-guess"
```

When the agent provides `scan_type = "service"`, the executor:

1. Validates `"service"` is in the `allowed` list
2. Looks up `"service"` in `[command.mappings.scan_type]`
3. Sets `{_scan_flags}` to `"-sT -sV --version-intensity 5"`
4. Interpolates the template

The agent selects a logical operation ("service scan"). The manifest translates it to the correct flags. The agent never needs to know nmap's flag syntax.

## Conditionals

For tools where some flags should only be present when certain conditions are met:

```toml
[command]
template = "hydra {_service_flags} {_credential_flags} {_thread_flags} {target}"

[command.conditionals]
service_port = { when = "port != 0", template = "-s {port}" }
username_file = { when = "username_file != ''", template = "-L {username_file}" }
password_file = { when = "password_file != ''", template = "-P {password_file}" }
single_user = { when = "username != '' and username_file == ''", template = "-l {username}" }
single_pass = { when = "password != '' and password_file == ''", template = "-p {password}" }
```

### `when` Expression Syntax

Conditionals use a closed-vocabulary expression parser (no `eval`, no dynamic code execution):

| Expression | Meaning |
|-----------|---------|
| `arg == value` | Equality check |
| `arg != value` | Inequality check |
| `arg != ''` | Non-empty check |
| `expr1 and expr2` | Both must be true |

Values are compared as strings. The parser only supports `==`, `!=`, and `and`. This is deliberately limited -- complex dispatch logic belongs in a custom executor.

### Conditional Evaluation Order

Conditionals are evaluated in declaration order. Each conditional that evaluates to `true` has its template fragment interpolated and appended to the command. Conditionals that evaluate to `false` are omitted entirely (no empty strings left in the command).

## Defaults

Provide default values for template variables that are not declared as args:

```toml
[command]
template = "nmap {_scan_flags} --max-rate {max_rate} -oX {_output_file} {target}"

[command.defaults]
max_rate = 1000
```

If `max_rate` is not provided as an arg and has no arg definition, the default value is used. This is useful for internal tuning knobs that should not be exposed to the agent.

## Escape Hatch: Custom Executor

When a tool's invocation logic exceeds what templates can express, delegate to a custom executor script:

```toml
[command]
executor = "scripts/tool-wrappers/msf-wrapper.sh"
```

The custom executor receives validated arguments as environment variables:

| Variable | Source |
|----------|--------|
| `TOOLCLAD_ARG_MODULE` | Validated `module` arg value |
| `TOOLCLAD_ARG_TARGET` | Validated `target` arg value |
| `TOOLCLAD_ARG_PORT` | Validated `port` arg value |
| `TOOLCLAD_SCAN_ID` | Auto-generated scan ID |
| `TOOLCLAD_OUTPUT_DIR` | Evidence output directory |
| `TOOLCLAD_EVIDENCE_DIR` | Root evidence directory |

The escape hatch is for command construction only. All other ToolClad guarantees still apply:

- Parameter validation runs before the executor is called
- Scope enforcement runs on `scope_target` args
- Timeout enforcement wraps the executor process
- Evidence envelope captures the executor's stdout
- Cedar policy evaluation runs before anything executes

```bash
#!/bin/bash
# scripts/tool-wrappers/msf-wrapper.sh
# Complex msfconsole invocation that exceeds template capabilities

msfconsole -q -x "
  use ${TOOLCLAD_ARG_MODULE};
  set RHOSTS ${TOOLCLAD_ARG_TARGET};
  set RPORT ${TOOLCLAD_ARG_PORT};
  set PAYLOAD ${TOOLCLAD_ARG_PAYLOAD};
  set LHOST ${TOOLCLAD_ARG_LHOST};
  set LPORT ${TOOLCLAD_ARG_LPORT};
  ${TOOLCLAD_ARG_OPTIONS:+$(echo "$TOOLCLAD_ARG_OPTIONS" | tr ';' '\n')}
  run;
  exit
"
```

## Secret Injection

The `{_secret:name}` syntax resolves secrets from environment variables at invocation time. Secrets never appear in the manifest, MCP schema, or LLM context.

```toml
[http]
url = "https://api.example.com/v1/{endpoint}?key={_secret:api_key}"
headers = { "Authorization" = "Bearer {_secret:bearer_token}" }
```

Resolution: `{_secret:api_key}` -> `$TOOLCLAD_SECRET_API_KEY` environment variable. In Symbiont, secrets resolve from Vault/OpenBao.

## Array-Based Execution

Commands are split into an argv array and dispatched via direct `execve`. There is no `sh -c` shell interpretation:

```
Template: "nmap -sT -sV --max-rate 1000 10.0.1.0/24"
Argv:     ["nmap", "-sT", "-sV", "--max-rate", "1000", "10.0.1.0/24"]
```

This means:

- No shell expansion (`$HOME`, `~`, `*`)
- No piping (`|`)
- No command chaining (`&&`, `;`)
- No subshell execution (`` `cmd` ``, `$(cmd)`)

Even if injection characters somehow pass type validation, they are treated as literal strings by `execve`.

## Process Group Kill on Timeout

Tools are spawned in a new process group (PGID). When `timeout_seconds` is exceeded, the executor sends `SIGTERM` to the entire process group, then `SIGKILL` after a grace period. This kills the tool and all its child processes -- no zombie processes, no orphaned background jobs.

```
Spawn:   tool PID=1234, PGID=1234
Timeout: kill(-1234, SIGTERM)  ->  kills PID 1234 and all children
Grace:   kill(-1234, SIGKILL)  ->  force kill if still alive
```

## Full Example: Hydra with Conditionals

```toml
[tool]
name = "hydra_bruteforce"
version = "1.0.0"
binary = "hydra"
description = "Network login brute-force"
timeout_seconds = 1800
risk_tier = "high"
human_approval = true

[args.target]
position = 1
required = true
type = "scope_target"

[args.service]
position = 2
required = true
type = "enum"
allowed = ["ssh", "ftp", "http-get", "http-post-form", "smb", "rdp", "mysql", "postgres"]

[args.port]
type = "port"
required = false
default = 0

[args.username]
type = "string"
required = false
default = ""

[args.password]
type = "string"
required = false
default = ""

[args.username_file]
type = "credential_file"
required = false

[args.password_file]
type = "credential_file"
required = false

[args.threads]
type = "integer"
min = 1
max = 64
clamp = true
default = 4

[command]
template = "hydra {_conditional_flags} -t {threads} {target} {service}"

[command.conditionals]
service_port = { when = "port != 0", template = "-s {port}" }
username_file = { when = "username_file != ''", template = "-L {username_file}" }
password_file = { when = "password_file != ''", template = "-P {password_file}" }
single_user = { when = "username != '' and username_file == ''", template = "-l {username}" }
single_pass = { when = "password != '' and password_file == ''", template = "-p {password}" }

[output]
format = "text"
parser = "builtin:text"
envelope = true

[output.schema]
type = "object"

[output.schema.properties.raw_output]
type = "string"
description = "Hydra brute-force results"
```
