# Command Construction

ToolClad command construction is the core mechanism that prevents LLMs from generating arbitrary shell commands. Parameters are validated, then interpolated into a declared command structure. Commands are dispatched via direct `execve` (no `sh -c`), so shell interpretation never occurs.

## Invocation Forms

ToolClad has one canonical invocation form, `exec`, and a deprecated sugar form, `template`, that is compiled into `exec` at load.

### Array Form (Canonical)

Each element is exactly one argv entry, passed directly to `execve` without shell interpretation. Values are substituted into their token and never re-split, so a value that contains whitespace (permitted only with `allow_whitespace = true`) still occupies exactly one argv element.

```toml
[command]
exec = ["curl", "-s", "-S", "-X", "{method}", "-w", "\\n%{{http_code}}", "{_header_flags}", "{url}"]
```

Rules:

- A placeholder must be a **whole, unquoted token** such as `"{url}"`. A placeholder may also sit inside a token with literal text (`"{protocol}://{target}:{port}"`); it is substituted textually and the token is never split.
- `{{` and `}}` are escapes for a literal `{` and `}`. They are not placeholders: `"\\n%{{http_code}}"` reaches curl as `\n%{http_code}`.
- Every placeholder must name a declared `[args.*]` entry, a `[command.defaults]` key, a mapping or conditional variable, or one of the executor variables `_scan_id`, `_output_file`, `_evidence_dir`. Any other placeholder rejects the manifest at load.
- A token that consists of exactly one placeholder whose value is the empty string is dropped, so unset optional arguments disappear from the argv. A token with surrounding literal text is kept even if the placeholder is empty.
- A placeholder that resolves to no variable at build time is a build error: `unresolved placeholder '{name}' in command`.

### String Template Form (Deprecated)

```toml
[command]
template = "whois {target}"
```

`template` is legacy sugar. At load it is tokenized with a POSIX-like splitter that honors `'`/`"` quoting and backslash escapes, and the resulting tokens are stored as the compiled `exec` form. The tokenizer runs on the trusted manifest string only -- substituted values are never re-split. Loading a manifest with `template` prints, once per load:

```
warning: [command] template is deprecated and will be removed in the next minor release; use exec = [...]
```

Two template-specific rejections:

- A `{` inside quotes (for example `-H '{headers}'`) rejects the manifest: `command template places a placeholder inside quotes at offset N; placeholders must be whole, unquoted tokens (use exec = [...])`. A `{{` escape inside quotes (`'%{{http_code}}'`) is legal.
- Unbalanced quotes reject the manifest.

A manifest that declares `template` is validated in template mode even after compilation: `allow_whitespace` is **not** honored. When both `exec` and `template` are present, `exec` is used. Every `[command.conditionals.<name>].template` is tokenized with the same rules.

### `end_of_options`

```toml
[command]
exec = ["grep", "-r", "{pattern}", "{path}"]
end_of_options = "--"
```

Only the exact value `"--"` is accepted; anything else rejects the manifest. When set, a literal `--` is inserted immediately before the **first** argv token that was produced from a template token consisting solely of a user-argument placeholder (`{pattern}` above), at most once. If no such token exists nothing is inserted. This stops a value from being parsed as an option by tools that honor `--`, on top of the leading-dash rejection the validator already applies.

---

## Template Variables

`exec` array elements (and deprecated `template` strings) support `{placeholder}` interpolation:

```toml
[command]
exec = ["nmap", "{_scan_type_flags}", "--max-rate", "{max_rate}", "-oX", "{_output_file}", "-v", "{target}"]
```

| Variable Pattern | Class | Source | Example |
|-----------------|-------|--------|---------|
| `{arg_name}` | single token | Validated parameter value | `{target}` -> `10.0.1.0/24` |
| `{default_name}` | single token | `[command.defaults]` entry | `{max_rate}` -> `1000` |
| `{_<arg>_flags}` | multi-token | Resolved from `[command.mappings.<arg>]` | `{_scan_type_flags}` -> `-sT -sV --version-intensity 5` |
| `{_<cond>}` | multi-token | Resolved from `[command.conditionals.<cond>]` | `{_header_flags}` -> `-H X-Trace:on`, or nothing |
| `{_output_file}` | single token | Auto-generated evidence output path | `/evidence/123-nmap/scan.xml` |
| `{_scan_id}` | single token | Auto-generated scan/invocation ID | `1711929600-12345` |
| `{_evidence_dir}` | single token | Evidence directory from runtime config | `/evidence` |

Two disjoint classes:

- **Trusted multi-token variables** -- `_<arg>_flags` and `_<cond>` -- hold a token vector produced from manifest-controlled text. When an `exec` element is exactly `{_scan_type_flags}`, that vector is spliced into the argv (zero or more tokens). Mapping values are tokenized at resolve time and conditional templates at load; both come from the manifest, so splitting them is safe.
- **Single-token variables** -- every `[args.*]` value, every `[command.defaults]` entry, and the executor-injected `_scan_id`, `_output_file`, `_evidence_dir` -- are substituted textually into exactly one token and are never split.

The mapping variable name is `_<arg_name>_flags` and nothing else: `{_scan_type_flags}` for `[command.mappings.scan_type]`. Legacy aliases such as `{_scan_type}`, `{_scan_flags}` (unless the argument is literally named `scan`), and `{_cond_<name>}` are not recognized. Variables prefixed with `_` come from the manifest or the executor, never from the agent; the agent only fills parameters declared in `[args]`. `{_secret:name}` is an HTTP-backend feature; see [Secret Injection](#secret-injection).

## Mappings

Mappings translate logical enum values to actual CLI flag strings:

```toml
[args.scan_type]
type = "enum"
allowed = ["ping", "service", "version", "syn", "os_detect"]

[command]
exec = ["nmap", "{_scan_type_flags}", "{target}"]

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
3. Tokenizes the mapped value `-sT -sV --version-intensity 5` (manifest-controlled text) into four tokens and exposes them as `{_scan_type_flags}`
4. Splices those tokens into the argv where `{_scan_type_flags}` appears, producing `["nmap", "-sT", "-sV", "--version-intensity", "5", "10.0.1.0/24"]`

The agent selects a logical operation ("service scan"). The manifest translates it to the correct flags. The agent never needs to know nmap's flag syntax.

## Conditionals

For tools where some flags should only be present when certain conditions are met:

```toml
[command]
exec = ["hydra", "{_service_port}", "{_username_file}", "{_password_file}", "{_single_user}", "{_single_pass}", "{target}", "{service}"]

[command.conditionals]
service_port = { when = "port != ''", template = "-s {port}" }
username_file = { when = "username_file != ''", template = "-L {username_file}" }
password_file = { when = "password_file != ''", template = "-P {password_file}" }
single_user = { when = "username != '' and username_file == ''", template = "-l {username}" }
single_pass = { when = "password != '' and password_file == ''", template = "-p {password}" }
```

Each conditional is exposed as the multi-token variable `{_<name>}` -- `{_service_port}` for `service_port`. Its `template` is tokenized at load with the same rules as `[command].template`: placeholders must be whole, unquoted tokens and `{{`/`}}` escape literal braces. When `when` is true, the tokens are spliced into the argv where `{_<name>}` appears, with the conditional's own placeholders substituted as single tokens; when false, the placeholder contributes zero tokens.

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

Conditionals are evaluated in declaration order. Each conditional's tokens land at the position of its `{_<name>}` placeholder in `exec`, so the manifest author controls where the flags go. Conditionals that evaluate to `false` are omitted entirely (no empty strings are left in the argv).

## Defaults

Provide default values for template variables that are not declared as args:

```toml
[command]
exec = ["nmap", "{_scan_type_flags}", "--max-rate", "{max_rate}", "-oX", "{_output_file}", "{target}"]

[command.defaults]
max_rate = 1000
```

If `max_rate` is not provided as an arg and has no arg definition, the default value is used as a single token. This is useful for internal tuning knobs that should not be exposed to the agent. `[command.defaults]` is an open map (its keys are user-chosen names), so it is exempt from the unknown-key check.

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
| `TOOLCLAD_TOOL_NAME` | `[tool] name` |
| `TOOLCLAD_OUTPUT_DIR` | Evidence output directory |
| `TOOLCLAD_EVIDENCE_DIR` | Root evidence directory |

These are the **only** additions to an otherwise cleared environment. The child sees a fixed `PATH` (`/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`) plus `HOME`, `LANG`, `LC_ALL`, `TZ`, and `TERM` if the parent had them. `TOOLCLAD_SECRET_*` is never passed to the executor; secrets are not available to escape-hatch scripts. The executor path is resolved like any other `argv[0]` (used as-is when it contains a path separator, otherwise looked up on the fixed `PATH`) and is subject to the interpreter denylist -- `executor = "python3"` is refused at load unless `[tool] allow_interpreter = true`, while a script such as `msf-wrapper.sh` is fine because its basename is not an interpreter.

The escape hatch is for command construction only. All other ToolClad guarantees still apply:

- Parameter validation runs before the executor is called
- Scope enforcement runs on args with `scope_check = true`
- The policy gate runs before anything executes (Cedar evaluation is external)
- The hardened spawn path applies: stdin from `/dev/null`, a 0700 per-invocation scratch cwd, process group kill on timeout
- Timeout enforcement wraps the executor process
- Evidence envelope captures the executor's stdout, subject to `[output] max_bytes`

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

The `{_secret:name}` syntax, used in `[http]` templates (`url`, `headers` values, `body_template`), resolves secrets at invocation time. Secrets never appear in the manifest, MCP schema, LLM context, or evidence envelope.

```toml
[http]
url = "https://api.example.com/v1/{endpoint}?key={_secret:api_key}"
headers = { "Authorization" = "Bearer {_secret:bearer_token}" }
```

Resolution order:

1. The TOML file named by `TOOLCLAD_SECRETS_FILE` (`api_key = "..."` at top level). The file's permissions are checked and it is rejected if group- or other-readable. When present, it wins.
2. `TOOLCLAD_SECRET_<NAME>` in the runtime's own environment (`{_secret:api_key}` -> `$TOOLCLAD_SECRET_API_KEY`).

A missing secret is a hard error. Secrets are expanded on the manifest template **before** argument interpolation, so an argument value can never introduce a secret reference; `TOOLCLAD_SECRET_*` is never passed to any child process; and the envelope's `command` holds the unexpanded template. A hosting runtime such as Symbiont may resolve secrets from Vault/OpenBao instead; that integration is outside the reference runtimes.

## Array-Based Execution

All commands are dispatched via direct `execve` with an argument array. There is no `sh -c` shell interpretation:

```
# exec form — already an array, no splitting needed:
exec = ["nmap", "-sT", "-sV", "--max-rate", "1000", "10.0.1.0/24"]

# template form (deprecated) — tokenized at load, before any value is substituted:
Template: "nmap -sT -sV --max-rate 1000 {target}"
Compiled: ["nmap", "-sT", "-sV", "--max-rate", "1000", "{target}"]
Argv:     ["nmap", "-sT", "-sV", "--max-rate", "1000", "10.0.1.0/24"]
```

The `exec` form is canonical because it preserves argument boundaries exactly as declared -- no splitting heuristics, no edge cases with quotes or spaces. In both forms the argv is built by substituting values into already-separated tokens; a substituted value is never re-split. `argv[0]` is resolved to an absolute path against a fixed `PATH` at spawn time, and the child runs with a cleared, allowlisted environment and stdin from `/dev/null` (see [Security Model](security-model.md#spawn-path-hardening)).

This means:

- No shell expansion (`$HOME`, `~`, `*`)
- No piping (`|`)
- No command chaining (`&&`, `;`)
- No subshell execution (`` `cmd` ``, `$(cmd)`)

Even if injection characters somehow pass type validation, they are treated as literal strings by `execve`.

## Process Group Kill on Timeout

Tools are spawned in a new process group (PGID). When `timeout_seconds` is exceeded, the executor sends `SIGTERM` to the entire process group, waits a grace period of `TOOLCLAD_KILL_GRACE_MS` milliseconds (default 2000), then sends `SIGKILL` to the group. This kills the tool and all its child processes -- no zombie processes, no orphaned background jobs. The same sequence is used by all four runtimes (Go via `cmd.Cancel` + `cmd.WaitDelay`; JavaScript via an async `spawn` with a timer, which is why its `execute` is asynchronous).

```
Spawn:   tool PID=1234, PGID=1234
Timeout: kill(-1234, SIGTERM)  ->  kills PID 1234 and all children
Grace:   wait TOOLCLAD_KILL_GRACE_MS (default 2000 ms)
Then:    kill(-1234, SIGKILL)  ->  force kill if still alive
```

Output captured before the kill is returned in the envelope with `status: "timeout"` (and `output_truncated` if the `max_bytes` cap was hit). `timeout_seconds = 0` is refused at load with `timeout_seconds must be greater than zero`; the default remains 60.

## Full Example: Hydra with Conditionals

```toml
[tool]
name = "hydra_bruteforce"
version = "1.0.0"
binary = "hydra"
description = "Network login brute-force"
timeout_seconds = 1800
risk_tier = "high"          # Denied by the default policy gate: run with --approve
human_approval = true
network_egress = true       # hydra is also on the known egress-binary list

[args.target]
position = 1
required = true
type = "scope_target"
block_internal = true       # Mandatory for an egress tool; the manifest is refused without it
scope_check = true          # Allowlist against scope/scope.toml (fail-closed)

[args.service]
position = 2
required = true
type = "enum"
allowed = ["ssh", "ftp", "http-get", "http-post-form", "smb", "rdp", "mysql", "postgres"]

[args.port]
type = "port"
required = false

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
exec = [
    "hydra",
    "{_service_port}",
    "{_username_file}", "{_password_file}",
    "{_single_user}", "{_single_pass}",
    "-t", "{threads}",
    "{target}", "{service}",
]

[command.conditionals]
service_port = { when = "port != ''", template = "-s {port}" }
username_file = { when = "username_file != ''", template = "-L {username_file}" }
password_file = { when = "password_file != ''", template = "-P {password_file}" }
single_user = { when = "username != '' and username_file == ''", template = "-l {username}" }
single_pass = { when = "password != '' and password_file == ''", template = "-p {password}" }

[output]
format = "text"
parser = "builtin:text"
envelope = true
max_bytes = 8388608

[output.schema]
type = "object"

[output.schema.properties.raw_output]
type = "string"
description = "Hydra brute-force results"
```
