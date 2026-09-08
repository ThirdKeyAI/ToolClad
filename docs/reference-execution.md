# Reference Execution and Migration

The Rust, Python, JavaScript and Go reference runners validate tool contracts and execute selected commands or HTTP requests. They run with the host user's filesystem and network permissions. They are **not a containment boundary for a hostile agent or executable**.

This branch hardens the boundary between supplied arguments, trusted manifest structure and execution. It does not install Symbiont's sandbox, approval service, egress broker or audit service into ToolClad.

## What changes for callers

| Operation | Current reference-runner behavior |
|---|---|
| `validate` | Parses a manifest. Acceptance does not authorize execution or certify containment. |
| `test` | Validates invocation arguments and previews supported backends without executing or fetching HTTP secrets. |
| `run` | Executes supported standalone contracts. Returns a nonzero CLI exit status unless execution reports `success`. |
| Approval, Cedar or explicit `scope_check` | Execution is refused with an embedding-runtime requirement. Preview remains available. There is no approval bypass flag. |
| `dispatch = "callback"` | Validation/preview only. Dispatch belongs to the embedding runtime. |
| MCP | Produces a `delegation_preview`; no upstream call occurs. `run` exits nonzero because the tool has not executed. |
| Session/browser | Parsed contract formats; reference execution remains unavailable. |
| Custom parser | Refused before execution. Reference runners do not execute parser scripts. |
| Multiple backends | Refused as ambiguous. An `exec` array and legacy `template` in the same command section are allowed; `exec` takes precedence. |

The CLI interface retains the same four commands. There is no new graphical UI. The visible differences are earlier refusals, safely quoted command previews, redacted secret previews, bounded failures and meaningful process exit codes.

## Arguments and templates

All supplied names must be declared in `[args]`. Duplicate CLI names, empty names, missing or empty required values and NUL bytes are refused. Defaults in argument definitions, and command defaults referring to declared arguments, pass through the same validators as supplied values. Argument defaults take precedence over command defaults. Clamping applies to defaults as well as supplied values. Generated MCP input schemas set `additionalProperties = false`.

Use `exec = ["tool", "--label", "{label}"]` for literal argument arrays. Every element remains one argument, including an empty element. Values still have to pass their declared validators.

Legacy templates are tokenized **before** argument substitution. For `template = "tool --label {label}"`, the value `alpha --extra` remains one label argument. An omitted optional placeholder can disappear from a legacy template. A literal quoted empty argument remains empty.

Only a standalone placeholder for a trusted mapping or conditional fragment can expand into several legacy-template arguments. Those fragments are tokenized before their argument values are inserted. For example, `_scan_flags` is the short alias for the mapping on `scan_type`. Generic aliases are `_<argument>` and `_<argument>_flags`. In an explicit `exec` array, a fragment remains one element; `"-sT -sV"` does **not** become two flags.

A caller-supplied `{other}` or `{_secret:token}` remains literal data when its type permits it. It is not another template expansion. An argument beginning with `-` can still be interpreted as an option by the selected executable. Manifest authors must use the executable's supported `--` terminator, constrained enums, or separate option-value forms where appropriate.

## HTTP requests and secrets

Reference requests require a fixed manifest-owned `http://` or `https://` authority. Arguments may appear in the path or query, but cannot select a host, port or scheme. URL credentials, fragments and secret placeholders are refused. Put credentials in headers or a body:

```toml
[http]
method = "POST"
url = "https://api.example.com/v1/items/{item_id}"
headers = { Authorization = "Bearer {_secret:api_token}", "Content-Type" = "application/json" }
body_template = '{"label":"{label}"}'
```

Arguments and secret references expand in one pass over the original template. Values in JSON string body slots, including secrets, are JSON-escaped. These slots belong **inside JSON string quotes**; this mechanism is not a general JSON serializer or URL encoder. Use constrained path/query values and encode them in the embedding application where necessary.

Dry runs do not retrieve secrets. JavaScript's asynchronous preview redacts secret slots; CLI previews show method and URL. JavaScript's synchronous curl transport passes headers and body through stdin configuration so secrets are not process arguments. It disables user curl configuration. All reference HTTP transports disable redirects and ambient proxies.

Requests are limited to 1 MiB of URL, headers and body, and responses to 4 MiB. `timeout_seconds` must be an integer from 1 through 3600 for execution/preview. Python overrides may shorten this timeout. Transport behavior differs: Python's urllib timeout is a blocking socket-operation timeout, not a complete wall-clock deadline over DNS and a slowly streamed body. Use an outer runtime deadline when this distinction matters.

A fixed origin is not a DNS or SSRF policy. Operator-configured internal origins remain possible. DNS changes, alternate routing, tool subprocesses and target-specific actions require controls at the actual network boundary. This branch does not claim that the Rust network validators' existing address checks have been ported to every language.

## Processes and evidence

Reference command execution starts with only `PATH`, `LANG`, `LC_ALL` and `SYSTEMROOT` when present. Custom executors additionally receive validated `TOOLCLAD_ARG_*` values and invocation metadata. Stdin is closed. Wrappers that relied on inherited credentials, `HOME`, loader variables or language search paths must obtain explicit configuration from their embedding runtime.

Captured stdout and stderr have a 4 MiB limit per stream. Process supervision uses a deadline and cleanup of the original process group on Unix. Rust/Python drain pipes under the deadline; Go also bounds its wait for pipe closure; JavaScript uses synchronous process limits. A process that leaves the original group can survive. A process group does not restrict filesystem access, network access, privileges or total memory/CPU consumption. Production hostile-code execution needs an OS/container/VM boundary and a supervisor that owns the entire workload.

Evidence envelopes and SHA-256 output hashes are diagnostic records, **not signed audit receipts**. Parser and output-schema behavior still differs across implementations; successful execution does not prove full JSON Schema validation, durable evidence persistence or complete descendant cleanup. A failure can occur after an external effect. Do not automatically retry an effectful call solely because its envelope reports failure.

## Validation

`tests/execution_vectors.json` supplies common argument/argv cases to all four language suites. `tests/e2e_cli.py` launches all four shipping CLIs against temporary process fixtures and loopback HTTP servers. It checks expected exits and actual effects, uses synthetic secrets, includes proxy/redirect traps, and records planned/executed cases plus source/executable hashes before and after the run.

```bash
CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/tmp/toolclad-target cargo build --manifest-path rust/Cargo.toml
(cd go && go build -o /tmp/toolclad-go ./cmd/toolclad)
python3 tests/e2e_cli.py \
  --rust-bin /tmp/toolclad-target/debug/toolclad \
  --go-bin /tmp/toolclad-go \
  --python python3 \
  --report /tmp/toolclad-e2e.json
```

The Python interpreter needs the package's declared dependencies; JavaScript needs `npm install` in `js/`. The local process fixtures use Unix process groups and `/usr/bin/python3`. No provider credentials, external HTTP destinations, autonomous attack model or public services are used. These deterministic checks establish regression coverage for the listed contracts, not proof against all escape attempts.
