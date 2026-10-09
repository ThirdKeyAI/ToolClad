# Changelog

All notable changes to ToolClad are recorded here. The manifest format and the
four reference runtimes share one version number; the protocol-level history
before this file lives in the Changelog section of `TOOLCLAD_DESIGN_SPEC.md`.

## [Unreleased]

A security review of the reference runtimes produced 23 findings. This release
closes all of them. Several are **breaking by design** — a control that
silently degraded to "off" is worse than a control that refuses to load — so
read "Breaking changes" before upgrading.

### Breaking changes

- **Unknown manifest keys are refused at load** (TC-13). A typo such as
  `tiemout_seconds` or a control an older runtime does not support now fails
  the manifest instead of falling back to a default. Authoring escape hatch:
  `toolclad validate --allow-unknown-keys`.
- **Whitespace, quotes, backslashes and a leading `-`/`+` are refused in
  string-derived argument values** (TC-1, TC-3). Opt back in per argument with
  `allow_whitespace = true` (honored only with the `exec` form) and
  `allow_leading_dash = true`. Negative numbers need `allow_leading_dash`.
- **`[command] template` is deprecated** and is tokenized into an `exec` array
  at load, with a load-time warning. A template whose placeholder sits inside
  quotes (`-H '{headers}'`) no longer loads. `{{` and `}}` are now escapes for
  literal braces.
- **Mapping and conditional variable names are unified** (TC-23): mappings are
  `{_<arg_name>_flags}` only, conditionals are `{_<cond_name>}` only. The Rust
  `_<arg>` alias, the Go `_<prefix>_flags` alias, the shared `_scan_flags`
  alias and the JavaScript `_cond_<name>` spelling are gone.
- **An unresolved placeholder is an error**, at load where it can be detected
  and at build otherwise. It used to reach argv as a literal token.
- **`execute()` takes a policy gate** and denies by default when
  `human_approval = true` or `risk_tier` is `high`/`critical` (TC-9). The
  existing signatures keep working through a default-gate shim; pass an
  approving gate, or `--approve` on the CLIs, to run such a manifest.
- **`timeout_seconds = 0` is refused** at load (TC-11); it used to disable the
  timeout entirely in Rust.
- **Custom output parsers are refused at load** (TC-14). They were silently
  ignored, which produced unvalidated output under a manifest that claimed to
  parse and validate.
- **`scope_check = true` is enforced and fail-closed** (TC-10). With no
  reachable `scope/scope.toml`, the call is refused rather than allowed.
- **The `url` type defaults to `schemes = ["http", "https"]`** and refuses
  dangerous schemes outright (TC-6).
- **An interpreter as `argv[0]`** (`sh`, `bash`, `python`, `node`, `env`, …) is
  refused at load unless `[tool] allow_interpreter = true` (TC-21).
- **`argv[0]`'s basename must match `tool.binary`'s** (TC-8).
- **The evidence envelope's `command` field reports the declared command**, not
  the expanded argv, so executor-injected paths and expanded secrets no longer
  reach the agent. The human-facing dry run still shows the resolved argv.
- **The JavaScript `execute()` is now async** (TC-11), so the timeout no longer
  depends on the child closing its output pipe. `executeSync` remains as a
  shim that explains the change.

### Security fixes

- **TC-1 (critical)** — Argument and option injection through template
  re-splitting. The trusted template is now tokenized at load, before any value
  exists; each placeholder resolves to exactly one argv entry and the result is
  never re-split. String-derived types reject whitespace and quotes.
  All four runtimes.
- **TC-2 (critical)** — The shipped `nmap_scan` manifest exposed a free-form
  `extra_flags` string, which is arbitrary nmap option injection (`-iL` file
  disclosure, `-oN` file write, `--script` Lua execution in a process that
  usually holds `CAP_NET_RAW`). The parameter is removed; every supported
  invocation is a `[command.mappings]` entry.
- **TC-3 (high)** — No leading-dash protection in any mode. Default-deny `^[-+]`
  for string-derived types, `allow_leading_dash` to opt in, and
  `[command] end_of_options = "--"` for tools whose parser honors it.
- **TC-4 (high)** — `block_internal` was implemented only in Rust and silently
  dropped by Go, JavaScript and Python, so the shipped examples had no SSRF
  defense in three runtimes. Ported to all four from one shared range table,
  with unknown-key rejection (TC-13) ensuring a runtime that lacks a control
  refuses the manifest instead of running without it.
- **TC-5 (high)** — The Rust `block_internal` was a literal-IP string check.
  Added the unconditional internal-name denylist (`localhost`, `.local`,
  `.internal`, `.home.arpa`, …), embedded-IP-literal hostname detection
  (`127.0.0.1.nip.io`, `10-0-0-1.nip.io`), CIDR **overlap** testing so
  `8.0.0.0/5` can no longer smuggle `10.0.0.0/8`, and DNS resolution with the
  range policy applied to every answer and failure treated as refusal.
- **TC-6 (high)** — One normative `url` validator: scheme allowlist defaulting
  to http/https, explicit refusal of `javascript:`, `data:`, `file:`, `blob:`,
  `about:`, `gopher:`, `dict:` and friends, userinfo refused, hygiene checks
  applied (the JavaScript validator previously ran none), and Rust now honors
  `schemes`.
- **TC-7 (high)** — JavaScript expanded `{_secret:name}` *after* argument
  interpolation, so a `url` value could exfiltrate a secret. Secrets are now
  expanded on the manifest template first, in every runtime.
- **TC-8 (high)** — Tools inherited the runtime's whole environment, including
  `TOOLCLAD_SECRET_*`, `LD_PRELOAD` and `PATH`. The child environment is now
  cleared and rebuilt from an allowlist, secrets are never passed to a child
  (and may live in `TOOLCLAD_SECRETS_FILE` instead of the environment), and
  `argv[0]` is resolved to an absolute path against a fixed `PATH`.
- **TC-9 (medium)** — Cedar, `risk_tier` and `human_approval` were parsed and
  printed only; `toolclad run` would execute a `human_approval = true` manifest
  unconditionally. Added the gate seam described above. Cedar evaluation is
  explicitly external.
- **TC-10 (medium)** — `scope_check`, `scope_target` and the browser
  `allowed_domains`/`blocked_domains` enforced no scope at all. Implemented
  `scope/scope.toml` loading and wired `scope_check` in all four runtimes, with
  `tests/scope_vectors.json` now executed by every suite.
- **TC-11 (medium)** — Timeout gaps: Go could hang forever waiting on the
  output pipe, JavaScript relied on `SIGTERM` to a `spawnSync` child, Rust
  treated `0` as "no timeout", and no runtime had a `SIGTERM` grace period.
  Fixed with `cmd.WaitDelay`/`cmd.Cancel` in Go, async `spawn` with a timer in
  JavaScript, load-time refusal of `0`, and a `SIGTERM` → grace → `SIGKILL`
  group kill everywhere (`TOOLCLAD_KILL_GRACE_MS`, default 2000 ms).
- **TC-12 (medium)** — Unbounded stdout capture and untrusted XML entity
  expansion. Added `[output] max_bytes` (default 8 MiB) with
  `output_truncated` in the envelope, and refusal of XML containing
  `<!DOCTYPE`/`<!ENTITY`.
- **TC-13 (medium)** — Unknown manifest keys were silently ignored in all four
  parsers. This was the mechanism by which the examples looked hardened but
  were not. Now a load error.
- **TC-14 (medium)** — Output-schema validation was absent or silently skipped
  (Python swallowed `ImportError` for an undeclared dependency). Each runtime
  now bundles a JSON-Schema subset validator and fails closed with
  `schema_error`.
- **TC-15 (medium)** — The Rust-only egress lint was bypassable through custom
  and `string` types. Egress is now a declared manifest property
  (`[tool] network_egress`), the lint is ported to all four runtimes, and a
  custom-typed network target is refused because a custom type cannot carry
  `block_internal`.
- **TC-16 (medium)** — HTTP backend: raw interpolation into URL and headers,
  Go not JSON-escaping the body, secrets echoed into the envelope and (in
  JavaScript) onto the curl argv where `/proc/<pid>/cmdline` exposes them, and
  unchecked redirects. Interpolated values are percent-encoded, a placeholder
  in the scheme or host is a load error, Go escapes the body, the envelope
  carries the unexpanded template, redirects are not followed
  (`redirect_blocked`), and the JavaScript backend uses `fetch` instead of
  spawning curl, so nothing secret reaches a process argv.
- **TC-17 (medium)** — Dependency advisories and an unpinned Go toolchain.
  Updated rustls to 0.23.45, rustls-webpki to 0.103.15, h2 to 0.4.20 and
  anyhow to 1.0.104 (`cargo audit`: 5 vulnerabilities and 1 warning → none);
  pinned `toolchain go1.26.9` in `go/go.mod` (`govulncheck`: 26 reachable
  standard-library advisories → none); added a hash-pinned Python lockfile;
  and added the audits to CI.
- **TC-18 (low)** — Tools inherited stdin in Rust and Python; now
  `/dev/null` everywhere.
- **TC-19 (low)** — Evidence paths were world-writable, low-entropy and
  symlink-following, and Rust never created the directory it advertised in
  `{_output_file}`. The evidence root is created 0700, identifiers carry 128
  bits of entropy, output files are opened `O_NOFOLLOW|O_EXCL` mode 0600, and
  `TOOLCLAD_EVIDENCE_DIR` is honored consistently (JavaScript no longer
  hardcodes `/tmp`).
- **TC-20 (low)** — Validator leniency and cross-runtime drift: `Number("")`
  accepted as `0`, `0x10` as 16, `1_000` and `" 7 "` as integers, bogus IP
  literals and trailing-dot hostnames accepted, durations with a trailing
  newline accepted, and `pattern` acting as a substring test. Patterns are now
  anchored, numeric and duration parsing is strict, and the Rust canonical-IP
  rules apply in all four runtimes.
- **TC-21 (low)** — No process hardening. Added a 0700 per-invocation scratch
  cwd, a restrictive umask, resource limits where the language supports them
  (Rust and Python; Go and Node cannot set child rlimits portably — documented),
  and the interpreter denylist.
- **TC-22 (info)** — README, AGENTS.md and the docs presented session, browser
  and MCP-proxy execution as shipped backends. They are parsed and validated
  but not executable by the reference runtimes, and the docs now say so.
- **TC-23 (info)** — Functional drift with security impact: the `exec` array
  form was unusable in Go, conditionals were never evaluated in Go, the
  executor-injected variables were missing in Go, JavaScript used a
  `_cond_<name>` spelling that made every conditional empty, Rust never
  resolved `{_scan_flags}` and passed the literal token to the tool, the
  `nikto_scan` example could not be loaded by any CLI, and the version strings
  disagreed with the package metadata. All fixed; the CLIs now discover
  `toolclad.toml` custom types.

### Added

- `tests/injection_vectors.json` — shared negative-test vectors (option
  injection, quote breakout, control characters, URL schemes, SSRF literals,
  CIDR overlap, obfuscated IP encodings, unknown manifest keys), executed by
  all four suites alongside the existing `tests/scope_vectors.json`.
- `tests/run_all.sh` and `tests/README.md`.
- `.github/workflows/ci.yml`: the four test suites plus `cargo audit`,
  `govulncheck`, `npm audit` and `pip-audit` on every push, pull request and
  weekly, so a new advisory against a pinned dependency fails the build.
- `python/requirements-dev.lock`, a hash-pinned lockfile for the Python dev
  environment.
- Fuzz targets for the validator and manifest loader: `cargo-fuzz` (Rust), Go
  native fuzzing, `fast-check` (JavaScript), `hypothesis` (Python).
- `scope/scope.toml` starter scope definition.
- New manifest keys: `[tool] network_egress`, `[tool] allow_interpreter`,
  `[tool] mode`, `[tool.limits]`, `[args.*] allow_leading_dash`,
  `[args.*] allow_whitespace`, `[command] end_of_options`,
  `[output] max_bytes`.
- Normative spec sections: tokenization order, argument hygiene, egress safety,
  the gate seam, the process environment, and **Session and Browser Security
  Requirements** (S1–S7) covering control-character rejection, sentinel-anchored
  `ready_pattern` matching, selectors as CDP arguments rather than concatenated
  JavaScript, `execute_js` absent by default, the full URL-scope surface list,
  and the refusal to register a child session from tool output.

### Fixed

- The spec's v0.5.2 claim of "full feature parity across Rust, Python,
  JavaScript, and Go" was not accurate: `block_internal` was 1 of 4, the egress
  lint 1 of 4, `schemes` honored 3 of 4, conditionals 3 of 4 under two naming
  schemes, and the `exec` array working in 3 of 4. The parity gaps are closed
  and the shared vector files now hold them closed.
- Version strings: `js/src/cli.js` reported 0.1.0 and
  `python/toolclad/__init__.py` reported 0.6.1 against a package version of
  0.6.2.
- The `curl_fetch` example's `-w` format string, which was mangled to `%{}` by
  the JavaScript runtime.
