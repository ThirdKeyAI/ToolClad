# Cross-language test vectors

The four reference runtimes (`rust/`, `go/`, `js/`, `python/`) are independent
implementations of the same contract. The spec warns that this invites security
drift, and it has happened: a control implemented in one runtime and silently
ignored in three is worse than no control, because the manifest reads as if it
is enforced.

These files are the shared enforcement point. Every runtime's own test suite
loads them and asserts the stated verdict for every vector.

| File | Covers |
|---|---|
| `injection_vectors.json` | Argument and manifest rejection: option injection, quote breakout, whitespace, control characters, URL schemes, SSRF literals and CIDR overlap, obfuscated IP encodings, unknown manifest keys, interpreter binaries |
| `scope_vectors.json` | Scope math: IP-in-CIDR containment, hostname wildcard matching, `scope_target` shape validation, URL host scoping |

## Rules

- **Add vectors before rules.** A new validation rule gets its vectors here
  first; the four implementations then make them pass.
- **Vectors are deterministic.** No vector may depend on live DNS, a writable
  path, the clock, or an environment variable. A suite must give the same
  verdict offline and in CI.
- **`expect` is authoritative.** A runtime that disagrees with a vector is
  wrong, or the vector is wrong and changes for all four in one commit. Never
  let one runtime carry a local exception.

## Format

`injection_vectors.json`:

```json
{
  "arg_vectors": [
    { "id": "…", "arg": { "type": "string" }, "value": "…",
      "expect": "reject", "note": "why this matters" }
  ],
  "manifest_vectors": [
    { "id": "…", "manifest": "<TOML source>",
      "expect": "reject", "note": "why this matters" }
  ]
}
```

`arg.*` fields are ToolClad `[args.<name>]` keys, so a vector maps directly onto
each runtime's argument definition. `manifest` is a complete `.clad.toml`
source string, loaded through the runtime's normal manifest loader.

Positive controls (`"expect": "accept"`) are as important as the rejections:
they are what stops a runtime from passing the suite by refusing everything.

## Running every suite

```bash
tests/run_all.sh                 # all four
tests/run_all.sh rust go         # a subset
TOOLCLAD_PYTHON=/path/to/venv/bin/python tests/run_all.sh python
```
