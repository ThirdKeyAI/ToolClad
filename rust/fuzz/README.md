# ToolClad fuzz targets

`cargo-fuzz` targets for the Rust runtime. This crate is excluded from the
main package (`exclude = ["fuzz"]` in `../Cargo.toml`) and is its own
workspace, so `cargo test` and `cargo clippy` on the library never build it.

| Target | Property |
|---|---|
| `validate_arg` | The argument validator never panics, and never returns a value for a string-derived type (`string`, `path`, `regex_match`, `url`, `scope_target`, `duration`, `msf_options`) that contains whitespace, a quote, a backslash, a control character, or a leading `-`/`+` without the matching opt-in. `msf_options` may keep its ASCII space separator. No definition sets `block_internal`, so no input does DNS. |
| `parse_manifest` | The strict manifest loader never panics on any input. |

## Running

Requires a nightly toolchain and `cargo install cargo-fuzz`. From `rust/`:

```bash
CARGO_BUILD_JOBS=2 cargo +nightly fuzz build
cargo +nightly fuzz run validate_arg -- -max_total_time=20
cargo +nightly fuzz run parse_manifest -- -max_total_time=20
```

Drop `-max_total_time` to fuzz until stopped. A crashing input is written to
`fuzz/artifacts/<target>/`; replay it with
`cargo +nightly fuzz run <target> fuzz/artifacts/<target>/<file>`, fix the
validator, and add the input as a unit test in the main crate.

The same `validate_arg` property also runs in the ordinary test suite over a
few thousand deterministic pseudo-random inputs
(`validator::tests::test_validator_property_over_pseudo_random_inputs`), so it
is exercised in CI even where the fuzzer is not run.
