#!/usr/bin/env bash
# Run every reference runtime's test suite.
#
# The suites are the only place the shared vector files in this directory are
# enforced, so "all four green" is what keeps the implementations from drifting
# apart. Each suite loads tests/injection_vectors.json and
# tests/scope_vectors.json from the repository root.
#
# Usage:  tests/run_all.sh [rust|go|js|python ...]
#         (no arguments runs all four)
#
# Environment:
#   TOOLCLAD_PYTHON   python interpreter to use for the Python suite
#                     (default: python3; point this at a virtualenv that has
#                     the package installed with its dev extra)
#   CARGO_JOBS        -j value for cargo (default: 2)

set -uo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
python_bin="${TOOLCLAD_PYTHON:-python3}"
cargo_jobs="${CARGO_JOBS:-2}"

targets=("$@")
if [ ${#targets[@]} -eq 0 ]; then
    targets=(rust go js python)
fi

failed=()

run_step() {
    local name="$1"
    shift
    printf '\n=== %s ===\n' "$name"
    if "$@"; then
        printf '--- %s: OK\n' "$name"
    else
        printf '--- %s: FAILED\n' "$name"
        failed+=("$name")
    fi
}

for target in "${targets[@]}"; do
    case "$target" in
    rust)
        run_step "rust fmt" env -C "$repo_root/rust" cargo fmt --all --check
        run_step "rust clippy" env -C "$repo_root/rust" \
            cargo clippy --all-targets --all-features "-j$cargo_jobs" -- -D warnings
        run_step "rust test" env -C "$repo_root/rust" \
            cargo test --all-features "-j$cargo_jobs"
        ;;
    go)
        run_step "go vet" env -C "$repo_root/go" go vet ./...
        run_step "go test" env -C "$repo_root/go" go test ./...
        ;;
    js)
        run_step "js test" env -C "$repo_root/js" npm test
        ;;
    python)
        run_step "python test" env -C "$repo_root/python" "$python_bin" -m pytest -q
        ;;
    *)
        printf 'unknown target: %s\n' "$target" >&2
        exit 2
        ;;
    esac
done

printf '\n'
if [ ${#failed[@]} -eq 0 ]; then
    printf 'all suites passed\n'
    exit 0
fi
printf 'failed: %s\n' "${failed[*]}"
exit 1
