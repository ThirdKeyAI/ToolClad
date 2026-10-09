// The shared cross-language negative suite: tests/injection_vectors.json.
// Every vector must give its stated verdict here, unmodified.

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { validateArg } from "../src/validator.js";
import { loadManifestFromString } from "../src/manifest.js";

const VECTORS = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "tests", "injection_vectors.json");
const SKIP = existsSync(VECTORS)
  ? false
  : `${VECTORS} not found (package built outside the repository)`;

function verdict(fn) {
  try {
    fn();
    return { verdict: "accept" };
  } catch (err) {
    return { verdict: "reject", error: err };
  }
}

describe("tests/injection_vectors.json", { skip: SKIP }, () => {
  it("every vector gives its stated verdict", () => {
    const doc = JSON.parse(readFileSync(VECTORS, "utf-8"));
    const failures = [];
    let executed = 0;

    for (const v of doc.arg_vectors) {
      // Strict single-argument entry point (template mode).
      const got = verdict(() => validateArg({ ...v.arg }, v.value));
      executed++;
      if (got.verdict !== v.expect) {
        failures.push(
          `arg vector ${v.id}: expected ${v.expect}, got ${got.verdict}` +
            (got.error ? ` (${got.error.message})` : "") +
            ` -- ${v.note}`
        );
      }
    }

    // Discovery (toolclad.toml, scope) starts from an empty directory so no
    // file outside the vector can change its verdict.
    const baseDir = mkdtempSync(join(tmpdir(), "toolclad-vectors-"));
    const savedWarn = console.warn;
    console.warn = () => {};
    try {
      for (const v of doc.manifest_vectors) {
        const got = verdict(() => loadManifestFromString(v.manifest, { baseDir, customTypes: {} }));
        executed++;
        if (got.verdict !== v.expect) {
          failures.push(
            `manifest vector ${v.id}: expected ${v.expect}, got ${got.verdict}` +
              (got.error ? ` (${got.error.message})` : "") +
              ` -- ${v.note}`
          );
        }
      }
    } finally {
      console.warn = savedWarn;
    }

    assert.ok(executed > 0, "no vectors executed");
    console.log(
      `injection vectors executed: ${executed} ` +
        `(${doc.arg_vectors.length} arg, ${doc.manifest_vectors.length} manifest)`
    );
    assert.deepEqual(failures, []);
  });
});
