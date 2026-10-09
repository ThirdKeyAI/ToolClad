// Property tests for the argument validator (W13). For every string-derived
// type the validator either returns a value or throws a plain Error; it never
// throws a programming error (TypeError, RangeError, ...) or a non-Error, and
// an accepted value never violates the hygiene rules: no control character,
// no quote or backslash, no whitespace (msf_options exempt, U+0020 only), and
// no leading '-' or '+'.
//
// No argument here sets block_internal, so nothing resolves DNS.

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";
import { validateArg, validateArgMode } from "../src/validator.js";

const NUM_RUNS = 2000;

const ARG_DEFS = [
  { type: "string" },
  { type: "string", pattern: "[\\s\\S]*" },
  { type: "path" },
  { type: "regex_match", pattern: "[\\s\\S]*" },
  { type: "url" },
  { type: "url", schemes: ["http", "https", "ftp", "file", "gopher"] },
  { type: "scope_target" },
  { type: "duration" },
  { type: "msf_options" },
];

// Characters the hygiene rules exist for, plus enough ordinary ones to let
// values reach the type-specific parsers.
const NASTY = [
  "\0", "\t", "\n", "\r", "\v", "\f", "\x1b", "\x7f", "\x85", "\x9f",
  " ", "\u00a0", "\u1680", "\u2000", "\u2009", "\u200b", "\u2028", "\u2029",
  "\u202e", "\u3000", "\ufeff", "'", '"', "\\", "`", "$", ";", "|", "&",
  "<", ">", "(", ")", "{", "}", "[", "]", "*", "?", "!", "#", "%", "~",
  "-", "+", "=", ",", "@", ":", "/", ".", "_",
  "a", "z", "A", "Z", "0", "1", "9", "x", "s", "m", "h",
  "\u0430", "\u0131", "\u212a", "\ud83d\ude00", "\uff0e", "\u2215",
];

const nastyString = fc.string({ unit: fc.constantFrom(...NASTY), maxLength: 40 });

const value = fc.oneof(
  fc.string(),
  fc.string({ unit: "binary" }),
  nastyString,
  fc.tuple(
    fc.constantFrom("http://", "https://", "ftp://", "file://", "-", "+", "10.", "a.example.", "RHOSTS "),
    nastyString
  ).map(([prefix, rest]) => prefix + rest),
  fc.tuple(fc.integer({ min: 0, max: 99999 }), fc.constantFrom("", "s", "m", "h", "ms", "d"), nastyString)
    .map(([n, unit, rest]) => `${n}${unit}${rest}`)
);

const CONTROL = /[\u0000-\u001f\u007f-\u009f]/u;
const QUOTE = /['"\\]/u;
const WHITESPACE = /\s/u;
const NON_SPACE_WHITESPACE = /(?! )\s/u;

const PROGRAMMING_ERRORS = [TypeError, RangeError, ReferenceError, SyntaxError, EvalError, URIError];

function assertExpectedError(err, def, input) {
  const where = `${def.type} ${JSON.stringify(def)} on ${JSON.stringify(input)}`;
  assert.ok(err instanceof Error, `non-Error thrown for ${where}: ${String(err)}`);
  for (const bad of PROGRAMMING_ERRORS) {
    assert.ok(!(err instanceof bad), `${err.name} for ${where}: ${err.message}`);
  }
}

function assertHygiene(out, def, input, { spaceAllowed }) {
  const where = `${def.type} ${JSON.stringify(def)} on ${JSON.stringify(input)} -> ${JSON.stringify(out)}`;
  assert.equal(typeof out, "string", `non-string result for ${where}`);
  assert.ok(!CONTROL.test(out), `control character accepted: ${where}`);
  assert.ok(!QUOTE.test(out), `quote or backslash accepted: ${where}`);
  assert.ok(!/^[-+]/u.test(out), `leading dash or plus accepted: ${where}`);
  if (spaceAllowed) {
    assert.ok(!NON_SPACE_WHITESPACE.test(out), `non-space whitespace accepted: ${where}`);
  } else {
    assert.ok(!WHITESPACE.test(out), `whitespace accepted: ${where}`);
  }
}

function check(def, input, execMode) {
  let out;
  try {
    out = execMode ? validateArgMode(def, input, true) : validateArg(def, input);
  } catch (err) {
    assertExpectedError(err, def, input);
    return;
  }
  const spaceAllowed =
    def.type === "msf_options" || (execMode && def.allow_whitespace === true);
  assertHygiene(out, def, input, { spaceAllowed });
}

describe("validator property tests (fast-check)", () => {
  it("strict mode: never crashes, never accepts an unhygienic value", () => {
    fc.assert(
      fc.property(fc.constantFrom(...ARG_DEFS), value, (def, input) => {
        check(def, input, false);
      }),
      { numRuns: NUM_RUNS }
    );
  });

  it("exec mode with allow_whitespace: only U+0020 gets through", () => {
    fc.assert(
      fc.property(fc.constantFrom(...ARG_DEFS), value, (def, input) => {
        check({ ...def, allow_whitespace: true }, input, true);
      }),
      { numRuns: NUM_RUNS }
    );
  });

  it("a leading dash needs allow_leading_dash; with it the other rules still hold", () => {
    fc.assert(
      fc.property(fc.constantFrom(...ARG_DEFS), nastyString, (def, rest) => {
        const input = `-${rest}`;
        assert.throws(() => validateArg(def, input), Error);
        let out;
        try {
          out = validateArg({ ...def, allow_leading_dash: true }, input);
        } catch (err) {
          assertExpectedError(err, def, input);
          return;
        }
        assert.equal(typeof out, "string");
        assert.ok(!CONTROL.test(out) && !QUOTE.test(out), `unhygienic: ${JSON.stringify(out)}`);
        if (def.type !== "msf_options") {
          assert.ok(!WHITESPACE.test(out), `whitespace accepted: ${JSON.stringify(out)}`);
        }
      }),
      { numRuns: NUM_RUNS }
    );
  });

  it("non-string inputs are refused or coerced, never crash", () => {
    const odd = fc.oneof(
      fc.integer(),
      fc.double(),
      fc.boolean(),
      fc.constant(null),
      fc.constant(undefined),
      fc.array(fc.string(), { maxLength: 3 }),
      fc.dictionary(fc.string(), fc.string(), { maxKeys: 2 })
    );
    fc.assert(
      fc.property(fc.constantFrom(...ARG_DEFS), odd, (def, input) => {
        let out;
        try {
          out = validateArg(def, input);
        } catch (err) {
          assertExpectedError(err, def, input);
          return;
        }
        assertHygiene(out, def, input, { spaceAllowed: def.type === "msf_options" });
      }),
      { numRuns: NUM_RUNS }
    );
  });
});

describe("fuzz regressions", () => {
  it("a prototype-less object is refused with a plain Error, not a TypeError", () => {
    for (const def of ARG_DEFS) {
      assert.throws(
        () => validateArg(def, Object.create(null)),
        (err) => err.constructor === Error && /must be a string, number or boolean/.test(err.message),
        def.type
      );
    }
    assert.throws(() => validateArg({ type: "string" }, ["a", "b"]), /got array/);
    assert.throws(() => validateArg({ type: "integer" }, null), /got null/);
  });
});
