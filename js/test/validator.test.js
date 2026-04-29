import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { validateArg, checkInjection } from "../src/validator.js";

describe("checkInjection", () => {
  it("accepts clean strings", () => {
    checkInjection("hello-world");
    checkInjection("10.0.1.0/24");
    checkInjection("example.com");
  });

  it("rejects shell metacharacters", () => {
    assert.throws(() => checkInjection("foo;bar"), /Injection detected/);
    assert.throws(() => checkInjection("foo|bar"), /Injection detected/);
    assert.throws(() => checkInjection("$(whoami)"), /Injection detected/);
    assert.throws(() => checkInjection("foo`id`"), /Injection detected/);
    assert.throws(() => checkInjection("foo&bar"), /Injection detected/);
  });
});

describe("validateArg - string", () => {
  it("accepts a plain string", () => {
    const result = validateArg({ type: "string" }, "hello");
    assert.equal(result, "hello");
  });

  it("rejects injection in strings", () => {
    assert.throws(() => validateArg({ type: "string" }, "foo;rm -rf /"), /Injection/);
  });

  it("validates pattern constraint", () => {
    const def = { type: "string", pattern: "^[a-z]+$" };
    assert.equal(validateArg(def, "hello"), "hello");
    assert.throws(() => validateArg(def, "Hello123"), /does not match pattern/);
  });
});

describe("validateArg - integer", () => {
  it("accepts valid integers", () => {
    assert.equal(validateArg({ type: "integer" }, 42), 42);
    assert.equal(validateArg({ type: "integer" }, "10"), 10);
  });

  it("rejects non-integers", () => {
    assert.throws(() => validateArg({ type: "integer" }, "abc"), /Expected integer/);
    assert.throws(() => validateArg({ type: "integer" }, 3.5), /Expected integer/);
  });

  it("enforces min/max", () => {
    const def = { type: "integer", min: 1, max: 10 };
    assert.equal(validateArg(def, 5), 5);
    assert.throws(() => validateArg(def, 0), /below minimum/);
    assert.throws(() => validateArg(def, 11), /exceeds maximum/);
  });

  it("clamps when clamp=true", () => {
    const def = { type: "integer", min: 1, max: 10, clamp: true };
    assert.equal(validateArg(def, 0), 1);
    assert.equal(validateArg(def, 100), 10);
    assert.equal(validateArg(def, 5), 5);
  });
});

describe("validateArg - port", () => {
  it("accepts valid ports", () => {
    assert.equal(validateArg({ type: "port" }, 80), 80);
    assert.equal(validateArg({ type: "port" }, 65535), 65535);
    assert.equal(validateArg({ type: "port" }, "443"), 443);
  });

  it("rejects invalid ports", () => {
    assert.throws(() => validateArg({ type: "port" }, 0), /Invalid port/);
    assert.throws(() => validateArg({ type: "port" }, 70000), /Invalid port/);
    assert.throws(() => validateArg({ type: "port" }, "abc"), /Invalid port/);
  });
});

describe("validateArg - boolean", () => {
  it("accepts true/false strings", () => {
    assert.equal(validateArg({ type: "boolean" }, "true"), true);
    assert.equal(validateArg({ type: "boolean" }, "false"), false);
    assert.equal(validateArg({ type: "boolean" }, true), true);
  });

  it("rejects other values", () => {
    assert.throws(() => validateArg({ type: "boolean" }, "yes"), /Boolean must be/);
    assert.throws(() => validateArg({ type: "boolean" }, 1), /Boolean must be/);
  });
});

describe("validateArg - enum", () => {
  const def = { type: "enum", allowed: ["ping", "service", "syn"] };

  it("accepts allowed values", () => {
    assert.equal(validateArg(def, "ping"), "ping");
    assert.equal(validateArg(def, "syn"), "syn");
  });

  it("rejects disallowed values", () => {
    assert.throws(() => validateArg(def, "aggressive"), /not in allowed/);
  });
});

describe("validateArg - scope_target", () => {
  it("accepts valid targets", () => {
    assert.equal(validateArg({ type: "scope_target" }, "10.0.1.1"), "10.0.1.1");
    assert.equal(validateArg({ type: "scope_target" }, "example.com"), "example.com");
    assert.equal(
      validateArg({ type: "scope_target" }, "10.0.1.0/24"),
      "10.0.1.0/24"
    );
  });

  it("rejects wildcards", () => {
    assert.throws(() => validateArg({ type: "scope_target" }, "*.example.com"), /Wildcard/);
  });

  it("rejects injection", () => {
    assert.throws(() => validateArg({ type: "scope_target" }, "10.0.1.1;whoami"), /Injection/);
  });

  it("rejects leading or trailing whitespace", () => {
    assert.throws(
      () => validateArg({ type: "scope_target" }, "example.com "),
      /whitespace/
    );
    assert.throws(
      () => validateArg({ type: "scope_target" }, " example.com"),
      /whitespace/
    );
    assert.throws(
      () => validateArg({ type: "scope_target" }, "\texample.com"),
      /whitespace/
    );
  });

  it("rejects values exceeding the 253-char RFC 1035 limit", () => {
    assert.throws(
      () => validateArg({ type: "scope_target" }, "a".repeat(254)),
      /253/
    );
    // 4096-char buffer-pathological payload from cross-impl harness.
    assert.throws(
      () => validateArg({ type: "scope_target" }, "a".repeat(4096)),
      /253|exceeds/
    );
  });

  it("rejects empty input", () => {
    assert.throws(
      () => validateArg({ type: "scope_target" }, ""),
      /empty/
    );
  });
});

describe("validateArg - url", () => {
  it("accepts valid URLs", () => {
    assert.equal(
      validateArg({ type: "url" }, "https://example.com"),
      "https://example.com"
    );
  });

  it("enforces scheme restrictions", () => {
    const def = { type: "url", schemes: ["https"] };
    assert.equal(validateArg(def, "https://example.com"), "https://example.com");
    assert.throws(() => validateArg(def, "http://example.com"), /scheme.*not in allowed/);
  });

  it("rejects invalid URLs", () => {
    assert.throws(() => validateArg({ type: "url" }, "not-a-url"), /Invalid URL/);
  });
});

describe("validateArg - path", () => {
  it("accepts valid relative paths", () => {
    assert.equal(validateArg({ type: "path" }, "tmp/wordlist.txt"), "tmp/wordlist.txt");
  });

  it("rejects absolute paths", () => {
    assert.throws(() => validateArg({ type: "path" }, "/tmp/wordlist.txt"), /must be relative/);
  });

  it("rejects path traversal", () => {
    assert.throws(() => validateArg({ type: "path" }, "etc/../shadow"), /traversal/);
  });

  it("rejects injection", () => {
    assert.throws(() => validateArg({ type: "path" }, "tmp/$(whoami)"), /Injection/);
  });
});

describe("validateArg - ip_address", () => {
  it("accepts valid IPv4", () => {
    assert.equal(validateArg({ type: "ip_address" }, "192.168.1.1"), "192.168.1.1");
  });

  it("accepts valid IPv6", () => {
    assert.equal(validateArg({ type: "ip_address" }, "::1"), "::1");
    assert.equal(validateArg({ type: "ip_address" }, "fe80::1"), "fe80::1");
  });

  it("rejects invalid IPs", () => {
    assert.throws(() => validateArg({ type: "ip_address" }, "999.999.999.999"), /Invalid IPv4/);
    assert.throws(() => validateArg({ type: "ip_address" }, "not-an-ip"), /Invalid IP/);
  });
});

describe("validateArg - cidr", () => {
  it("accepts valid CIDR", () => {
    assert.equal(validateArg({ type: "cidr" }, "10.0.0.0/24"), "10.0.0.0/24");
    assert.equal(validateArg({ type: "cidr" }, "192.168.1.0/16"), "192.168.1.0/16");
  });

  it("rejects invalid CIDR", () => {
    assert.throws(() => validateArg({ type: "cidr" }, "10.0.0.0"), /Invalid CIDR/);
    assert.throws(() => validateArg({ type: "cidr" }, "10.0.0.0/33"), /Invalid CIDR prefix/);
  });
});

describe("validateArg - number (float)", () => {
  it("accepts valid floats", () => {
    assert.equal(validateArg({ type: "number" }, "0.5"), 0.5);
    assert.equal(validateArg({ type: "number" }, "-3.14"), -3.14);
  });

  it("rejects NaN and infinity", () => {
    assert.throws(() => validateArg({ type: "number" }, "NaN"), /finite/);
    assert.throws(() => validateArg({ type: "number" }, "Infinity"), /finite/);
  });

  it("respects min_float / max_float", () => {
    const def = { type: "number", min_float: 0, max_float: 1 };
    assert.equal(validateArg(def, "0.5"), 0.5);
    assert.throws(() => validateArg(def, "-0.1"), /below minimum/);
    assert.throws(() => validateArg(def, "1.5"), /exceeds maximum/);
  });

  it("falls back to int min/max bounds", () => {
    const def = { type: "number", min: 1, max: 10 };
    assert.equal(validateArg(def, "5.5"), 5.5);
    assert.throws(() => validateArg(def, "0.5"), /below minimum/);
  });

  it("clamps when clamp=true", () => {
    const def = { type: "number", min_float: 0, max_float: 1, clamp: true };
    assert.equal(validateArg(def, "-5"), 0);
    assert.equal(validateArg(def, "5"), 1);
  });
});

describe("validateArg - scope_target hardening", () => {
  it("rejects punycode (xn--) labels", () => {
    assert.throws(
      () => validateArg({ type: "scope_target" }, "xn--example-9c.com"),
      /punycode/
    );
    assert.throws(
      () => validateArg({ type: "scope_target" }, "sub.XN--example-9c.com"),
      /punycode/
    );
  });

  it("rejects non-ASCII (homoglyph IDN)", () => {
    assert.throws(
      () => validateArg({ type: "scope_target" }, "exаmple.com"),
      /ASCII/
    );
  });

  it("surfaces specific traversal failure message", () => {
    assert.throws(
      () => validateArg({ type: "scope_target" }, "../../etc/passwd"),
      /traversal/
    );
  });

  it("surfaces specific slash failure message", () => {
    assert.throws(
      () => validateArg({ type: "scope_target" }, "etc/passwd"),
      /'\/'/
    );
  });
});
