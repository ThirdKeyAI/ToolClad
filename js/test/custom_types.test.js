// toolclad.toml discovery, strict custom type loading, and load-time type
// checking of every declared argument type (TC-23).

import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  CUSTOM_TYPES,
  discoverCustomTypes,
  loadCustomTypes,
  loadManifest,
  loadManifestFromString,
  loadManifestWithOptions,
} from "../src/manifest.js";
import { execute } from "../src/executor.js";

const TYPES = `[types.level]
base = "integer"
min = 1
max = 5

[types.ident]
base = "string"
pattern = "[a-z]+"
`;

const manifestWith = (type) => `[tool]
name = "t"
binary = "echo"
description = "d"

[args.a]
position = 1
required = true
type = "${type}"
description = "a"

[command]
exec = ["echo", "{a}"]

[output]
format = "text"
`;

function tree() {
  const root = mkdtempSync(join(tmpdir(), "toolclad-ct-"));
  const sub = join(root, "tools", "deep");
  mkdirSync(sub, { recursive: true });
  return { root, sub };
}

let savedConfig;
beforeEach(() => {
  savedConfig = process.env.TOOLCLAD_CONFIG_FILE;
  delete process.env.TOOLCLAD_CONFIG_FILE;
});
afterEach(() => {
  if (savedConfig === undefined) delete process.env.TOOLCLAD_CONFIG_FILE;
  else process.env.TOOLCLAD_CONFIG_FILE = savedConfig;
});

describe("toolclad.toml discovery", () => {
  it("is found by walking up from the manifest directory", async () => {
    const { root, sub } = tree();
    writeFileSync(join(root, "toolclad.toml"), TYPES);
    const path = join(sub, "t.clad.toml");
    writeFileSync(path, manifestWith("level"));
    const m = loadManifest(path);
    assert.deepEqual(Object.keys(m[CUSTOM_TYPES]).sort(), ["ident", "level"]);
    const ok = await execute(m, { a: "3" }, { dryRun: true });
    assert.deepEqual(ok.argv, ["echo", "3"]);
    await assert.rejects(execute(m, { a: "9" }, { dryRun: true }));
  });

  it("an unknown type with no toolclad.toml is refused at load", () => {
    const { sub } = tree();
    const path = join(sub, "t.clad.toml");
    writeFileSync(path, manifestWith("level"));
    assert.throws(() => loadManifest(path), /unknown type 'level' for argument 'a'/);
  });

  it("TOOLCLAD_CONFIG_FILE wins, and an unreadable path is an error", () => {
    const { root, sub } = tree();
    writeFileSync(join(root, "toolclad.toml"), "");
    const elsewhere = join(root, "other.toml");
    writeFileSync(elsewhere, TYPES);
    const path = join(sub, "t.clad.toml");
    writeFileSync(path, manifestWith("ident"));
    assert.throws(() => loadManifest(path), /unknown type 'ident'/);
    process.env.TOOLCLAD_CONFIG_FILE = elsewhere;
    assert.doesNotThrow(() => loadManifest(path));
    process.env.TOOLCLAD_CONFIG_FILE = join(root, "missing.toml");
    assert.throws(() => loadManifest(path), /cannot read custom type file/);
    assert.throws(() => discoverCustomTypes(sub), /cannot read custom type file/);
  });

  it("the customTypes option overrides discovery", () => {
    const { sub } = tree();
    const path = join(sub, "t.clad.toml");
    writeFileSync(path, manifestWith("level"));
    const m = loadManifestWithOptions(path, { customTypes: { level: { base: "integer" } } });
    assert.equal(m[CUSTOM_TYPES].level.base, "integer");
  });

  it("the string loader discovers from baseDir", () => {
    const { root, sub } = tree();
    writeFileSync(join(root, "toolclad.toml"), TYPES);
    assert.doesNotThrow(() => loadManifestFromString(manifestWith("ident"), { baseDir: sub }));
    const { sub: bare } = tree();
    assert.throws(
      () => loadManifestFromString(manifestWith("ident"), { baseDir: bare }),
      /unknown type 'ident'/
    );
  });
});

describe("toolclad.toml is strict", () => {
  const load = (text) => {
    const { root } = tree();
    const path = join(root, "toolclad.toml");
    writeFileSync(path, text);
    return () => loadCustomTypes(path);
  };

  it("refuses unknown keys at both levels", () => {
    assert.throws(load(`[other]\nx = 1\n`), /unknown key 'other'/);
    assert.throws(load(`[types.x]\nbase = "string"\npatern = "a"\n`), /unknown key 'types\.x\.patern'/);
  });

  it("requires a built-in base and refuses shadowing a built-in", () => {
    assert.throws(load(`[types.x]\npattern = "a"\n`), /missing required 'base'/);
    assert.throws(load(`${TYPES}\n[types.x]\nbase = "level"\n`), /not a built-in type/);
    assert.throws(load(`[types.url]\nbase = "string"\n`), /shadows a built-in type/);
  });

  it("accepts every allowed key", () => {
    const types = load(`[types.x]
base = "number"
min = 1
max = 2
min_float = 0.5
max_float = 1.5

[types.y]
base = "enum"
allowed = ["a", "b"]

[types.z]
base = "string"
pattern = "a+"
`)();
    assert.deepEqual(Object.keys(types).sort(), ["x", "y", "z"]);
  });
});

describe("load-time type checking covers session and browser command args", () => {
  it("refuses an unknown type inside [session.commands.*.args]", () => {
    const text = `[tool]
name = "s"
description = "d"

[session]
startup_command = "psql"
ready_pattern = "^> $"

[session.commands.select]
pattern = "^SELECT .+$"
description = "q"

[session.commands.select.args.table]
type = "tablename"
`;
    const { sub } = tree();
    assert.throws(
      () => loadManifestFromString(text, { baseDir: sub }),
      /unknown type 'tablename' for argument 'table'/
    );
  });

  it("refuses an unknown type inside [browser.commands.*.args]", () => {
    const text = `[tool]
name = "b"
description = "d"

[browser]
engine = "cdp"

[browser.commands.navigate]
description = "go"

[browser.commands.navigate.args.where]
type = "location"
`;
    const { sub } = tree();
    assert.throws(
      () => loadManifestFromString(text, { baseDir: sub }),
      /unknown type 'location' for argument 'where'/
    );
  });
});
