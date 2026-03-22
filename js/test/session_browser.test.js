import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { writeFileSync, unlinkSync, mkdtempSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { loadManifest } from "../src/manifest.js";

function writeTmp(content) {
  const dir = mkdtempSync(join(tmpdir(), "toolclad-"));
  const path = join(dir, "test.clad.toml");
  writeFileSync(path, content);
  return path;
}

describe("session mode", () => {
  it("parses a session manifest", () => {
    const path = writeTmp(`
[tool]
name = "psql_session"
mode = "session"
description = "PostgreSQL session"

[session]
startup_command = "psql -U user dbname"
ready_pattern = "^dbname=> $"
max_interactions = 50

[session.commands.select]
pattern = "^SELECT .+$"
description = "Run a SELECT query"
risk_tier = "low"

[session.commands.drop]
pattern = "^DROP .+$"
description = "Drop a table"
risk_tier = "high"
human_approval = true

[output]
format = "text"

[output.schema]
type = "object"
`);
    try {
      const m = loadManifest(path);
      assert.equal(m.tool.name, "psql_session");
      assert.equal(m.tool.mode, "session");

      assert.ok(m.session);
      assert.equal(m.session.startup_command, "psql -U user dbname");
      assert.equal(m.session.ready_pattern, "^dbname=> $");
      assert.equal(m.session.max_interactions, 50);

      assert.ok(m.session.commands.select);
      assert.equal(m.session.commands.select.pattern, "^SELECT .+$");
      assert.equal(m.session.commands.select.risk_tier, "low");

      assert.ok(m.session.commands.drop);
      assert.equal(m.session.commands.drop.human_approval, true);
      assert.equal(m.session.commands.drop.risk_tier, "high");

      assert.equal(m.output.format, "text");
      assert.equal(m.output.schema.type, "object");
    } finally {
      unlinkSync(path);
    }
  });
});

describe("browser mode", () => {
  it("parses a browser manifest", () => {
    const path = writeTmp(`
[tool]
name = "browser_session"
mode = "browser"
description = "Browser session"

[browser]
engine = "cdp"
connect = "launch"
extract_mode = "accessibility_tree"

[browser.scope]
allowed_domains = ["*.example.com"]

[browser.commands.navigate]
description = "Navigate to URL"
risk_tier = "medium"

[browser.commands.snapshot]
description = "Get accessibility tree"
risk_tier = "low"

[output]
format = "json"

[output.schema]
type = "object"
`);
    try {
      const m = loadManifest(path);
      assert.equal(m.tool.name, "browser_session");
      assert.equal(m.tool.mode, "browser");

      assert.ok(m.browser);
      assert.equal(m.browser.engine, "cdp");
      assert.equal(m.browser.connect, "launch");
      assert.equal(m.browser.extract_mode, "accessibility_tree");

      assert.ok(m.browser.scope);
      assert.deepEqual(m.browser.scope.allowed_domains, ["*.example.com"]);

      assert.ok(m.browser.commands.navigate);
      assert.equal(m.browser.commands.navigate.risk_tier, "medium");

      assert.ok(m.browser.commands.snapshot);
      assert.equal(m.browser.commands.snapshot.risk_tier, "low");

      assert.equal(m.output.format, "json");
    } finally {
      unlinkSync(path);
    }
  });
});
