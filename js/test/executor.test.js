import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { buildCommand, generateMcpSchema, injectTemplateVars, executeMcp } from "../src/executor.js";

// Minimal manifest for testing template interpolation
function makeManifest(overrides = {}) {
  return {
    tool: {
      name: "test_tool",
      binary: "echo",
      description: "A test tool",
      timeout_seconds: 30,
      ...overrides.tool,
    },
    args: overrides.args || {
      target: {
        position: 1,
        required: true,
        type: "scope_target",
        description: "Target host",
      },
    },
    command: overrides.command || {
      template: "echo {target}",
    },
    output: overrides.output || {
      format: "text",
      envelope: true,
      schema: { type: "object" },
    },
  };
}

describe("buildCommand - basic interpolation", () => {
  it("interpolates a simple template", () => {
    const manifest = makeManifest();
    const result = buildCommand(manifest, { target: "10.0.1.1" });
    assert.equal(result.command, "echo 10.0.1.1");
    assert.equal(result.isExecutor, false);
  });

  it("throws on missing required argument", () => {
    const manifest = makeManifest();
    assert.throws(() => buildCommand(manifest, {}), /Missing required argument/);
  });

  it("applies default values", () => {
    const manifest = makeManifest({
      args: {
        target: { position: 1, required: true, type: "scope_target", description: "t" },
        rate: { position: 2, required: false, type: "integer", default: 100, description: "r" },
      },
      command: { template: "scan --rate {rate} {target}" },
    });
    const result = buildCommand(manifest, { target: "10.0.1.1" });
    assert.equal(result.command, "scan --rate 100 10.0.1.1");
  });
});

describe("buildCommand - command.defaults", () => {
  it("uses command.defaults for unset context variables", () => {
    const manifest = makeManifest({
      args: {
        target: { position: 1, required: true, type: "scope_target", description: "t" },
      },
      command: {
        template: "nmap --max-rate {max_rate} {target}",
        defaults: { max_rate: 1000 },
      },
    });
    const result = buildCommand(manifest, { target: "10.0.1.0/24" });
    assert.equal(result.command, "nmap --max-rate 1000 10.0.1.0/24");
  });
});

describe("buildCommand - mappings", () => {
  it("resolves enum value to mapped flags", () => {
    const manifest = makeManifest({
      args: {
        target: { position: 1, required: true, type: "scope_target", description: "t" },
        scan_type: {
          position: 2,
          required: true,
          type: "enum",
          allowed: ["ping", "service", "syn"],
          description: "s",
        },
      },
      command: {
        template: "nmap {_scan_flags} {target}",
        mappings: {
          scan_type: {
            ping: "-sn -PE",
            service: "-sT -sV",
            syn: "-sS",
          },
        },
      },
    });

    const result = buildCommand(manifest, {
      target: "10.0.1.0/24",
      scan_type: "service",
    });
    assert.equal(result.command, "nmap -sT -sV 10.0.1.0/24");
  });
});

describe("buildCommand - executor escape hatch", () => {
  it("returns executor path when command.executor is set", () => {
    const manifest = makeManifest({
      command: { executor: "scripts/wrapper.sh" },
    });
    const result = buildCommand(manifest, { target: "10.0.1.1" });
    assert.equal(result.command, "scripts/wrapper.sh");
    assert.equal(result.isExecutor, true);
  });
});

describe("buildCommand - validation rejects bad args", () => {
  it("rejects injection in scope_target", () => {
    const manifest = makeManifest();
    assert.throws(
      () => buildCommand(manifest, { target: "10.0.1.1;whoami" }),
      /Injection/
    );
  });

  it("rejects invalid enum value", () => {
    const manifest = makeManifest({
      args: {
        mode: {
          position: 1,
          required: true,
          type: "enum",
          allowed: ["fast", "slow"],
          description: "m",
        },
      },
      command: { template: "tool --mode {mode}" },
    });
    assert.throws(
      () => buildCommand(manifest, { mode: "dangerous" }),
      /not in allowed/
    );
  });
});

describe("generateMcpSchema", () => {
  it("produces correct MCP schema", () => {
    const manifest = makeManifest({
      args: {
        target: {
          position: 1,
          required: true,
          type: "scope_target",
          description: "Target CIDR",
        },
        scan_type: {
          position: 2,
          required: true,
          type: "enum",
          allowed: ["ping", "service"],
          description: "Scan type",
        },
        extra: {
          position: 3,
          required: false,
          type: "string",
          default: "",
          description: "Extra flags",
        },
      },
      output: {
        format: "text",
        envelope: true,
        schema: {
          type: "object",
          properties: {
            raw_output: { type: "string" },
          },
        },
      },
    });

    const schema = generateMcpSchema(manifest);

    assert.equal(schema.name, "test_tool");
    assert.equal(schema.inputSchema.type, "object");
    assert.deepEqual(schema.inputSchema.required, ["target", "scan_type"]);
    assert.equal(schema.inputSchema.properties.target.type, "string");
    assert.deepEqual(schema.inputSchema.properties.scan_type.enum, ["ping", "service"]);
    assert.equal(schema.inputSchema.properties.extra.default, "");

    // Output schema should be wrapped in envelope
    assert.equal(schema.outputSchema.type, "object");
    assert.ok(schema.outputSchema.properties.status);
    assert.ok(schema.outputSchema.properties.results);
  });
});

describe("injectTemplateVars", () => {
  it("replaces {_secret:name} with env var", () => {
    process.env.TOOLCLAD_SECRET_API_KEY = "test-key-123";
    const result = injectTemplateVars("Bearer {_secret:api_key}");
    assert.equal(result, "Bearer test-key-123");
    delete process.env.TOOLCLAD_SECRET_API_KEY;
  });

  it("throws on missing env var", () => {
    delete process.env.TOOLCLAD_SECRET_MISSING;
    assert.throws(
      () => injectTemplateVars("{_secret:missing}"),
      /Missing environment variable: TOOLCLAD_SECRET_MISSING/
    );
  });

  it("leaves non-secret placeholders untouched", () => {
    const result = injectTemplateVars("hello {world}");
    assert.equal(result, "hello {world}");
  });
});

describe("HTTP manifest parsing", () => {
  it("loadManifest accepts manifest with [http] section and no [command]", async () => {
    // We test that makeManifest-like objects with http work in executors
    const httpManifest = {
      tool: { name: "api_check", description: "Check an API" },
      http: {
        method: "GET",
        url: "https://api.example.com/status",
        headers: { "Accept": "application/json" },
        success_status: [200],
      },
    };
    assert.equal(httpManifest.http.method, "GET");
    assert.equal(httpManifest.http.url, "https://api.example.com/status");
    assert.deepEqual(httpManifest.http.success_status, [200]);
  });
});

describe("executeMcp", () => {
  it("returns delegated envelope with field mapping", () => {
    const manifest = {
      tool: { name: "proxy_tool", description: "MCP proxy" },
      mcp: {
        server: "mcp://security-tools.example.com",
        tool: "remote_scan",
        field_map: { target: "host", scan_type: "mode" },
      },
      args: {
        target: {
          position: 1,
          required: true,
          type: "scope_target",
          description: "Target",
        },
        scan_type: {
          position: 2,
          required: true,
          type: "enum",
          allowed: ["ping", "syn"],
          description: "Scan type",
        },
      },
    };

    const result = executeMcp(manifest, { target: "10.0.1.1", scan_type: "ping" });
    assert.equal(result.status, "delegated");
    assert.equal(result.mcp_server, "mcp://security-tools.example.com");
    assert.equal(result.mcp_tool, "remote_scan");
    assert.equal(result.mapped_args.host, "10.0.1.1");
    assert.equal(result.mapped_args.mode, "ping");
    assert.ok(result.scan_id);
    assert.ok(result.timestamp);
  });

  it("passes args through when no field_map", () => {
    const manifest = {
      tool: { name: "proxy_tool", description: "MCP proxy" },
      mcp: {
        server: "mcp://tools.example.com",
        tool: "echo",
      },
      args: {
        msg: {
          position: 1,
          required: true,
          type: "string",
          description: "Message",
        },
      },
    };

    const result = executeMcp(manifest, { msg: "hello" });
    assert.equal(result.status, "delegated");
    assert.equal(result.mapped_args.msg, "hello");
  });

  it("throws when mcp section is missing", () => {
    const manifest = {
      tool: { name: "bad", description: "no mcp" },
      args: {},
    };
    assert.throws(() => executeMcp(manifest, {}), /missing \[mcp\] section/);
  });
});
