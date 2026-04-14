---
title: LLM Integration
description: Wiring ToolClad manifests into LLM tool-calling loops (Anthropic, OpenAI, OpenRouter)
---

# LLM Integration

ToolClad manifests are a natural fit for LLM tool calling. Each manifest already declares a name, a description, and a JSON Schema for its parameters — exactly the shape every major LLM tool-calling API expects. This guide shows how to wire a set of manifests into a multi-turn tool-calling loop (Anthropic native `tool_use`, or OpenAI / OpenRouter function calling) without depending on any specific runtime.

The pattern is the same one the Symbiont runtime uses to execute agents on-demand from webhook requests; it generalizes to any application that wants to expose ToolClad tools to an LLM.

## The loop

At a high level:

1. Load manifests from `tools/` and derive a tool-definition list for the model.
2. Send the user prompt (and the tool list) to the LLM.
3. The LLM responds with zero or more **tool-use** calls, or a final text answer.
4. For each tool-use call, validate and execute via `executor::execute`.
5. Feed the output back as a **tool-result** message and loop.
6. Stop when the LLM produces a final text response or you hit an iteration cap.

```
            ┌──────────────┐
 prompt ───▶│     LLM      │──── tool_use ──▶ execute ──▶ tool_result
            │              │◀─────────────────┴───────────────┘
            └──────────────┘
                   │ end_turn
                   ▼
                 final text
```

## Tool-definition format

Every ToolClad manifest produces a canonical triple:

| Field | Source | Description |
|-------|--------|-------------|
| `name` | `[tool.name]` | Unique tool identifier |
| `description` | `[tool.description]` | Human-readable explanation for the LLM |
| `parameters` | `[args]` → JSON Schema | Typed parameter schema |

This maps cleanly onto both major tool-calling conventions:

### Anthropic (native `tool_use`)

Anthropic's Messages API accepts the triple directly, under the field names `name`, `description`, and `input_schema`:

```rust
let tools: Vec<serde_json::Value> = manifests
    .iter()
    .map(|m| serde_json::json!({
        "name":        m.tool.name,
        "description": m.tool.description,
        "input_schema": generate_mcp_schema(m)["inputSchema"],
    }))
    .collect();
```

### OpenAI / OpenRouter (function calling)

OpenAI wraps the same fields under `function`, and uses `parameters` rather than `input_schema`:

```rust
fn to_openai_functions(tools: &[serde_json::Value]) -> Vec<serde_json::Value> {
    tools.iter().map(|t| serde_json::json!({
        "type": "function",
        "function": {
            "name":        t["name"],
            "description": t["description"],
            "parameters":  t["input_schema"],
        }
    })).collect()
}
```

## Normalizing responses

Each provider returns tool calls in a different envelope. Normalize them to a single content-block shape early so the rest of your loop is provider-agnostic. A good target is Anthropic's native format: a list of content blocks where each block is either:

- `{"type": "text", "text": "..."}`, or
- `{"type": "tool_use", "id": "...", "name": "...", "input": {...}}`

Convert OpenAI's `choices[0].message` into this shape:

```rust
fn normalize_openai_response(resp: &serde_json::Value) -> serde_json::Value {
    let msg = &resp["choices"][0]["message"];
    let finish = resp["choices"][0]["finish_reason"].as_str().unwrap_or("stop");

    let mut blocks = Vec::new();
    if let Some(text) = msg["content"].as_str() {
        if !text.is_empty() {
            blocks.push(serde_json::json!({"type": "text", "text": text}));
        }
    }
    if let Some(calls) = msg["tool_calls"].as_array() {
        for c in calls {
            let args: serde_json::Value = serde_json::from_str(
                c["function"]["arguments"].as_str().unwrap_or("{}")
            ).unwrap_or_default();
            blocks.push(serde_json::json!({
                "type": "tool_use",
                "id":   c["id"],
                "name": c["function"]["name"],
                "input": args,
            }));
        }
    }

    let stop_reason = match finish {
        "tool_calls" | "function_call" => "tool_use",
        _ => "end_turn",
    };
    serde_json::json!({ "content": blocks, "stop_reason": stop_reason })
}
```

## The tool-calling loop

With normalization in place, the loop body is the same across providers. A minimal implementation:

```rust
use std::sync::Arc;
use std::time::Duration;
use std::collections::{HashMap, HashSet};

async fn run_tool_calling_loop(
    llm: &LlmClient,
    system_prompt: &str,
    user_message: &str,
    manifests: &HashMap<String, Arc<toolclad::Manifest>>,
    tools: &[serde_json::Value],
) -> Result<String, String> {
    const MAX_ITERATIONS: usize = 15;
    const TOOL_TIMEOUT: Duration = Duration::from_secs(120);

    let mut messages = vec![
        serde_json::json!({"role": "user", "content": user_message}),
    ];
    let mut final_text = String::new();

    for _ in 0..MAX_ITERATIONS {
        // 1. Ask the LLM for the next step (normalized envelope)
        let resp = llm.chat_with_tools(system_prompt, &messages, tools).await?;
        let stop_reason = resp["stop_reason"].as_str().unwrap_or("end_turn");
        let blocks = resp["content"].as_array().cloned().unwrap_or_default();

        // 2. Collect text + tool_use blocks from this turn
        let mut tool_calls = Vec::new();
        for b in &blocks {
            match b["type"].as_str() {
                Some("text") => {
                    if let Some(t) = b["text"].as_str() { final_text = t.into() }
                }
                Some("tool_use") => tool_calls.push(b.clone()),
                _ => {}
            }
        }
        if tool_calls.is_empty() || stop_reason == "end_turn" {
            break;
        }

        // 3. Commit the assistant turn before executing tools
        messages.push(serde_json::json!({"role": "assistant", "content": blocks}));

        // 4. Execute tools (with dedup + spawn_blocking + timeout)
        let mut seen = HashSet::new();
        let mut results = Vec::new();
        for call in &tool_calls {
            let id    = call["id"].as_str().unwrap_or("?");
            let name  = call["name"].as_str().unwrap_or("?").to_string();
            let input = call["input"].clone();
            let key   = format!("{name}:{input}");

            let output = if !seen.insert(key) {
                "Duplicate tool call skipped.".to_string()
            } else if let Some(manifest) = manifests.get(&name).cloned() {
                let args: HashMap<String, String> = input
                    .as_object()
                    .map(|o| o.iter()
                        .map(|(k, v)| (k.clone(), v.as_str().map(|s| s.into())
                            .unwrap_or_else(|| v.to_string())))
                        .collect())
                    .unwrap_or_default();

                let handle = tokio::task::spawn_blocking(move || {
                    toolclad::executor::execute(&manifest, &args)
                });
                match tokio::time::timeout(TOOL_TIMEOUT, handle).await {
                    Ok(Ok(Ok(env)))   => serde_json::to_string_pretty(&env)
                                          .unwrap_or_else(|_| env.status.clone()),
                    Ok(Ok(Err(e)))    => format!("tool error: {e}"),
                    Ok(Err(join_err)) => format!("task panicked: {join_err}"),
                    Err(_)            => format!("timed out after {:?}", TOOL_TIMEOUT),
                }
            } else {
                format!("unknown tool '{name}'")
            };

            results.push(serde_json::json!({
                "type": "tool_result",
                "tool_use_id": id,
                "content": output,
            }));
        }

        // 5. Feed results back and loop
        messages.push(serde_json::json!({"role": "user", "content": results}));
    }

    Ok(final_text)
}
```

## Patterns worth keeping

**Iteration cap.** Bound the loop (15 is a reasonable default) so a misbehaving model cannot burn tokens forever. When the cap is hit, return whatever `final_text` you have with a note that the loop terminated by limit.

**Per-tool timeout on the caller side.** The manifest's `timeout_seconds` kills the child process, but spawn, validation, and output parsing happen outside that scope. Wrap the whole `spawn_blocking` in `tokio::time::timeout` — see [Calling `execute` from async code](api-reference.md#calling-execute-from-async-code).

**Deduplicate `(name, input)` within an iteration.** LLMs frequently propose the same call twice in one turn. For idempotent tools this is merely wasteful; for tools with side effects it is a bug. Keep a `HashSet` of `name:canonical_input_json` per iteration and short-circuit duplicates with a synthetic `tool_result`.

**UTF-8 safe previews.** If you include tool output snippets in HTTP responses or logs, truncate on char boundaries — `&s[..500]` panics when byte 500 lands inside a multi-byte codepoint. `EvidenceEnvelope` fields are always valid UTF-8 (ToolClad runs child output through `from_utf8_lossy`), but UTF-8 replacement characters (`U+FFFD`) are 3 bytes, so naive byte slicing is still unsafe:

```rust
fn truncate_utf8(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes { return s; }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) { end -= 1; }
    &s[..end]
}
```

**Resolve manifests once, at startup.** Load and validate every `.clad.toml` at boot, wrap each in `Arc<Manifest>`, and keep them in a `HashMap<String, Arc<Manifest>>` keyed by tool name. Clone the `Arc` into each blocking task — never re-parse manifests per LLM call.

**Log everything, but not the output.** ORGA-style logs (`provider`, `model`, `tools`, `iteration`, `tool`, `latency`) are high-signal and cheap. Full tool output in logs is a footgun — it may contain scope-violating URLs, credentials, or simply be huge. Log a truncated preview and write the full envelope to your evidence store.

## See also

- [API Reference — `executor::execute`](api-reference.md#executorexecutemanifest-args---resultevidenceenvelope) — the synchronous primitive this recipe wraps.
- [Output & Evidence](output-evidence.md) — the `EvidenceEnvelope` shape your tool-result messages carry.
- [Security Model](security-model.md) — argument validation, scope enforcement, and evidence chaining all still apply inside the loop.
- [Symbiont Integration](symbiont-integration.md) — a concrete runtime that uses this pattern end-to-end.
