---
title: Security Model
description: Contract enforcement, runtime responsibilities and limits
---

# Security Model

ToolClad constrains a tool invocation to a manifest's declared arguments and operation structure. A contract reduces the interface exposed to an agent. **ToolClad alone does not contain a hostile agent or executable.** OS isolation, policy decisions, approvals, scoped network access and durable audit records require an embedding runtime.

See [Reference Execution and Migration](reference-execution.md) for the implemented behavior and compatibility changes in this branch.

## Trust boundaries

| Boundary | ToolClad reference behavior | Additional runtime responsibility |
|---|---|---|
| Supplied arguments | Declared names, validated values/defaults, required-value checks | Bind values to an authenticated caller and operation |
| Command structure | Trusted manifest, literal argv substitution, no implicit shell | Authenticate the manifest and executable; restrict tool-specific effects |
| Approval and Cedar | Refuse standalone effects when these controls are declared | Evaluate policy and bind approval to the exact prepared operation |
| Scope | Type validation; explicit `scope_check` requires a runtime | Enforce scope at the file/network effect boundary |
| HTTP | Fixed origin, no redirects/proxies, single-pass secret expansion, bounded response | DNS/address enforcement, credential policy, complete wall-clock deadlines |
| Process lifetime | Limited output and original process-group cleanup | Own all descendants, constrain resources, isolate mounts/network/privileges |
| Evidence | Structured results and output hashes | Persist and authenticate receipts; fail closed when required audit storage fails |

A signed manifest can authenticate a contract's author and bytes. Signature verification does not make its operation harmless, approve a particular invocation or prevent the executable from exceeding its declared intent. The reference runners do not perform SchemaPin signature verification before dispatch. Integrations must verify manifests, retain the verified identity and bind execution to that identity.

## Argument and command safety

String validators reject defined sets of shell metacharacters. Exact behavior differs by type and language; an explicitly allowed enum is not a universal metacharacter filter. These checks do not replace argument-boundary preservation.

`exec` arrays preserve each argument. Legacy templates and trusted mapping/conditional fragments are tokenized before inserting values. Inserted data is never split again or recursively interpreted as template syntax. The runner does not add an implicit shell, but a trusted manifest can explicitly select a shell or an interpreter. Such a manifest grants those capabilities.

Literal argv prevents a value from inventing extra argument boundaries. It does not prevent an executable from interpreting a single value as an option, a script, a configuration file or a target. Review the actual executable's semantics and prefer narrow enums and supported option terminators.

The `path` validator checks path syntax. Relative paths can still traverse symlinks, resolve against an unexpected working directory or race with filesystem changes. It does not confine access to a project directory. Use runtime-owned descriptors or mounted workspaces with appropriate OS enforcement.

## Network and secret safety

Reference HTTP runners only allow a fixed manifest-defined origin, do not follow redirects, and ignore proxy environment variables. Secrets are permitted in trusted header/body templates and are resolved in a single pass. Untrusted values containing secret-placeholder syntax cannot request another lookup. Dry runs do not read secret values.

These rules reduce accidental credential forwarding. A trusted endpoint can still echo a credential into a response, and an executable can read accessible host files. Reference output is not universally redacted. Do not treat a hash or envelope as a confidentiality control.

Literal address validation is not a complete egress boundary. DNS resolution, connection-time address changes, internal origins, subprocess networking and browser navigation need independent runtime enforcement. Type acceptance is not project-scope authorization.

## Failure and cleanup

Non-success execution and MCP delegation previews produce nonzero `run` exit codes. Approval/Cedar/scope requirements, callback dispatch, ambiguous backends and unsupported parser scripts refuse standalone execution before effects. A dry run previews a supported invocation without satisfying those runtime requirements.

Output and time limits bound the reference runner's work. Process-group cleanup is best effort and does not contain processes that leave that group. A timeout, output overflow or evidence/parser failure may happen after the tool has already caused an effect. Callers must retain this distinction and apply operation-specific recovery or idempotency controls.

The shared vectors and local CLI E2E matrix check concrete boundary regressions. They do not demonstrate comprehensive containment of an autonomous adversarial agent. A containment assessment must include the embedding runtime, deployed isolation backend, tools, credentials, network/filesystem policy and independent held-out escape tests.
