# SchemaPin v1.4 Features in ToolClad

> **Status:** SchemaPin v1.4-alpha shipped (2026-04-30 / 2026-05-01) across Rust, Python, JavaScript, and Go. ToolClad signs `.clad.toml` manifests with SchemaPin and inherits these features at the signing-time and verification-time boundaries — no ToolClad code changes required.

A `.clad.toml` is a complete behavioral contract for a tool: typed parameters, validation rules, command template, output schema, risk tier, Cedar mappings. A signed `.clad.toml` is an authenticated behavioral contract — and SchemaPin v1.4 adds three additive optional mechanisms that harden that signature against compromise, drift, and substitution. This page documents how each one applies to ToolClad publishers and runtimes.

The wire format and per-language APIs live in the canonical SchemaPin docs:

- [Signature expiration](https://docs.schemapin.org/signature-expiration/) — `expires_at`
- [Schema version binding](https://docs.schemapin.org/schema-version-binding/) — `schema_version` + `previous_hash`
- [DNS TXT cross-verification](https://docs.schemapin.org/dns-txt/) — `_schemapin.{domain}` TXT records

This page is the ToolClad-specific operator's view.

---

## At a glance

| Feature | What ToolClad publishers do | What runtimes verify |
|---------|----------------------------|----------------------|
| `expires_at` | Sign with `--expires-in 6mo` (or your renewal cadence). | Treat `expired = true` as a policy signal (refuse high-risk tools, prompt on medium-risk). |
| `schema_version` | Pass the manifest's `[tool] version` (semver) as `--schema-version`. | Optionally enforce monotonic version progression (refuse downgrades). |
| `previous_hash` | Set to the prior signed version's `skill_hash` (chains releases). | Maintain a per-tool `latest_known_hash` next to the TOFU pin. Mismatch → prompt the operator. |
| DNS TXT (`_schemapin.{vendor-domain}`) | Publish the TXT record alongside `.well-known/schemapin.json`. | Fetch the TXT and require it to match the discovery key fingerprint. Mismatch is a hard fail. |

All four are additive optional. SchemaPin v1.3 verifiers ignore them; v1.4 verifiers handle both. Adopt at your own pace.

---

## 1. Signature expiration (`expires_at`)

A `.clad.toml` from 2024 signing a binary that has had three CVEs since is cryptographically valid but operationally stale. There's no forcing function for vendors to re-sign after a security review.

### Publisher

```bash
schemapin-sign tools/nmap_scan.clad.toml --expires-in 6mo
```

Pick a TTL that matches your release cadence:

- Tools with frequent updates (weekly): `--expires-in 90d`
- Stable tools (monthly): `--expires-in 6mo`
- Long-lived utilities (rare changes): `--expires-in 1y`

### Runtime

The verification result gains two fields:

- `expired: bool` — true when the current time is past `expires_at`. Cryptographic validity is unaffected (`valid` stays true).
- `expires_at: string` — RFC 3339 timestamp mirrored from the signature.

Example policy at the ToolClad runtime layer:

| `risk_tier` | `expired = true` action |
|-------------|------------------------|
| `low` | Log a warning. Continue. |
| `medium` | Prompt the operator (similar to TOFU key rotation). |
| `high` | Refuse to register the tool. |

Pair with the `signature_expired` warning emitted on the result to surface in evidence envelopes.

---

## 2. Schema version binding (`schema_version` + `previous_hash`)

A `.clad.toml` already has a `[tool] version = "1.0.0"` field. SchemaPin v1.4 lets that semver flow into the signature so verifiers can:

- Reason about which version they're loading (`schema_version`)
- Fail on unauthorized substitutions where an attacker swaps a tampered manifest under the same name (`previous_hash` chain)

### Publisher

For the **first** signed release of a tool:

```bash
TOOL_VERSION=$(awk -F\" '/^version[[:space:]]*=/ {print $2; exit}' tools/nmap_scan.clad.toml)
schemapin-sign tools/nmap_scan.clad.toml --schema-version "$TOOL_VERSION"
```

For **subsequent** releases — pass the prior signature's `skill_hash` so verifiers can confirm lineage:

```bash
PREV_HASH=$(jq -r '.skill_hash' tools/nmap_scan.clad.toml.sig.prior)
TOOL_VERSION=$(awk -F\" '/^version[[:space:]]*=/ {print $2; exit}' tools/nmap_scan.clad.toml)
schemapin-sign tools/nmap_scan.clad.toml \
    --schema-version "$TOOL_VERSION" \
    --previous-hash "$PREV_HASH"
```

Recommended workflow:

1. After signing v_n, archive the resulting sig file as `*.sig.prior` in your release pipeline.
2. When signing v_{n+1}, read `skill_hash` from the archived prior sig.
3. Verifiers can then enforce the chain at load time.

### Runtime

Verification result gains:

- `schema_version: string` — the version this manifest claims to be.
- `previous_hash: string` — the hash this manifest claims to descend from.

Use the per-language `verify_chain(current, previous)` helper to confirm:

```rust
// Rust runtime example
use schemapin::skill::{verify_chain, ChainError};

// Both `current` and `previous` must already be cryptographically verified
// independently (verify_chain is a pure-metadata check).
match verify_chain(&current_sig, &previous_sig) {
    Ok(()) => log::info!("manifest {} succeeds {}",
                         current_sig.schema_version.as_deref().unwrap_or("?"),
                         previous_sig.schema_version.as_deref().unwrap_or("?")),
    Err(ChainError::NoPreviousHash) => {
        // First signed release of this tool, OR an attacker has stripped the field.
        // Prompt the operator if you previously saw a chained signature for this tool.
    }
    Err(ChainError::Mismatch { expected, got }) => {
        // The current signature claims to descend from a hash you don't recognize.
        // Likely an unauthorized substitution; refuse to register.
    }
}
```

Recommended runtime state: a per-tool `latest_known_hash` map persisted alongside the TOFU pin store. Treat `previous_hash` mismatch like a TOFU key rotation — refuse silently rolling forward; prompt instead.

This also pairs cleanly with `[tool] version` policy: refuse downgrades by comparing `schema_version` against the prior known version.

---

## 3. DNS TXT cross-verification

The `.well-known/schemapin.json` discovery document lives on the vendor's HTTPS origin. A vendor whose TLS account is compromised — or whose CDN cache is poisoned, or who fell victim to ACME ownership-validation bypass — could serve a forged discovery doc with an attacker's key. TOFU pinning catches the *next* time this happens, but doesn't help on the first encounter.

Adding a `_schemapin.{vendor-domain}` TXT record gives a second-channel cross-check. DNS is administered through a separate credential chain (registrar, DNS provider, optionally DNSSEC). Compromising one channel doesn't automatically give the attacker the other.

### Publisher

```bash
# Compute fingerprint of your published key
FP=$(openssl pkey -pubin -in pubkey.pem -outform DER \
  | openssl dgst -sha256 -hex \
  | awk '{print "sha256:" $2}')

# Publish via your DNS provider (TTL 3600 is conventional)
echo "_schemapin.acme.dev. 3600 IN TXT \"v=schemapin1; kid=acme-2026-04; fp=$FP\""
```

### Runtime

For ToolClad runtimes (e.g. Symbiont) that adopt the cross-check:

```rust
// Rust runtime example
use schemapin::dns::{fetch_dns_txt, parse_txt_record};
use schemapin::skill::verify_skill_offline_with_dns;

// `dns` Cargo feature must be enabled to use the resolver
let txt = fetch_dns_txt("acme.dev").await?;

let result = verify_skill_offline_with_dns(
    &manifest_dir, &discovery, None, revocation.as_ref(),
    Some(&mut pin_store), Some("nmap_scan"),
    txt.as_ref(),
);
```

Treatment when the TXT record is missing depends on policy:

- **Lenient** (typical for low-risk tools): treat absent TXT as no-op — verification proceeds via discovery + TOFU only.
- **Strict** (high-risk tools, or vendors known to publish TXT): treat absent TXT as a verification failure. This matches the "publisher who opted in has signaled DNS is part of their trust chain" posture.

A mismatch (TXT present but `fp=` doesn't match the discovery key) is always a hard fail — `DOMAIN_MISMATCH`.

---

## Combined recipe: production-grade signing

A vendor publishing a stable tool should run:

```bash
#!/usr/bin/env bash
set -euo pipefail

MANIFEST="tools/nmap_scan.clad.toml"
PRIOR_SIG="${MANIFEST}.sig.prior"

TOOL_VERSION=$(awk -F\" '/^version[[:space:]]*=/ {print $2; exit}' "$MANIFEST")

ARGS=(
    --expires-in 6mo
    --schema-version "$TOOL_VERSION"
)

if [[ -f "$PRIOR_SIG" ]]; then
    PREV_HASH=$(jq -r '.skill_hash' "$PRIOR_SIG")
    ARGS+=(--previous-hash "$PREV_HASH")
fi

schemapin-sign "$MANIFEST" "${ARGS[@]}"

# Archive the new sig as the "prior" for the next release
cp "${MANIFEST}.sig" "$PRIOR_SIG"
```

And separately, in the vendor's DNS provider:

```
_schemapin.acme.dev.  3600  IN  TXT  "v=schemapin1; kid=acme-2026-04; fp=sha256:<published-fingerprint>"
```

The result: every published `.clad.toml` carries a TTL, a version tag, a chain back to its predecessor, and a DNS-anchored second channel — without changing a single line of the manifest itself.

---

## Backward compatibility

| Verifier ↓ / Signer → | v1.3 sig | v1.4 sig (no opts) | v1.4 sig (TTL + lineage) | v1.4 sig + DNS TXT |
|------------------------|----------|---------------------|--------------------------|---------------------|
| **v1.3 verifier** | works | works (fields ignored) | works (fields ignored) | works (DNS check skipped) |
| **v1.4 verifier (no DNS)** | works | works (no metadata) | works (metadata surfaced; chain check opt-in) | works (DNS check skipped) |
| **v1.4 verifier with DNS** | works | works | works | works (mismatch → DOMAIN_MISMATCH) |

There is no situation where bumping the signing or verification side to v1.4 breaks an existing deployment.

---

## See also

- [Security model](security-model.md) — overall threat model and Cedar / scope enforcement
- [Manifest format](manifest-format.md) — `[tool] version` semver and other manifest fields
- SchemaPin canonical docs: [signature expiration](https://docs.schemapin.org/signature-expiration/), [schema version binding](https://docs.schemapin.org/schema-version-binding/), [DNS TXT cross-verification](https://docs.schemapin.org/dns-txt/)
