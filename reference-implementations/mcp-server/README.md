# Sovrn Agent Protocol — MCP Server Reference Implementation

A **stateless, verifier-only, key-optional** MCP server implementing Layers 0–2 of the Sovrn Agent Protocol (discovery, credentials, delegation) over MCP transport. Built from the published design; Apache-2.0.

This is the **hardened verifier pattern**: verifiers and zone authorities adopt it instead of rolling their own against the MCP attack surface (the single largest documented attack surface in the 2025–2026 agent-security literature). It addresses the six-class agent-identity adversarial taxonomy — see [SECURITY.md](./SECURITY.md).

## Reference vs managed (the firewall)

| | This reference implementation | A managed/operated server |
|---|---|---|
| State | Stateless verifier — no persisted agent state | Account-scoped state |
| Keys | Key-optional — a verifier holds no holder signing key | Server-held signing keys |
| KYC / issuance | None — `request_credential` is a thin handoff | Live issuance backends |
| Presentation | **Verifies** presentations (Procedure A) | May also construct + sign them |

Holder-side presentation construction, live issuance, and reputation tooling (Layer 3) are **out of scope** — see [docs/extension-points.md](./docs/extension-points.md).

## Surface

**Tools (3):**
- `verify_presentation` — resolution algorithm **Procedure A** (presentation-time): A1 resolve DID (hard-fail, no fallback) → A2 verify every `proof[]` entry → A3 status + authority key generation → A5 cross-layer revocation walk → A6 issuer-trusted-list + Play/Gov seam → graded signals → verdict.
- `validate_delegation_chain` — resolution algorithm **Procedure B** (invocation-time): DID → every link signature → time bounds → chain-validation invariant (sub→iss line, invoker = terminal aud, attenuation) → resource-identifier match → revocation (cross-layer walk, UCAN blocklist, VC status bit, key generation) → root-principal check → verdict.
- `request_credential` — thin issuance handoff. No KYC, no issuance here.

Every verdict carries the **cited rule** on rejection/denial plus a full step **trace** (the audit-evasion mitigation).

**Resources (2, public surface only):**
- `sovrn-agent-protocol://credential-metadata/{credentialType}` — schema/context/envelope metadata for credential discovery.
- `sovrn-agent-protocol://zone-federation-map` — the public zone list. No Federation trust logic, no PII, no agent state.

## Quick start

Requires Node >= 20. From this directory:

```bash
npm install

# stdio (Claude Desktop / Claude Code / Cursor)
npm run start:stdio

# streamable HTTP (binds 127.0.0.1 by default)
SOVRN_MCP_JWKS_URL=https://auth.example/jwks \
SOVRN_MCP_OAUTH_ISSUER=https://auth.example \
SOVRN_MCP_SERVER_DID=did:sovrn:agent:your-server \
npm run start:http
```

Client configs and a curl walkthrough: [examples/](./examples/).

## Auth model (three layers, outermost first)

1. **OAuth 2.1 + RFC 8707 audience binding — HTTP only.** Tokens are validated against the authorization server's JWKS and MUST be bound to this server's canonical resource URI. RFC 9728 metadata is served at `/.well-known/oauth-protected-resource`. OAuth is **N/A on stdio** by design: the client launched the process and shares the local trust boundary.
2. **MCP transport hardening.** DNS-rebinding protection with explicit allowed hosts, Origin allow-list, localhost bind default, stateless per-request transport.
3. **UCAN capability gate — BOTH transports, per tool call.** A credential-touching tool call is **refused without a valid UCAN chain even when the OAuth session is valid**. The per-action capability is the structural confused-deputy fix; an OAuth session is not a substitute. Capabilities are UCAN 0.10 compact JWTs whose terminal audience is this server's DID (`SOVRN_MCP_SERVER_DID`) and whose attenuation covers `mcp/<toolName>` on `sovrn:mcp:server`.

## Configuration

| Env (flag) | Purpose | Default |
|---|---|---|
| `SOVRN_MCP_TRANSPORT` (`--transport`) | `stdio` \| `http` | `stdio` |
| `SOVRN_MCP_PORT` (`--port`) / `SOVRN_MCP_BIND` (`--bind`) | HTTP port / bind address | `3900` / `127.0.0.1` |
| `SOVRN_MCP_AUDIENCE` | RFC 8707 canonical resource URI | `http://<bind>:<port>/mcp` |
| `SOVRN_MCP_JWKS_URL` / `SOVRN_MCP_OAUTH_ISSUER` | Authorization server JWKS / issuer | — (HTTP 401s without) |
| `SOVRN_MCP_SERVER_DID` | This server's DID (UCAN terminal audience) | — |
| `SOVRN_MCP_REGISTRY_URL` | `did:sovrn` resolution endpoint | — (did:sovrn unresolvable without) |
| `SOVRN_MCP_TRUSTED_ISSUERS` | Issuer trusted list (comma-separated zone DIDs) | empty |
| `SOVRN_MCP_STATIC_DID_DOCS` (`--static-did-docs`) | Local DID-document trust store (JSON file) | — |
| `SOVRN_MCP_ZONE_MAP` (`--zone-map`) | Zone federation map override (JSON file) | bundled sample |
| `SOVRN_MCP_UCAN_GATE` (`--ucan-gate`) | `enforce` \| `optional` (see SECURITY.md) | `enforce` |
| `SOVRN_MCP_EPOCH_OVERLAP_SECONDS` | Reputation epoch overlap window | `0` |

## Conformance

The engine passes the protocol's frozen 40-bundle conformance suite — 100% of the MUST set with **exact cited rules**, plus a differential run against the suite's deterministic mock verifier:

```bash
npm run conformance          # 40/40 + differential
npm test                     # unit tests: real crypto vectors (ed25519 SD-JWT-VC, signed UCAN chains, Data Integrity)
npm run typecheck            # engine + server
npm run typecheck:conformance  # + compile-time parity pins against the frozen Verifier contract
```

Architecture note: the engine is built around a `CheckProviders` dependency-injection seam. Production wiring uses real crypto/DID/status providers; the conformance run injects fixture-derived providers so the suite exercises the real orchestration (ordering, short-circuiting, verdict assembly, rule citation). Real crypto is proven by the unit tests on genuinely signed vectors, and `tests/provider-parity.test.ts` pins production provider outcomes to the adapter's shapes.

**Typed deviation:** the frozen harness `Verifier` interface is synchronous (authored for a deterministic mock); a real verifier resolves DIDs and status lists over the network, so this engine is async (`Promise<Verdict>`). `conformance/contract-parity.ts` pins the Verdict/CitedRule types to the frozen contract at compile time.

## Layout

```
src/engine/       Procedure A/B orchestration, checks, rules (single source of cited rules), trace
src/providers/    Production CheckProviders, BitstringStatusList
src/did/          Layer 0 resolution: did:sovrn (registry) + did:web, hard-fail, no fallback
src/crypto/       Data Integrity (eddsa-jcs-2022), SD-JWT-VC, UCAN 0.10 JWT, JCS, key material
src/auth/         OAuth 2.1 resource-server + the UCAN conjunction gate
src/tools/        The 3 MCP tools (SDK-agnostic definitions)
src/resources/    The 2 public-surface resources
src/server.ts     MCP SDK wiring (the only SDK importer, with transports/)
src/transports/   stdio + streamable HTTP (raw node:http, hardened)
conformance/      Runner + fixture adapter + contract parity pins (dev-only)
tests/            Unit tests with genuinely signed vectors
```

The MCP SDK is pinned `>=1.24 <2` (1.24.0 turns DNS-rebinding protection on by default; v2 is a breaking rewrite). SDK imports are confined to `src/server.ts` + `src/transports/` so a future migration is localized.

## License

Apache-2.0.
