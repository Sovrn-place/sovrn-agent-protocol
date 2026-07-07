# Security Model

The reference implementation MUST address the six-class agent-identity adversarial taxonomy (a design-level mandate, not an integrator suggestion). The table maps each class to its mitigation in code.

| # | Class | Mitigation | Where |
|---|---|---|---|
| 1 | Identity spoofing via key substitution | DID resolution is hard-fail with NO cross-method fallback (a `did:sovrn` failure never downgrades to `did:web` or anything else); every `proof[]` entry is verified against key material resolved from the DID document | `src/did/resolve.ts`, `src/engine/procedure-a.ts` (A1/A2) |
| 2 | Token replay across delegation chains | `nbf`/`exp` time bounds on every link; RFC 8707 audience binding pins OAuth tokens to THIS server; UCAN capabilities pin their terminal `aud` to THIS server's DID | `src/engine/procedure-b.ts` (B4), `src/auth/oauth.ts`, `src/auth/ucan-gate.ts` |
| 3 | Scope widening | The chain-validation invariant: attenuation (each link ⊆ its parent), invoker = terminal `aud`, resource-identifier match (`att.with` vs the targeted resource) — the confused-deputy rule, enforced | `src/engine/checks.ts` (`chainInvariantStatus`), B5/B6 |
| 4 | Token forgery against unsigned/weak delegations | Bearer-only and unsigned delegations are rejected (a decoded object with no signature bytes fails closed); every UCAN link's signature is verified; a credential-touching tool call is refused without a valid UCAN chain even with a valid OAuth session | `src/crypto/ucan.ts`, `src/auth/ucan-gate.ts` |
| 5 | Audit evasion via delegation without context recording | Every Procedure A/B run emits a verdict + cited-rule step trace, returned with the result. The server is stateless BY DESIGN; the durable system-of-record is the agent-memory-board (separate repository). Stated honestly as a seam, not a hole | `src/engine/trace.ts` |
| 6 | Credential exfiltration via the runtime | stdio process isolation; HTTP: Origin validation, DNS-rebinding protection with explicit allowed hosts, 127.0.0.1 bind default, OAuth strictly before the transport, no credential pass-through to intermediaries; the verifier holds NO holder key (key-optional) and never logs secrets | `src/transports/http.ts`, `src/server.ts` |

## The conjunction, stated once

OAuth 2.1 (HTTP session) and the UCAN capability gate are a **conjunction**, not alternatives. The OAuth layer authenticates the session to the resource; the UCAN capability authorizes the specific action. A valid session with no capability is refused for credential-touching calls. This is the structural fix for the confused deputy — do not weaken it.

`SOVRN_MCP_UCAN_GATE=optional` exists for local, verifier-only evaluation (it admits `verify_presentation` / `validate_delegation_chain` without a capability, with a logged warning; `request_credential` stays enforced). **Never run optional mode in production.**

## Hostile-input hardening

This server is written to be copied. Untrusted input reaches it through tool arguments, DID resolution, and the HTTP transport, so the hostile-input edges are handled explicitly rather than left to the caller:

- **Malformed capability/delegation payloads never crash.** A UCAN whose `att` is not an array, a compact link that decodes to JSON `null`, and a deeply-nested credential body are all handled as a clean DENY/REJECT/VIOLATED, not a thrown exception. Canonicalization is depth-capped, so a nesting bomb cannot overflow the stack.
- **Fail-closed status.** A malformed `statusListIndex` (negative / non-integer) or an undecodable status list is treated as REVOKED — the verifier never silently grants when it cannot confirm active status.
- **Expiry is strict.** A non-numeric `exp`/`nbf` is treated as expired; a token cannot dodge expiry by supplying a string-typed bound.
- **DID resolution is bounded.** `did:web` URLs are built from validated segments (no `..`, no `%2F`-smuggled separators, no empty host); resolution does not follow redirects (anti-SSRF), and both a request timeout and a response-body size cap apply.
- **The HTTP transport caps the request body** (1 MiB) with an idle timeout, and destroys the connection on exceed (413) rather than buffering unbounded.

## Known limits (v0.1.0, documented not hidden)

- B8 (root-principal-still-verified) is injectable and defaults to VERIFIED when no oracle is configured. Integrators gating real invocations MUST inject a real cross-protocol source — see docs/extension-points.md.
- UCAN 1.0-rc.1 DAG-CBOR wire decoding, BBS-2023, and live BitstringStatusList fetching are documented extension points, not implemented surfaces.
- Canonicalization is the JCS-style sorted-key form; full RFC 8785 number-form interop is a tracked follow-up.
- **Root-wildcard capabilities are accepted.** A capability granting `{ "with": "sovrn:*", "can": "*" }` covers any tool (the terminal-audience pin to this server's DID still holds, so it is not a cross-server bypass). Integrators issuing capabilities should attenuate `with`/`can` to the specific tool rather than rely on root wildcards; a stricter default is a tracked follow-up.

## Reporting

Report vulnerabilities privately to the repository maintainers. Do not open public issues for exploitable findings.
