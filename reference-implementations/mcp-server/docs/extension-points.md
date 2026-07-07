# Extension Points (v0.1.0)

The floor-vs-extension split is part of the design of record. FLOOR surfaces are implemented for real in this reference; EXTENSION surfaces are documented seams an integrator (or a later version) fills. Nothing here is silently stubbed — every extension point is named, typed, and injectable.

| Surface | v0.1.0 status | Seam |
|---|---|---|
| SD-JWT-VC signature verification | **FLOOR — real** | `src/crypto/sd-jwt.ts` (issuer key via DID resolution) |
| `did:sovrn` / `did:web` resolution | **FLOOR — real** (hard-fail, no fallback) | `src/did/resolve.ts` |
| Procedure A / B ordering | **FLOOR — real** (the ordering is the algorithm's contribution) | `src/engine/procedure-{a,b}.ts` |
| Six-class adversarial mitigations | **FLOOR — real** | SECURITY.md table |
| Data Integrity eddsa-jcs-2022 | **FLOOR — real** (JCS-style canonical form; RFC 8785 number-form interop tracked) | `src/crypto/data-integrity.ts` |
| UCAN 0.10 JWT wire verification | **FLOOR — real** (accepted input) | `src/crypto/ucan.ts` |
| UCAN 1.0-rc.1 DAG-CBOR wire decode | **EXTENSION** — the normative wire; the conformance fixture for it ships xfail (no schema artifact yet) | `decodeDagCborUcan()` throws with a documented message; replace with a DAG-CBOR decoder and CID-based token ids |
| BBS-2023 cryptosuite | **EXTENSION** — the declared promotion target | Add a suite branch in `src/crypto/data-integrity.ts`; the engine is suite-agnostic (providers return outcomes) |
| Live BitstringStatusList fetch | **EXTENSION** — the decoder is real; the SOURCE is injectable | Implement `CredentialStatusSource` (`src/providers/status.ts`) with an HTTPS fetch + verification of the status-list credential itself |
| B8 cross-protocol root-principal fetch | **EXTENSION** — impl-defined at v0.1.0; oracle-injected for conformance | `ProductionProviderConfig.rootPrincipalOracle`. Defaults to VERIFIED when absent — inject a real source before gating real invocations |
| Holder-side presentation construction | **EXTENSION** — needs a holder signing key; a managed-server concern, out of the reference's trust model | Not a seam in this package by design |
| Zone-attestation conjunct (Gov-scoped ops) | **EXTENSION** — none of the three v0.1.0 tools is Gov-scoped | `ZoneAttestationCheck` interface in `src/auth/ucan-gate.ts`; conjunction form keeps attestation revocation independent of capability issuance |
| Layer 3 reputation tooling | **OUT OF SCOPE for v0.1.0** — can be added post-v0.1.0 if signal warrants; any future reputation surface reads opaque tokens only and inherits the re-hash-on-read discipline | — |

## Verifier hash-recompute contract

A consuming verifier re-hashes on read and never trusts a server-asserted hash. This reference server asserts no hashes on behalf of artifacts it did not verify; where a chain is present the walk is over presented inputs. Any future integration that READS stored hash-bearing artifacts (e.g. the agent-memory-board) must recompute integrity hashes and walk the chain on read.

## SDK migration

All MCP SDK imports live in `src/server.ts` and `src/transports/`. SDK v2 (package split, Web-Standard transports, zod v4) lands as a change to those files only; the engine, providers, tools, resources, and auth are SDK-agnostic.
