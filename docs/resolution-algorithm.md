# Resolution Algorithm

**Status:** DRAFT. Ships with protocol v0.1.0 and is version-pinned to it (no independent version line).
**Conformance:** a 40-fixture conformance suite tests verifiers against this algorithm (see [Conformance](#conformance)). The bundled MCP server reference implementation (`reference-implementations/mcp-server/`) implements it in full.

The resolution algorithm is the verifier procedure that **composes** the per-layer rules into a single decision. It is **not a protocol layer** and introduces **no new rules** — its contribution is the separation into two verifier contexts, the normative step ordering, the failure-mode table, and the conformance criteria. Where a step cites a rule, the cited layer specification is the locking authority.

## The two verifier contexts

The canonical scenario — an agent DID resolvable via Layer 0, an agent credential per Layer 1, a UCAN delegation chain per Layer 2, and a reputation VC per Layer 3 — spans two distinct questions, answered by two procedures over a shared check library:

- **Procedure A — presentation-time.** A verifier evaluates a *presented credential bundle* (agent identity + agent credential + optional reputation VC) to decide: *should I trust this agent's claimed standing and authority?*
- **Procedure B — invocation-time.** An agent *invokes a protected action* via a UCAN delegation chain, and the verifier decides: *may this specific invocation proceed?*

A verifier may run A alone (standing), B alone (gating an invocation), or A-then-B.

## Algorithm inputs

| Input | Context | Layer | Notes |
|---|---|---|---|
| Agent DID + resolution result | A, B | 0 | `did:sovrn:` primary normative; `did:web` accepted-input only when separately presented. Resolution is **hard-fail with NO auto-fallback** — a `did:sovrn:` failure never silently degrades to another method (closes the downgrade attack). |
| Agent credential (`SovrnAgentCredential`, W3C VC 2.0 or SD-JWT-VC envelope) | A, B | 1 | Carries `issuer`, multi-`proof[]`, `issuanceMethod`, `credentialStatus`, `evidence[]`. |
| `evidence[]` UCAN witness chain | A, B | 1 | Required for any authority decision on a DELEGATED agent. |
| Issuer Trust Establishment Document (resolved off `issuer.id`) | A, B | 1 | Names the issuer's framework/accreditation (DIF Trust Establishment). |
| UCAN delegation chain for the invocation | B | 2 | UCAN 1.0-rc.1 normative wire; 0.10 JWT accepted-input, translated at parse. |
| Target resource of the invocation | B | 2 | Compared against `att.with` (resource-identifier matching). |
| Reputation VC (`SovrnReputationRecord`) | A | 3 | Optional. `compositeScore` / `tier` are **opaque tokens** — read, never decoded. Dimension names, tier vocabulary, and score semantics are implementation-defined and out of scope for verifiers. |
| Accompanying credential chain (zone-authority attestation) | A | 3/4 | Optional. Feeds the Play/Gov seam (3-signal rule). Gov Mode attestation internals are opaque to this open algorithm. |

## Shared check library

Atomic checks both procedures call. Each cites its locking rule; none is new.

- `resolveAgentDID(did)` — resolve `did:sovrn:` (primary) or a separately-presented `did:web`. Hard-fail, no cross-method fallback. **MUST.**
- `verifySignatures(credential)` — verify **every** `proof[]` entry (multi-proof co-signing) and confirm `issuer.id`. **MUST.**
- `parseUCAN(token)` — parse 1.0-rc.1 (DAG-CBOR) normative; translate a 0.10 JWT envelope at parse. **MUST.**
- `resolveTED(issuerDID)` — resolve the issuer's Trust Establishment Document. **MUST** for authority decisions.
- `checkCredentialStatus(credential)` — BitstringStatusList revocation/suspension lookup. **MUST.**
- `checkAuthorityKeyGeneration(credential)` — authority key-generation status: a credential signed under a rotated/revoked key generation is stale. **MUST.**
- `checkUCANRevocation(link)` — UCAN-native blocklist lookup per delegation. **MUST.**
- `checkTimeBounds(token|credential, now)` — `nbf`/`exp` for UCAN; `validFrom`/`validUntil` for VCs. **MUST.**

## Procedure A — presentation-time

**Input:** agent DID, agent credential, optional reputation VC + accompanying chain.
**Output:** `{ accepted, mode: PLAY|GOV, trustProfile, reputationStatus, reasons[] }`.

```
A1. resolve     resolveAgentDID(agent.did)                # Layer 0 §4 — hard-fail, no fallback
                if unresolvable -> REJECT(DID_UNRESOLVABLE)

A2. signatures  verifySignatures(credential)              # L1 §8.2 — every proof[] entry
                if any proof invalid -> REJECT(SIGNATURE_INVALID)

A3. status      checkCredentialStatus(credential)         # L1 §9.1
                if revoked/suspended -> REJECT(CREDENTIAL_REVOKED)
                checkAuthorityKeyGeneration(credential)   # L1 D8
                if stale generation -> REJECT(STALE_EMBEDDED_AUTHORITY)

A4. ted         framework := resolveTED(credential.issuer.id)   # L1 §5.2

A5. chain       walk the evidence[] UCAN witness chain    # cross-layer revocation walk (below)
                if any link revoked -> REJECT(CROSS_LAYER_REVOKED)

A6. seam        mode := playGovSeam(credential, accompanyingChain)
                # normative: issuer.id in the verifier's trusted-issuer list (signal 1)
                # guidance:  issuanceMethod value + accompanying chain (signals 2, 3)

A7. reputation  if reputationVC present:
                  checkTimeBounds(reputationVC, now)      # epoch rule
                  if past validUntil AND outside the overlap window
                    -> reputationStatus := STALE_EPOCH    # GRADED, not a reject
                  read compositeScore/tier as OPAQUE tokens — never decode

A8. profile     trustProfile := apply the verifier trust profile   # guidance
                # encodes the COMMUNITY_ATTESTED Sybil floor and maps
                # issuanceMethod + co-signer composition to a threshold

A9. verdict     ACCEPT with { mode, trustProfile, reputationStatus }
```

**Normative vs graded:** A1–A5 are **MUST-reject** on failure (integrity/authority). A6's issuer-trusted-list check is **normative**; seam *recognition* is guidance. A7 reputation staleness is a **graded signal** — a stale reputation VC downgrades `reputationStatus`, it does not block standing evaluation. A8's threshold is guidance. Evaluation is sequential with short-circuit: the earliest failing step decides, and later checks are not run.

## Procedure B — invocation-time

**Input:** agent DID, agent credential (+ its `evidence[]` chain), the UCAN delegation chain for this invocation, the target resource.
**Output:** `{ permitted, reasons[] }`.

```
B1. resolve     resolveAgentDID(agent.did)                # Layer 0 §4 — hard-fail, no fallback
                if unresolvable -> DENY(DID_UNRESOLVABLE)

B2. parse       for each link: parseUCAN(link)            # 1.0-rc.1 normative; 0.10 JWT translated

B3. signatures  verify every delegation signature
                if invalid -> DENY(SIGNATURE_INVALID)

B4. timebounds  for each link: checkTimeBounds(link, now)
                if any expired -> DENY(DELEGATION_EXPIRED)

B5. chain       chain-validation invariant:
                  - direct line of authority: root sub -> ... -> invoker iss
                  - invoker DID == aud of the terminal delegation
                  - attenuation: each link's capabilities are a subset of its parent's
                if violated -> DENY(CHAIN_INVARIANT_VIOLATION)

B6. resource    resource-identifier match: att.with == the targeted resource
                (normalizing comparator; a trailing slash is not a different resource)
                if mismatch -> DENY(RESOURCE_MISMATCH)

B7. revocation  ORDER WITHIN B7 IS NORMATIVE:
                  1. cross-layer revocation walk over evidence[]  -> DENY(CROSS_LAYER_REVOKED)
                  2. for each link: checkUCANRevocation(link)     -> DENY(DELEGATION_REVOKED)
                  3. checkCredentialStatus(credential)            -> DENY(CREDENTIAL_REVOKED)
                  4. checkAuthorityKeyGeneration(credential)      -> DENY(STALE_EMBEDDED_AUTHORITY)

B8. principal   root principal still verified?
                if the root principal's credential is revoked/expired
                  -> DENY(ROOT_PRINCIPAL_NO_LONGER_VERIFIED)

B9. verdict     PERMIT
```

**All of B1–B8 are MUST-deny** on failure — invocation-time is integrity/authority all the way down; there is no graded path. B8 resolves the "UCAN technically unexpired but the root principal is no longer verified" case: a valid chain is not sufficient if its root authority has lapsed.

**B8 is a cross-protocol dependency.** The root-principal check resolves to a citizen credential in the sibling human-credential protocol. The resolution contract and the revocation-propagation path between the two protocols are **implementation-defined at v0.1.0** (the rule is locked; the plumbing is an integrator concern — the reference implementation exposes it as an injectable provider).

## The cross-layer revocation walk (called by A5 and B7)

A UCAN delegation embedded in a credential's `evidence[]` array MUST be treated as invalid if **(i)** the enclosing VC's BitstringStatusList bit indicates revocation, regardless of UCAN-level revocation state; **or (ii)** any link in the embedded UCAN proof chain appears in the UCAN revocation registry, regardless of the enclosing VC's status bit. The two conditions are independent; either alone rejects. Verifiers MUST walk the full `evidence[]` chain on every credential verification — a credential whose embedded chain contains a revoked link MUST be rejected even when its own status bit is clear.

## Failure modes

| Failure | Context | Handling | Cited rule |
|---|---|---|---|
| `DID_UNRESOLVABLE` | A, B | **REJECT/DENY** | Layer 0 §4 |
| `SIGNATURE_INVALID` | A, B | **REJECT/DENY** | L1 §8.2 / L2 §5 |
| `CREDENTIAL_REVOKED` | A, B | **REJECT/DENY** | L1 §9.1 / L2 §8.1 |
| `STALE_EMBEDDED_AUTHORITY` | A, B | **REJECT/DENY** | L1 D8/§9.2 |
| `CROSS_LAYER_REVOKED` | A, B | **REJECT/DENY** | §6 / L2 §8 / master §9.1 |
| `DELEGATION_EXPIRED` | B | **DENY** | L2 §5 Time Bounds |
| `CHAIN_INVARIANT_VIOLATION` | B | **DENY** | L2 §5/§7.4 (DL6) |
| `RESOURCE_MISMATCH` | B | **DENY** | L2 DL7/E3 / master §9.7 |
| `DELEGATION_REVOKED` | B | **DENY** | L2 §8.2 |
| `ROOT_PRINCIPAL_NO_LONGER_VERIFIED` | B | **DENY** | master §9.7 |
| `STALE_EPOCH` (reputation past `validUntil`, outside overlap) | A | **GRADED** — downgrade `reputationStatus` | L3 §6 / master §9.6 |
| Trust-profile threshold unmet | A | **GRADED** — guidance signal | master §9.1 |
| Play/Gov seam ambiguous | A | **GRADED** — recognition is guidance; the issuer-list check stays normative | L3 §5 / master §9.2 |

## Normative / guidance boundary

The algorithm inherits the per-layer normative/guidance split exactly and introduces no new normativity:

- **Normative MUST** (failure → reject/deny): all signature checks; both revocation mechanisms + the cross-layer walk; authority key generation; the chain-validation invariant; resource-identifier matching; time bounds; the Play/Gov issuer-trusted-list check; root-principal-still-verified at invocation.
- **Guidance / SHOULD** (informs a graded verdict): trust-profile thresholds; Play/Gov seam recognition (signals 2–3); reputation epoch freshness as a standing input.

A verifier MAY layer additional policy atop the guidance signals; it MUST NOT relax any normative MUST.

## Conformance

A conforming verifier, given each fixture bundle in the conformance suite, MUST produce the expected verdict — ACCEPT/REJECT for Procedure A, PERMIT/DENY for Procedure B — and MUST cite the exact failing rule (the table above) for every negative case. Fixture classes: positive, negative (one per failure mode, including both independent arms of the cross-layer walk and all three chain-invariant sub-cases), graded (non-blocking signals surface without rejecting), and edge (epoch overlap-window boundary, 0.10-vs-1.0-rc.1 wire, multi-proof co-signing, resource-identifier boundary, short-circuit ordering, long-chain probes).

The 40-fixture suite and the deterministic verifier contract ship with the protocol publication; the MCP server reference implementation passes 100% of the MUST set with exact cited rules and runs a differential check against the suite's deterministic mock verifier.
