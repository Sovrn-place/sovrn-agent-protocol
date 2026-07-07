/**
 * Sovrn Agent Protocol — MCP Server Reference Implementation
 * Engine types: Verdict model + CheckProviders (dependency-injection seam).
 *
 * The Verdict / CitedRule / FailureMode types are string-identical to the
 * conformance harness contract (tests/fixtures/agent-protocol/verifier-contract.ts
 * in the protocol repo). This file deliberately re-declares them rather than
 * importing across the package boundary so the reference implementation stays
 * self-contained and publishable; conformance/contract-parity.ts pins the two
 * declarations together at compile time (type-only imports, dev-only).
 *
 * NOTE the intentional, typed deviation from the harness contract: the harness
 * `Verifier` interface is synchronous (it was authored for a deterministic mock);
 * a real verifier resolves DIDs and fetches status lists over the network, so the
 * engine here is async (`Promise<Verdict>`). The conformance runner awaits.
 *
 * License: Apache-2.0. Contains no proprietary vocabulary.
 */

// ---------------------------------------------------------------------------
// Cited rules — seeded from the resolution algorithm §7 failure-mode table's
// "Locking rule" column. citedRule-exact per conformance JC-F3.
// ---------------------------------------------------------------------------
export type CitedRule =
  | 'Layer 0 §4'        // DID_UNRESOLVABLE — hard-fail, no auto-fallback (JC1)
  | 'L1 §8.2 / L2 §5'   // SIGNATURE_INVALID
  | 'L1 §9.1 / L2 §8.1' // CREDENTIAL_REVOKED (BitstringStatusList)
  | 'L1 D8/§9.2'        // STALE_EMBEDDED_AUTHORITY (key-generation flip)
  | '§6 / L2 §8 / master §9.1' // CROSS_LAYER_REVOKED (revoked link in evidence[])
  | 'L2 §5 Time Bounds' // DELEGATION_EXPIRED
  | 'L2 §5/§7.4 (DL6)'  // CHAIN_INVARIANT_VIOLATION (all three sub-cases)
  | 'L2 DL7/E3 / master §9.7' // RESOURCE_MISMATCH
  | 'L2 §8.2'           // DELEGATION_REVOKED (UCAN-native blocklist)
  | 'master §9.7'       // ROOT_PRINCIPAL_NO_LONGER_VERIFIED
  | 'L3 §6 / master §9.6'     // STALE_EPOCH (graded)
  | 'master §9.1'       // trust-profile threshold unmet (graded)
  | 'L3 §5 / master §9.2';    // Play/Gov seam ambiguous (graded)

export type FailureModeA =
  | 'DID_UNRESOLVABLE'
  | 'SIGNATURE_INVALID'
  | 'CREDENTIAL_REVOKED'
  | 'STALE_EMBEDDED_AUTHORITY'
  | 'CROSS_LAYER_REVOKED';

export type FailureModeB =
  | 'DID_UNRESOLVABLE'
  | 'SIGNATURE_INVALID'
  | 'CREDENTIAL_REVOKED'
  | 'STALE_EMBEDDED_AUTHORITY'
  | 'CROSS_LAYER_REVOKED'
  | 'DELEGATION_EXPIRED'
  | 'CHAIN_INVARIANT_VIOLATION'
  | 'RESOURCE_MISMATCH'
  | 'DELEGATION_REVOKED'
  | 'ROOT_PRINCIPAL_NO_LONGER_VERIFIED';

// A graded Procedure-A outcome is still an ACCEPT, with reputationStatus
// and/or trustProfileDowngraded set. Field-presence semantics matter: absent
// means "no signal evaluated", and the conformance suite deep-equals verdicts.
export type Verdict =
  | { kind: 'ACCEPT'; mode: 'PLAY' | 'GOV'; reputationStatus?: 'FRESH' | 'STALE_EPOCH'; trustProfileDowngraded?: boolean }
  | { kind: 'REJECT'; citedRule: CitedRule; failureMode: FailureModeA }
  | { kind: 'PERMIT' }
  | { kind: 'DENY'; citedRule: CitedRule; failureMode: FailureModeB };

// ---------------------------------------------------------------------------
// Wire-shaped inputs (mirror the harness bundle shapes minus the _oracle key,
// which is a conformance-fixture artifact the engine never reads).
// ---------------------------------------------------------------------------
export interface PresentationInput {
  /** The agent credential wire-shape (SovrnAgentCredential). */
  credential: unknown;
  /** Optional reputation VC (SovrnReputationRecord); read as opaque, L3 out of scope. */
  reputationVC?: unknown;
}

export interface InvocationInput {
  /** The agent credential + its evidence[] chain. */
  credential: unknown;
  /** The UCAN delegation chain for this invocation. */
  delegationChain: unknown;
  /** The target resource of the invocation. */
  targetResource?: string;
}

// ---------------------------------------------------------------------------
// CheckProviders — the DI seam.
//
// Providers return CHECK OUTCOMES ONLY. They never construct verdicts and never
// cite rules: all verdict assembly and every citedRule string lives in the
// engine (rules.ts + procedure-a.ts / procedure-b.ts). This keeps the
// conformance fixture-adapter structurally incapable of smuggling verdict
// logic, and keeps production/conformance on one engine code path.
//
// Granularity notes:
// - Per-item where the wire structure is guaranteed (proof[] entries, delegation
//   links): the ENGINE iterates, the provider judges one item. The engine's
//   "every entry must verify" aggregation is therefore conformance-exercised.
// - Whole-walk for the cross-layer evidence[] walk: fixtures assert the walk's
//   OUTCOME (a revoked link exists), not its internal iteration, and a
//   credential's embedded-evidence shape is implementation-varied. The provider
//   walks; production iterates internally (checks.ts).
// - B8 root-principal status and the BitstringStatusList fetch are injectable
//   by design (impl-defined at v0.1.0 — resolution algorithm §5 / design §11).
// ---------------------------------------------------------------------------
export interface CheckProviders {
  /** A1/B1 — Layer 0 §4 resolveAgentDID. Hard-fail; NO cross-method fallback. */
  resolveDid(did: string | undefined): Promise<'RESOLVED' | 'UNRESOLVABLE'>;
  /** A2 — verify ONE credential proof[] entry against the resolved key material. */
  verifyCredentialProof(proof: unknown, credential: unknown): Promise<'VALID' | 'INVALID'>;
  /** B2/B3 — verify ONE delegation link's signature. */
  verifyDelegationSignature(link: unknown): Promise<'VALID' | 'INVALID'>;
  /** A3/B7 — credential status (BitstringStatusList bit). */
  credentialStatus(credential: unknown): Promise<'ACTIVE' | 'REVOKED'>;
  /** A3/B7 — authority key-generation freshness (L1 D8). */
  authorityKeyGeneration(credential: unknown): Promise<'CURRENT' | 'STALE'>;
  /** A5/B7 — cross-layer revocation walk over the credential's embedded evidence[] chain. */
  crossLayerWalk(credential: unknown): Promise<'CLEAR' | 'REVOKED_LINK'>;
  /** B4 — time bounds for ONE delegation link (nbf/exp against the verifier clock). */
  linkTimeBounds(link: unknown): Promise<'WITHIN' | 'EXPIRED'>;
  /** B5 — chain-validation invariant: sub→iss line, invoker = terminal aud, attenuation. */
  chainInvariant(chain: unknown[], invokerDid: string | undefined): Promise<'HOLDS' | 'VIOLATED'>;
  /** B6 — resource-identifier match (normalizing comparator; L2 DL7/E3). */
  resourceMatch(attWith: string | undefined, targetResource: string | undefined): Promise<'MATCH' | 'MISMATCH'>;
  /** B7 — UCAN-native blocklist status for ONE delegation link. */
  delegationRevocation(link: unknown): Promise<'CLEAR' | 'REVOKED'>;
  /** B8 — cross-protocol root-principal status (injectable; impl-defined at v0.1.0). */
  rootPrincipalStatus(chain: unknown[], credential: unknown): Promise<'VERIFIED' | 'NOT_VERIFIED'>;
  /** A6 — issuer-trusted-list check (normative) + Play/Gov seam recognition (guidance). */
  resolveMode(credential: unknown): Promise<{ mode: 'PLAY' | 'GOV'; seamAmbiguous: boolean }>;
  /**
   * A7 — reputation epoch signal (L3 §6 / master §9.6). Returns null when no
   * reputation signal is present (then no reputationStatus field is emitted).
   * The reputation VC is read as an OPAQUE artifact — Layer 3 semantics
   * (tiers, dimensions, scores) are never interpreted here.
   */
  reputationEpoch(reputationVC: unknown): Promise<{ pastValidUntil: boolean; insideOverlapWindow: boolean } | null>;
  /** A8 — trust-profile threshold (master §9.1, graded guidance). */
  trustProfileThreshold(credential: unknown, reputationVC: unknown): Promise<'MET' | 'UNMET'>;
}
