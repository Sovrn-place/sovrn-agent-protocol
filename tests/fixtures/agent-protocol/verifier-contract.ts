/**
 * Sovrn Agent Protocol — Conformance Harness: Verifier Contract
 * Generated for: Step 7 conformance fixtures (agent-protocol-conformance-fixtures-design-2026-06-04.md)
 * Version: 0.1.0
 * License: Apache-2.0
 *
 * The contract surface a verifier-under-test implements. The resolution algorithm
 * (agent-protocol-resolution-algorithm-design-2026-06-03.md) defines two procedures:
 *   - Procedure A (presentation-time): ACCEPT | REJECT (+ graded ACCEPT)
 *   - Procedure B (invocation-time):   PERMIT | DENY (all MUST-deny)
 *
 * Step 7 ships this interface + a deterministic mock driver (mock-verifier.ts, JC-F1).
 * A real verifier (crypto, DID resolution, BitstringStatusList, UCAN revocation,
 * DAG-CBOR) implements the SAME interface later and runs against the SAME fixtures.
 * This file contains NO proprietary vocabulary and is publishable.
 */

// ---------------------------------------------------------------------------
// Cited rules — the typed union seeded from the §7 failure-mode table's
// "Locking rule" column (resolution algorithm §7). citedRule-exact per JC-F3.
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

// Failure modes partitioned by procedure (resolution algorithm §7).
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

// ---------------------------------------------------------------------------
// Verdict model (design doc §2). A graded Procedure-A outcome is still an
// ACCEPT, with reputationStatus and/or trustProfileDowngraded set.
// ---------------------------------------------------------------------------
export type Verdict =
  | { kind: 'ACCEPT'; mode: 'PLAY' | 'GOV'; reputationStatus?: 'FRESH' | 'STALE_EPOCH'; trustProfileDowngraded?: boolean }
  | { kind: 'REJECT'; citedRule: CitedRule; failureMode: FailureModeA }
  | { kind: 'PERMIT' }
  | { kind: 'DENY'; citedRule: CitedRule; failureMode: FailureModeB };

// ---------------------------------------------------------------------------
// Oracle hints. The mock driver's atomic checks are deterministic table lookups
// keyed off these per-fixture hints (JC-F1). A real verifier ignores the oracle
// and computes these from crypto / DID resolution / revocation registries.
// Cross-protocol root-principal status (B8) is supplied as an oracle input
// because the cross-protocol plumbing is implementation-defined at v0.1.0.
// ---------------------------------------------------------------------------
export interface CheckOracle {
  didResolvable?: boolean;            // resolveAgentDID — Layer 0 §4 hard-fail
  signaturesValid?: boolean;          // verifySignatures — every proof[] entry
  credentialRevoked?: boolean;        // checkCredentialStatus — BitstringStatusList bit
  staleEmbeddedAuthority?: boolean;   // checkAuthorityKeyGeneration — key-generation flip
  crossLayerChainLinkRevoked?: boolean; // a revoked link inside evidence[] (the OR arm independent of the VC bit)
  delegationExpired?: boolean;        // checkTimeBounds on a chain link
  chainInvariantViolated?: boolean;   // chain-validation invariant (sub→iss / invoker=aud / attenuation)
  resourceMismatch?: boolean;         // att.with != targeted resource
  delegationRevoked?: boolean;        // checkUCANRevocation — UCAN-native blocklist
  rootPrincipalVerified?: boolean;    // B8 cross-protocol citizen-credential status (oracle input)
  reputationPastValidUntil?: boolean; // L3 §6 epoch boundary
  insideOverlapWindow?: boolean;      // L3 §6 overlap window
  trustProfileThresholdMet?: boolean; // master §9.1 trust-profile threshold
  seamAmbiguous?: boolean;            // L3 §5 Play/Gov seam recognition
  mode?: 'PLAY' | 'GOV';              // resolved mode for a positive/graded ACCEPT
}

export interface PresentationBundle {
  /** The agent credential wire-shape (SovrnAgentCredential). */
  credential: unknown;
  /** Optional reputation VC (SovrnReputationRecord). */
  reputationVC?: unknown;
  /** Oracle hints honored by the mock driver. */
  _oracle?: CheckOracle;
}

export interface InvocationBundle {
  /** The agent credential + its evidence[] chain. */
  credential: unknown;
  /** The UCAN delegation chain for this invocation. */
  delegationChain: unknown;
  /** The target resource of the invocation. */
  targetResource?: string;
  /** Oracle hints honored by the mock driver. */
  _oracle?: CheckOracle;
}

export interface Verifier {
  /** Procedure A — presentation-time. Returns ACCEPT (possibly graded) or REJECT. */
  procedureA(bundle: PresentationBundle): Verdict;
  /** Procedure B — invocation-time. Returns PERMIT or DENY. */
  procedureB(bundle: InvocationBundle): Verdict;
}
