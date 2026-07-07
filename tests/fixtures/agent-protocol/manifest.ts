/**
 * Sovrn Agent Protocol — Conformance Harness: Fixture Manifest
 * Generated for: Step 7 conformance fixtures (agent-protocol-conformance-fixtures-design-2026-06-04.md)
 * Version: 0.1.0
 * License: Apache-2.0
 *
 * The SINGLE SOURCE OF COVERAGE TRUTH. Every *.bundle.json under bundles/ has
 * exactly one FixtureSpec entry here (asserted by a meta-test). Every §7 failure
 * mode and every named edge case has >=1 entry (asserted by a coverage meta-test).
 *
 * Each entry's `expected` Verdict must match what mock-verifier.ts produces for the
 * bundle's _oracle hints (the conformance test asserts this). citedRule is exact
 * per JC-F3. Contains NO proprietary vocabulary. Publishable.
 */

import type { Verdict, FailureModeA, FailureModeB } from './verifier-contract';

export interface FixtureSpec {
  /** Path relative to bundles/. */
  bundle: string;
  /** Which procedure this bundle exercises. */
  procedure: 'A' | 'B';
  /** Fixture class (encodes the verdict class; graded is split from negative). */
  class: 'positive' | 'negative' | 'graded' | 'edge';
  /** The expected verdict the mock driver (and any conforming verifier) must produce. */
  expected: Verdict;
  /** For CHAIN_INVARIANT_VIOLATION, which of the three sub-cases this is. */
  chainInvariantSubCase?: 'SUB_ISS_BREAK' | 'INVOKER_AUD' | 'ATTENUATION';
  /** Whether the bundle is schema-validatable today; 'xfail' for DAG-CBOR / SD-JWT-presentation (no artifact). */
  schemaValidation: 'validate' | 'xfail';
  /** Which schema artifact validates this bundle's credential (when schemaValidation === 'validate'). */
  schema?: 'locked' | 'draft';
  /** The §7 failure mode this fixture covers (for the coverage meta-test). Omitted for positives. */
  covers?: FailureModeA | FailureModeB | EdgeCase;
  note?: string;
}

/** Named edge cases the design doc §5 enumerates (for the coverage meta-test). */
export type EdgeCase =
  | 'EPOCH_OVERLAP_INSIDE'
  | 'EPOCH_OVERLAP_OUTSIDE'
  | 'UCAN_010_WIRE'
  | 'UCAN_10_RC1_WIRE'
  | 'MULTI_PROOF_COSIGNING'
  | 'SYBIL_FLOOR'
  | 'SD_JWT_SELECTIVE_DISCLOSURE'
  | 'DID_SOVRN_TYPE_SEGMENTS'
  | 'ERC8004_ABSENT'
  | 'JWS_SIGNED_AGENT_CARD'
  | 'RESOURCE_IDENTIFIER_BOUNDARY'
  | 'SHORT_CIRCUIT_ORDERING'
  | 'LONG_CHAIN';

// ===========================================================================
// PROCEDURE A — presentation-time
// ===========================================================================
const PROCEDURE_A: FixtureSpec[] = [
  // --- positive ---
  { bundle: 'procedure-a/positive/play-self-attested.bundle.json', procedure: 'A', class: 'positive',
    expected: { kind: 'ACCEPT', mode: 'PLAY' }, schemaValidation: 'validate', schema: 'locked' },
  { bundle: 'procedure-a/positive/gov-zone-issued.bundle.json', procedure: 'A', class: 'positive',
    expected: { kind: 'ACCEPT', mode: 'GOV' }, schemaValidation: 'validate', schema: 'locked' },

  // --- negative (MUST-reject) ---
  { bundle: 'procedure-a/negative/did-unresolvable.bundle.json', procedure: 'A', class: 'negative',
    expected: { kind: 'REJECT', citedRule: 'Layer 0 §4', failureMode: 'DID_UNRESOLVABLE' },
    schemaValidation: 'validate', schema: 'locked', covers: 'DID_UNRESOLVABLE' },
  { bundle: 'procedure-a/negative/signature-invalid.bundle.json', procedure: 'A', class: 'negative',
    expected: { kind: 'REJECT', citedRule: 'L1 §8.2 / L2 §5', failureMode: 'SIGNATURE_INVALID' },
    schemaValidation: 'validate', schema: 'locked', covers: 'SIGNATURE_INVALID' },
  { bundle: 'procedure-a/negative/credential-revoked.bundle.json', procedure: 'A', class: 'negative',
    expected: { kind: 'REJECT', citedRule: 'L1 §9.1 / L2 §8.1', failureMode: 'CREDENTIAL_REVOKED' },
    schemaValidation: 'validate', schema: 'locked', covers: 'CREDENTIAL_REVOKED' },
  { bundle: 'procedure-a/negative/stale-embedded-authority.bundle.json', procedure: 'A', class: 'negative',
    expected: { kind: 'REJECT', citedRule: 'L1 D8/§9.2', failureMode: 'STALE_EMBEDDED_AUTHORITY' },
    schemaValidation: 'validate', schema: 'locked', covers: 'STALE_EMBEDDED_AUTHORITY' },
  // CROSS_LAYER_REVOKED bidirectional pair. Arm (i): VC bit set -> surfaces as CREDENTIAL_REVOKED (A3).
  { bundle: 'procedure-a/negative/cross-layer-revoked-vc-bit.bundle.json', procedure: 'A', class: 'negative',
    expected: { kind: 'REJECT', citedRule: 'L1 §9.1 / L2 §8.1', failureMode: 'CREDENTIAL_REVOKED' },
    schemaValidation: 'validate', schema: 'locked', covers: 'CROSS_LAYER_REVOKED',
    note: 'arm (i): VC bit set, chain clean -> surfaces at A3 as CREDENTIAL_REVOKED' },
  // Arm (ii): VC bit clear, chain link revoked -> surfaces as CROSS_LAYER_REVOKED (A5).
  { bundle: 'procedure-a/negative/cross-layer-revoked-chain-link.bundle.json', procedure: 'A', class: 'negative',
    expected: { kind: 'REJECT', citedRule: '§6 / L2 §8 / master §9.1', failureMode: 'CROSS_LAYER_REVOKED' },
    schemaValidation: 'validate', schema: 'locked', covers: 'CROSS_LAYER_REVOKED',
    note: 'arm (ii): VC bit clear, chain link revoked -> surfaces at A5 as CROSS_LAYER_REVOKED' },

  // --- graded ---
  { bundle: 'procedure-a/graded/stale-epoch.bundle.json', procedure: 'A', class: 'graded',
    expected: { kind: 'ACCEPT', mode: 'PLAY', reputationStatus: 'STALE_EPOCH' },
    schemaValidation: 'validate', schema: 'locked', covers: 'EPOCH_OVERLAP_OUTSIDE' },
  { bundle: 'procedure-a/graded/trust-profile-threshold-unmet.bundle.json', procedure: 'A', class: 'graded',
    expected: { kind: 'ACCEPT', mode: 'PLAY', trustProfileDowngraded: true },
    schemaValidation: 'validate', schema: 'locked' },
  { bundle: 'procedure-a/graded/play-gov-seam-ambiguous.bundle.json', procedure: 'A', class: 'graded',
    expected: { kind: 'ACCEPT', mode: 'PLAY', trustProfileDowngraded: true },
    schemaValidation: 'validate', schema: 'locked' },

  // --- edge ---
  { bundle: 'procedure-a/edge/epoch-overlap-inside-window.bundle.json', procedure: 'A', class: 'edge',
    expected: { kind: 'ACCEPT', mode: 'PLAY', reputationStatus: 'FRESH' },
    schemaValidation: 'validate', schema: 'locked', covers: 'EPOCH_OVERLAP_INSIDE' },
  { bundle: 'procedure-a/edge/multi-proof-cosigning.bundle.json', procedure: 'A', class: 'edge',
    expected: { kind: 'ACCEPT', mode: 'GOV' },
    schemaValidation: 'validate', schema: 'locked', covers: 'MULTI_PROOF_COSIGNING',
    note: 'array proof — validates against locked schema, NOT draft (single-object proof)' },
  { bundle: 'procedure-a/edge/sybil-floor-all-self-attested.bundle.json', procedure: 'A', class: 'edge',
    expected: { kind: 'ACCEPT', mode: 'PLAY', trustProfileDowngraded: true },
    schemaValidation: 'validate', schema: 'locked', covers: 'SYBIL_FLOOR' },
  { bundle: 'procedure-a/edge/sd-jwt-vc-selective-disclosure.bundle.json', procedure: 'A', class: 'edge',
    expected: { kind: 'ACCEPT', mode: 'GOV' },
    schemaValidation: 'xfail', covers: 'SD_JWT_SELECTIVE_DISCLOSURE',
    note: 'disclosed-presentation shape (principalDID withheld) — no schema artifact; xfail per §10' },
  { bundle: 'procedure-a/edge/did-sovrn-type-segments.bundle.json', procedure: 'A', class: 'edge',
    expected: { kind: 'ACCEPT', mode: 'GOV' },
    schemaValidation: 'validate', schema: 'locked', covers: 'DID_SOVRN_TYPE_SEGMENTS' },
  { bundle: 'procedure-a/edge/erc8004-absent-still-resolvable.bundle.json', procedure: 'A', class: 'edge',
    expected: { kind: 'ACCEPT', mode: 'PLAY' },
    schemaValidation: 'validate', schema: 'locked', covers: 'ERC8004_ABSENT' },
  { bundle: 'procedure-a/edge/jws-signed-agent-card.bundle.json', procedure: 'A', class: 'edge',
    expected: { kind: 'ACCEPT', mode: 'PLAY' },
    schemaValidation: 'validate', schema: 'locked', covers: 'JWS_SIGNED_AGENT_CARD' },
  { bundle: 'procedure-a/edge/short-circuit-ordering.bundle.json', procedure: 'A', class: 'edge',
    expected: { kind: 'REJECT', citedRule: 'Layer 0 §4', failureMode: 'DID_UNRESOLVABLE' },
    schemaValidation: 'validate', schema: 'locked', covers: 'SHORT_CIRCUIT_ORDERING',
    note: 'double-fault A1+A2 -> earlier (A1 DID_UNRESOLVABLE) wins' },
];

// ===========================================================================
// PROCEDURE B — invocation-time
// ===========================================================================
const PROCEDURE_B: FixtureSpec[] = [
  // --- positive ---
  { bundle: 'procedure-b/positive/invocation-permitted-short-chain.bundle.json', procedure: 'B', class: 'positive',
    expected: { kind: 'PERMIT' }, schemaValidation: 'validate', schema: 'locked' },

  // --- negative (MUST-deny) ---
  { bundle: 'procedure-b/negative/did-unresolvable.bundle.json', procedure: 'B', class: 'negative',
    expected: { kind: 'DENY', citedRule: 'Layer 0 §4', failureMode: 'DID_UNRESOLVABLE' },
    schemaValidation: 'validate', schema: 'locked', covers: 'DID_UNRESOLVABLE' },
  { bundle: 'procedure-b/negative/signature-invalid.bundle.json', procedure: 'B', class: 'negative',
    expected: { kind: 'DENY', citedRule: 'L1 §8.2 / L2 §5', failureMode: 'SIGNATURE_INVALID' },
    schemaValidation: 'validate', schema: 'locked', covers: 'SIGNATURE_INVALID' },
  { bundle: 'procedure-b/negative/delegation-expired.bundle.json', procedure: 'B', class: 'negative',
    expected: { kind: 'DENY', citedRule: 'L2 §5 Time Bounds', failureMode: 'DELEGATION_EXPIRED' },
    schemaValidation: 'validate', schema: 'locked', covers: 'DELEGATION_EXPIRED' },
  { bundle: 'procedure-b/negative/chain-invariant-sub-iss-break.bundle.json', procedure: 'B', class: 'negative',
    expected: { kind: 'DENY', citedRule: 'L2 §5/§7.4 (DL6)', failureMode: 'CHAIN_INVARIANT_VIOLATION' },
    chainInvariantSubCase: 'SUB_ISS_BREAK', schemaValidation: 'validate', schema: 'locked', covers: 'CHAIN_INVARIANT_VIOLATION' },
  { bundle: 'procedure-b/negative/chain-invariant-invoker-not-terminal-aud.bundle.json', procedure: 'B', class: 'negative',
    expected: { kind: 'DENY', citedRule: 'L2 §5/§7.4 (DL6)', failureMode: 'CHAIN_INVARIANT_VIOLATION' },
    chainInvariantSubCase: 'INVOKER_AUD', schemaValidation: 'validate', schema: 'locked', covers: 'CHAIN_INVARIANT_VIOLATION' },
  { bundle: 'procedure-b/negative/chain-invariant-attenuation-break.bundle.json', procedure: 'B', class: 'negative',
    expected: { kind: 'DENY', citedRule: 'L2 §5/§7.4 (DL6)', failureMode: 'CHAIN_INVARIANT_VIOLATION' },
    chainInvariantSubCase: 'ATTENUATION', schemaValidation: 'validate', schema: 'locked', covers: 'CHAIN_INVARIANT_VIOLATION' },
  { bundle: 'procedure-b/negative/resource-mismatch.bundle.json', procedure: 'B', class: 'negative',
    expected: { kind: 'DENY', citedRule: 'L2 DL7/E3 / master §9.7', failureMode: 'RESOURCE_MISMATCH' },
    schemaValidation: 'validate', schema: 'locked', covers: 'RESOURCE_MISMATCH' },
  { bundle: 'procedure-b/negative/delegation-revoked.bundle.json', procedure: 'B', class: 'negative',
    expected: { kind: 'DENY', citedRule: 'L2 §8.2', failureMode: 'DELEGATION_REVOKED' },
    schemaValidation: 'validate', schema: 'locked', covers: 'DELEGATION_REVOKED' },
  // CROSS_LAYER_REVOKED bidirectional pair (Procedure B).
  { bundle: 'procedure-b/negative/cross-layer-revoked-vc-bit.bundle.json', procedure: 'B', class: 'negative',
    expected: { kind: 'DENY', citedRule: 'L1 §9.1 / L2 §8.1', failureMode: 'CREDENTIAL_REVOKED' },
    schemaValidation: 'validate', schema: 'locked', covers: 'CROSS_LAYER_REVOKED',
    note: 'arm (i): VC bit set, chain clean -> surfaces at B7 as CREDENTIAL_REVOKED' },
  { bundle: 'procedure-b/negative/cross-layer-revoked-chain-link.bundle.json', procedure: 'B', class: 'negative',
    expected: { kind: 'DENY', citedRule: '§6 / L2 §8 / master §9.1', failureMode: 'CROSS_LAYER_REVOKED' },
    schemaValidation: 'validate', schema: 'locked', covers: 'CROSS_LAYER_REVOKED',
    note: 'arm (ii): VC bit clear, chain link revoked -> surfaces at B7 as CROSS_LAYER_REVOKED' },
  { bundle: 'procedure-b/negative/credential-revoked.bundle.json', procedure: 'B', class: 'negative',
    expected: { kind: 'DENY', citedRule: 'L1 §9.1 / L2 §8.1', failureMode: 'CREDENTIAL_REVOKED' },
    schemaValidation: 'validate', schema: 'locked', covers: 'CREDENTIAL_REVOKED' },
  { bundle: 'procedure-b/negative/stale-embedded-authority.bundle.json', procedure: 'B', class: 'negative',
    expected: { kind: 'DENY', citedRule: 'L1 D8/§9.2', failureMode: 'STALE_EMBEDDED_AUTHORITY' },
    schemaValidation: 'validate', schema: 'locked', covers: 'STALE_EMBEDDED_AUTHORITY' },
  { bundle: 'procedure-b/negative/root-principal-no-longer-verified.bundle.json', procedure: 'B', class: 'negative',
    expected: { kind: 'DENY', citedRule: 'master §9.7', failureMode: 'ROOT_PRINCIPAL_NO_LONGER_VERIFIED' },
    schemaValidation: 'validate', schema: 'locked', covers: 'ROOT_PRINCIPAL_NO_LONGER_VERIFIED',
    note: 'partial — root-principal status supplied as oracle input; cross-protocol resolution out of scope at v0.1.0' },

  // --- edge ---
  { bundle: 'procedure-b/edge/ucan-010-jwt-wire.bundle.json', procedure: 'B', class: 'edge',
    expected: { kind: 'PERMIT' }, schemaValidation: 'validate', schema: 'draft', covers: 'UCAN_010_WIRE',
    note: '0.10 JWT accepted-input — validates against the draft delegation-token schema (JWT-shaped)' },
  { bundle: 'procedure-b/edge/ucan-10-rc1-dagcbor-wire.bundle.json', procedure: 'B', class: 'edge',
    expected: { kind: 'PERMIT' }, schemaValidation: 'xfail', covers: 'UCAN_10_RC1_WIRE',
    note: 'DAG-CBOR projection — no schema artifact for the 1.0-rc.1 wire; xfail per §10' },
  { bundle: 'procedure-b/edge/resource-identifier-boundary.bundle.json', procedure: 'B', class: 'edge',
    expected: { kind: 'PERMIT' }, schemaValidation: 'validate', schema: 'locked', covers: 'RESOURCE_IDENTIFIER_BOUNDARY' },
  { bundle: 'procedure-b/edge/long-chain-3-links.bundle.json', procedure: 'B', class: 'edge',
    expected: { kind: 'PERMIT' }, schemaValidation: 'validate', schema: 'locked', covers: 'LONG_CHAIN' },
  { bundle: 'procedure-b/edge/long-chain-5-links.bundle.json', procedure: 'B', class: 'edge',
    expected: { kind: 'PERMIT' }, schemaValidation: 'validate', schema: 'locked', covers: 'LONG_CHAIN' },
  { bundle: 'procedure-b/edge/long-chain-10-links.bundle.json', procedure: 'B', class: 'edge',
    expected: { kind: 'PERMIT' }, schemaValidation: 'validate', schema: 'locked', covers: 'LONG_CHAIN' },
  { bundle: 'procedure-b/edge/short-circuit-ordering.bundle.json', procedure: 'B', class: 'edge',
    expected: { kind: 'DENY', citedRule: 'Layer 0 §4', failureMode: 'DID_UNRESOLVABLE' },
    schemaValidation: 'validate', schema: 'locked', covers: 'SHORT_CIRCUIT_ORDERING',
    note: 'double-fault B1+B4 -> earlier (B1 DID_UNRESOLVABLE) wins' },
];

export const MANIFEST: FixtureSpec[] = [...PROCEDURE_A, ...PROCEDURE_B];

/** The WATCH-2 long-chain probes, in ascending depth, for the timing seam (JC-F4). */
export const LONG_CHAIN_PROBES: { bundle: string; depth: number }[] = [
  { bundle: 'procedure-b/edge/long-chain-3-links.bundle.json', depth: 3 },
  { bundle: 'procedure-b/edge/long-chain-5-links.bundle.json', depth: 5 },
  { bundle: 'procedure-b/edge/long-chain-10-links.bundle.json', depth: 10 },
];
