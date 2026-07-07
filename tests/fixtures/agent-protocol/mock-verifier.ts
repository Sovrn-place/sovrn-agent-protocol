/**
 * Sovrn Agent Protocol — Conformance Harness: Deterministic Mock Verifier (JC-F1)
 * Generated for: Step 7 conformance fixtures (agent-protocol-conformance-fixtures-design-2026-06-04.md)
 * Version: 0.1.0
 * License: Apache-2.0
 *
 * Implements the Verifier contract with atomic checks realized as DETERMINISTIC
 * TABLE LOOKUPS keyed off each fixture's _oracle hints. The A1–A9 / B1–B9 ORDERING
 * is genuine — the short-circuit sequencing (first failure wins) is real — but the
 * leaf checks (crypto, DID resolution, DAG-CBOR, revocation registries) are mocked.
 *
 * This makes the suite self-validating and pins step-ordering WITHOUT implementing
 * a production verifier. A real verifier implements the same interface later.
 *
 * Step ordering mirrors the resolution algorithm verbatim:
 *   Procedure A: A1 resolve, A2 signatures, A3 status+key-gen, A5 cross-layer walk,
 *                A6 seam, A7 reputation (graded), A8 trust-profile (graded), A9 verdict.
 *   Procedure B: B1 resolve, B2/B3 parse+signatures, B4 timebounds, B5 chain invariant,
 *                B6 resource, B7 revocation+cross-layer, B8 root principal, B9 verdict.
 *
 * Contains NO proprietary vocabulary. Publishable.
 */

import type {
  Verifier,
  Verdict,
  PresentationBundle,
  InvocationBundle,
  CheckOracle,
} from './verifier-contract';

// Defaults: absent oracle flags mean "the check passes" (a well-formed positive
// bundle supplies no failure hints and flows to ACCEPT/PERMIT).
function ora(bundle: { _oracle?: CheckOracle }): CheckOracle {
  return bundle._oracle ?? {};
}

export class MockVerifier implements Verifier {
  // -------------------------------------------------------------------------
  // Procedure A — presentation-time. ACCEPT (possibly graded) or REJECT.
  // -------------------------------------------------------------------------
  procedureA(bundle: PresentationBundle): Verdict {
    const o = ora(bundle);

    // A1 — resolve agent DID (Layer 0 §4, hard-fail, no fallback)
    if (o.didResolvable === false) {
      return { kind: 'REJECT', citedRule: 'Layer 0 §4', failureMode: 'DID_UNRESOLVABLE' };
    }

    // A2 — verify every proof[] entry (L1 §8.2)
    if (o.signaturesValid === false) {
      return { kind: 'REJECT', citedRule: 'L1 §8.2 / L2 §5', failureMode: 'SIGNATURE_INVALID' };
    }

    // A3 — credential status (L1 §9.1) then authority-key-generation (L1 D8)
    if (o.credentialRevoked === true) {
      return { kind: 'REJECT', citedRule: 'L1 §9.1 / L2 §8.1', failureMode: 'CREDENTIAL_REVOKED' };
    }
    if (o.staleEmbeddedAuthority === true) {
      return { kind: 'REJECT', citedRule: 'L1 D8/§9.2', failureMode: 'STALE_EMBEDDED_AUTHORITY' };
    }

    // A5 — cross-layer revocation walk (§6). Reject if EITHER the VC bit is set
    // (handled at A3) OR any embedded chain link is revoked (this arm).
    if (o.crossLayerChainLinkRevoked === true) {
      return { kind: 'REJECT', citedRule: '§6 / L2 §8 / master §9.1', failureMode: 'CROSS_LAYER_REVOKED' };
    }

    // A6 — Play/Gov seam. Issuer-trusted-list check is normative (assumed passed
    // here when mode is resolved); seam recognition is guidance (graded).
    const mode: 'PLAY' | 'GOV' = o.mode ?? 'PLAY';

    // A7/A8 — graded signals. None of these block; they downgrade the ACCEPT.
    let reputationStatus: 'FRESH' | 'STALE_EPOCH' | undefined;
    if (o.reputationPastValidUntil !== undefined) {
      reputationStatus =
        o.reputationPastValidUntil && o.insideOverlapWindow === false ? 'STALE_EPOCH' : 'FRESH';
    }
    const trustProfileDowngraded =
      o.trustProfileThresholdMet === false || o.seamAmbiguous === true ? true : undefined;

    // A9 — verdict
    const verdict: Verdict = { kind: 'ACCEPT', mode };
    if (reputationStatus !== undefined) verdict.reputationStatus = reputationStatus;
    if (trustProfileDowngraded) verdict.trustProfileDowngraded = true;
    return verdict;
  }

  // -------------------------------------------------------------------------
  // Procedure B — invocation-time. PERMIT or DENY (all MUST-deny on failure).
  // -------------------------------------------------------------------------
  procedureB(bundle: InvocationBundle): Verdict {
    const o = ora(bundle);

    // B1 — resolve agent DID (Layer 0 §4)
    if (o.didResolvable === false) {
      return { kind: 'DENY', citedRule: 'Layer 0 §4', failureMode: 'DID_UNRESOLVABLE' };
    }

    // B2/B3 — parse + verify every delegation signature (L2 §6 / §5)
    if (o.signaturesValid === false) {
      return { kind: 'DENY', citedRule: 'L1 §8.2 / L2 §5', failureMode: 'SIGNATURE_INVALID' };
    }

    // B4 — time bounds (L2 §5)
    if (o.delegationExpired === true) {
      return { kind: 'DENY', citedRule: 'L2 §5 Time Bounds', failureMode: 'DELEGATION_EXPIRED' };
    }

    // B5 — chain-validation invariant (L2 §5/§7.4): sub→iss line, invoker=terminal aud, attenuation
    if (o.chainInvariantViolated === true) {
      return { kind: 'DENY', citedRule: 'L2 §5/§7.4 (DL6)', failureMode: 'CHAIN_INVARIANT_VIOLATION' };
    }

    // B6 — resource-identifier match (L2 DL7/E3)
    if (o.resourceMismatch === true) {
      return { kind: 'DENY', citedRule: 'L2 DL7/E3 / master §9.7', failureMode: 'RESOURCE_MISMATCH' };
    }

    // B7 — revocation: cross-layer walk + UCAN-native blocklist + credential status + key-gen.
    // Order within B7: cross-layer chain link, then UCAN-native, then VC bit, then key-gen.
    if (o.crossLayerChainLinkRevoked === true) {
      return { kind: 'DENY', citedRule: '§6 / L2 §8 / master §9.1', failureMode: 'CROSS_LAYER_REVOKED' };
    }
    if (o.delegationRevoked === true) {
      return { kind: 'DENY', citedRule: 'L2 §8.2', failureMode: 'DELEGATION_REVOKED' };
    }
    if (o.credentialRevoked === true) {
      return { kind: 'DENY', citedRule: 'L1 §9.1 / L2 §8.1', failureMode: 'CREDENTIAL_REVOKED' };
    }
    if (o.staleEmbeddedAuthority === true) {
      return { kind: 'DENY', citedRule: 'L1 D8/§9.2', failureMode: 'STALE_EMBEDDED_AUTHORITY' };
    }

    // B8 — root principal still a verified citizen? (master §9.7; cross-protocol oracle input)
    if (o.rootPrincipalVerified === false) {
      return { kind: 'DENY', citedRule: 'master §9.7', failureMode: 'ROOT_PRINCIPAL_NO_LONGER_VERIFIED' };
    }

    // B9 — verdict
    return { kind: 'PERMIT' };
  }
}
