/**
 * Sovrn Agent Protocol — MCP Server Reference Implementation
 * Procedure A — presentation-time verification (resolution algorithm §4).
 *
 * Ordering is NORMATIVE and sequential with short-circuit on first hard
 * failure (the SHORT_CIRCUIT_ORDERING conformance fixtures test exactly this):
 *   A1 resolve DID (hard-fail, no fallback) → A2 verify every proof[] entry →
 *   A3 credential status + authority-key-generation → A5 cross-layer
 *   revocation walk → A6 issuer-trusted-list + Play/Gov seam → A7 graded
 *   reputation-epoch signal → A8 graded trust-profile → A9 verdict.
 * Checks are evaluated LAZILY one at a time — never in parallel. A hard
 * failure at step N means the step-N+1 provider is never invoked.
 *
 * License: Apache-2.0.
 */

import { RULE_FOR, GRADED_RULE } from './rules.js';
import type { CheckProviders, PresentationInput, Verdict } from './types.js';
import { TraceCollector, type VerdictTrace } from './trace.js';
import { getAgentDid, normalizeProofs } from './checks.js';

export interface ProcedureResult {
  verdict: Verdict;
  trace: VerdictTrace;
}

export async function procedureA(input: PresentationInput, p: CheckProviders): Promise<ProcedureResult> {
  const t = new TraceCollector('A');
  const reject = (failureMode: 'DID_UNRESOLVABLE' | 'SIGNATURE_INVALID' | 'CREDENTIAL_REVOKED' | 'STALE_EMBEDDED_AUTHORITY' | 'CROSS_LAYER_REVOKED'): ProcedureResult => ({
    verdict: { kind: 'REJECT', citedRule: RULE_FOR[failureMode], failureMode },
    trace: t.trace,
  });

  // A1 — resolve agent DID (Layer 0 §4, hard-fail, no auto-fallback)
  const did = getAgentDid(input.credential);
  const a1 = await p.resolveDid(did);
  t.add('A1', 'resolveAgentDID', a1, a1 === 'UNRESOLVABLE' ? RULE_FOR.DID_UNRESOLVABLE : undefined);
  if (a1 === 'UNRESOLVABLE') return reject('DID_UNRESOLVABLE');

  // A2 — verify EVERY proof[] entry (L1 §8.2). A credential with no embedded
  // proof[] (e.g. an SD-JWT-VC presentation, whose integrity is the JWS
  // envelope) gets a single envelope-level provider call.
  const proofs = normalizeProofs(input.credential);
  for (const proof of proofs.length > 0 ? proofs : [undefined]) {
    const a2 = await p.verifyCredentialProof(proof, input.credential);
    if (a2 === 'INVALID') {
      t.add('A2', 'verifySignatures', a2, RULE_FOR.SIGNATURE_INVALID);
      return reject('SIGNATURE_INVALID');
    }
  }
  t.add('A2', 'verifySignatures', 'VALID');

  // A3 — credential status (L1 §9.1) then authority-key-generation (L1 D8)
  const status = await p.credentialStatus(input.credential);
  t.add('A3', 'checkCredentialStatus', status, status === 'REVOKED' ? RULE_FOR.CREDENTIAL_REVOKED : undefined);
  if (status === 'REVOKED') return reject('CREDENTIAL_REVOKED');

  const keyGen = await p.authorityKeyGeneration(input.credential);
  t.add('A3', 'checkAuthorityKeyGeneration', keyGen, keyGen === 'STALE' ? RULE_FOR.STALE_EMBEDDED_AUTHORITY : undefined);
  if (keyGen === 'STALE') return reject('STALE_EMBEDDED_AUTHORITY');

  // A5 — cross-layer revocation walk (§6): a revoked link inside evidence[]
  // (the OR arm independent of the VC status bit, which A3 already checked)
  const walk = await p.crossLayerWalk(input.credential);
  t.add('A5', 'crossLayerRevocationWalk', walk, walk === 'REVOKED_LINK' ? RULE_FOR.CROSS_LAYER_REVOKED : undefined);
  if (walk === 'REVOKED_LINK') return reject('CROSS_LAYER_REVOKED');

  // A6 — issuer-trusted-list check (normative) + Play/Gov seam (guidance)
  const { mode, seamAmbiguous } = await p.resolveMode(input.credential);
  t.add('A6', 'resolveMode', mode, seamAmbiguous ? GRADED_RULE.PLAY_GOV_SEAM_AMBIGUOUS : undefined);

  // A7 — graded reputation-epoch signal (L3 §6 / master §9.6). Non-blocking.
  // The reputation VC is opaque here (Layer 3 out of scope); only the epoch
  // freshness signal is read. null = no reputation signal presented.
  const epoch = await p.reputationEpoch(input.reputationVC);
  let reputationStatus: 'FRESH' | 'STALE_EPOCH' | undefined;
  if (epoch !== null) {
    reputationStatus = epoch.pastValidUntil && !epoch.insideOverlapWindow ? 'STALE_EPOCH' : 'FRESH';
    t.add('A7', 'reputationEpoch', reputationStatus, reputationStatus === 'STALE_EPOCH' ? GRADED_RULE.STALE_EPOCH : undefined);
  } else {
    t.add('A7', 'reputationEpoch', 'NO_SIGNAL');
  }

  // A8 — graded trust-profile threshold (master §9.1). Non-blocking.
  const threshold = await p.trustProfileThreshold(input.credential, input.reputationVC);
  t.add('A8', 'trustProfileThreshold', threshold, threshold === 'UNMET' ? GRADED_RULE.TRUST_PROFILE_THRESHOLD_UNMET : undefined);
  const trustProfileDowngraded = threshold === 'UNMET' || seamAmbiguous ? true : undefined;

  // A9 — verdict assembly. Field-presence semantics are part of the contract:
  // absent graded fields mean "no signal", and conformance deep-equals verdicts.
  const verdict: Verdict = { kind: 'ACCEPT', mode };
  if (reputationStatus !== undefined) verdict.reputationStatus = reputationStatus;
  if (trustProfileDowngraded) verdict.trustProfileDowngraded = true;
  t.add('A9', 'verdict', 'ACCEPT');
  return { verdict, trace: t.trace };
}
