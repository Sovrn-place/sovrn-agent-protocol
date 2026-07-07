/**
 * Sovrn Agent Protocol — MCP Server Reference Implementation
 * Procedure B — invocation-time gating (resolution algorithm §5).
 *
 * Ordering is NORMATIVE and sequential with short-circuit on first failure:
 *   B1 resolve DID → B2/B3 parse + verify EVERY delegation signature →
 *   B4 time bounds per link → B5 chain-validation invariant (sub→iss line,
 *   invoker = terminal aud, attenuation) → B6 resource-identifier match →
 *   B7 revocation (order WITHIN B7: cross-layer chain link, then UCAN-native
 *   blocklist, then VC status bit, then key-generation) → B8 root principal
 *   still verified (cross-protocol; injectable at v0.1.0) → B9 verdict.
 * All failures are MUST-deny. Checks run lazily, never in parallel.
 *
 * License: Apache-2.0.
 */

import { RULE_FOR } from './rules.js';
import type { CheckProviders, FailureModeB, InvocationInput, Verdict } from './types.js';
import { TraceCollector, type VerdictTrace } from './trace.js';
import { getAgentDid, getChainLinks, terminalAttWiths } from './checks.js';

export interface ProcedureBResult {
  verdict: Verdict;
  trace: VerdictTrace;
}

export async function procedureB(input: InvocationInput, p: CheckProviders): Promise<ProcedureBResult> {
  const t = new TraceCollector('B');
  const deny = (failureMode: FailureModeB): ProcedureBResult => ({
    verdict: { kind: 'DENY', citedRule: RULE_FOR[failureMode], failureMode },
    trace: t.trace,
  });

  // B1 — resolve agent DID (Layer 0 §4, hard-fail, no auto-fallback)
  const agentDid = getAgentDid(input.credential);
  const b1 = await p.resolveDid(agentDid);
  t.add('B1', 'resolveAgentDID', b1, b1 === 'UNRESOLVABLE' ? RULE_FOR.DID_UNRESOLVABLE : undefined);
  if (b1 === 'UNRESOLVABLE') return deny('DID_UNRESOLVABLE');

  // B2/B3 — parse + verify EVERY delegation link's signature (L2 §6 / §5).
  // A chain-less invocation gets a single provider call (which fails it).
  const links = getChainLinks(input.delegationChain);
  for (const link of links.length > 0 ? links : [undefined]) {
    const b3 = await p.verifyDelegationSignature(link);
    if (b3 === 'INVALID') {
      t.add('B3', 'verifyDelegationSignatures', b3, RULE_FOR.SIGNATURE_INVALID);
      return deny('SIGNATURE_INVALID');
    }
  }
  t.add('B3', 'verifyDelegationSignatures', 'VALID');

  // B4 — time bounds on every link (L2 §5)
  for (const link of links) {
    const b4 = await p.linkTimeBounds(link);
    if (b4 === 'EXPIRED') {
      t.add('B4', 'checkTimeBounds', b4, RULE_FOR.DELEGATION_EXPIRED);
      return deny('DELEGATION_EXPIRED');
    }
  }
  t.add('B4', 'checkTimeBounds', 'WITHIN');

  // B5 — chain-validation invariant (L2 §5/§7.4, DL6): sub→iss line,
  // invoker = terminal aud, attenuation (each link ⊆ its parent)
  const b5 = await p.chainInvariant(links, agentDid);
  t.add('B5', 'chainValidationInvariant', b5, b5 === 'VIOLATED' ? RULE_FOR.CHAIN_INVARIANT_VIOLATION : undefined);
  if (b5 === 'VIOLATED') return deny('CHAIN_INVARIANT_VIOLATION');

  // B6 — resource-identifier match (L2 DL7/E3): the invocation target must be
  // covered by an att.with on the terminal link (normalizing comparator).
  let matched = false;
  for (const attWith of terminalAttWiths(links)) {
    const b6 = await p.resourceMatch(attWith, input.targetResource);
    if (b6 === 'MATCH') {
      matched = true;
      break;
    }
  }
  t.add('B6', 'resourceIdentifierMatch', matched ? 'MATCH' : 'MISMATCH', matched ? undefined : RULE_FOR.RESOURCE_MISMATCH);
  if (!matched) return deny('RESOURCE_MISMATCH');

  // B7 — revocation. Order WITHIN B7 is normative:
  // cross-layer chain link → UCAN-native blocklist → VC status bit → key-gen.
  const walk = await p.crossLayerWalk(input.credential);
  t.add('B7', 'crossLayerRevocationWalk', walk, walk === 'REVOKED_LINK' ? RULE_FOR.CROSS_LAYER_REVOKED : undefined);
  if (walk === 'REVOKED_LINK') return deny('CROSS_LAYER_REVOKED');

  for (const link of links) {
    const revoked = await p.delegationRevocation(link);
    if (revoked === 'REVOKED') {
      t.add('B7', 'checkUCANRevocation', revoked, RULE_FOR.DELEGATION_REVOKED);
      return deny('DELEGATION_REVOKED');
    }
  }
  t.add('B7', 'checkUCANRevocation', 'CLEAR');

  const status = await p.credentialStatus(input.credential);
  t.add('B7', 'checkCredentialStatus', status, status === 'REVOKED' ? RULE_FOR.CREDENTIAL_REVOKED : undefined);
  if (status === 'REVOKED') return deny('CREDENTIAL_REVOKED');

  const keyGen = await p.authorityKeyGeneration(input.credential);
  t.add('B7', 'checkAuthorityKeyGeneration', keyGen, keyGen === 'STALE' ? RULE_FOR.STALE_EMBEDDED_AUTHORITY : undefined);
  if (keyGen === 'STALE') return deny('STALE_EMBEDDED_AUTHORITY');

  // B8 — root principal still a verified citizen? (master §9.7). Cross-protocol
  // resolution is implementation-defined at v0.1.0: injectable provider,
  // oracle-injected for conformance (design §11).
  const b8 = await p.rootPrincipalStatus(links, input.credential);
  t.add('B8', 'rootPrincipalStatus', b8, b8 === 'NOT_VERIFIED' ? RULE_FOR.ROOT_PRINCIPAL_NO_LONGER_VERIFIED : undefined);
  if (b8 === 'NOT_VERIFIED') return deny('ROOT_PRINCIPAL_NO_LONGER_VERIFIED');

  // B9 — verdict
  t.add('B9', 'verdict', 'PERMIT');
  return { verdict: { kind: 'PERMIT' }, trace: t.trace };
}
