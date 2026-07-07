/**
 * Sovrn Agent Protocol — MCP Server Reference Implementation
 * Conformance fixture adapter: CheckOracle → CheckProviders.
 *
 * The Step 7 fixture bundles were authored for a deterministic mock — they
 * carry `_oracle` hints, not real cryptographic material. This adapter maps
 * each bundle's oracle hints into injected CheckProviders so the 40-bundle
 * suite exercises the REAL engine (step ordering, short-circuiting, per-item
 * aggregation, verdict assembly, citedRule mapping) while the crypto leaves
 * are supplied. Real crypto is proven separately by the package's unit tests
 * against genuinely signed vectors (tests/), and the production providers are
 * shape-checked against this adapter by tests/provider-parity.test.ts.
 *
 * DISCIPLINE: this adapter returns CHECK OUTCOMES ONLY. It contains zero
 * verdict logic and cites zero rules — it is structurally incapable of
 * "helping" the engine pass. Absent oracle flags mean "the check passes"
 * (harness semantics: a well-formed positive bundle supplies no failure hints).
 *
 * Dev-only file: NOT part of the server runtime; ships with the conformance
 * runner. License: Apache-2.0.
 */

import type { CheckProviders } from '../src/engine/types.js';
import type { CheckOracle } from '../../../tests/fixtures/agent-protocol/verifier-contract.js';

export function providersFromOracle(oracle: CheckOracle | undefined): CheckProviders {
  const o: CheckOracle = oracle ?? {};
  return {
    async resolveDid() {
      return o.didResolvable === false ? 'UNRESOLVABLE' : 'RESOLVED';
    },
    async verifyCredentialProof() {
      return o.signaturesValid === false ? 'INVALID' : 'VALID';
    },
    async verifyDelegationSignature() {
      return o.signaturesValid === false ? 'INVALID' : 'VALID';
    },
    async credentialStatus() {
      return o.credentialRevoked === true ? 'REVOKED' : 'ACTIVE';
    },
    async authorityKeyGeneration() {
      return o.staleEmbeddedAuthority === true ? 'STALE' : 'CURRENT';
    },
    async crossLayerWalk() {
      return o.crossLayerChainLinkRevoked === true ? 'REVOKED_LINK' : 'CLEAR';
    },
    async linkTimeBounds() {
      return o.delegationExpired === true ? 'EXPIRED' : 'WITHIN';
    },
    async chainInvariant() {
      return o.chainInvariantViolated === true ? 'VIOLATED' : 'HOLDS';
    },
    async resourceMatch() {
      return o.resourceMismatch === true ? 'MISMATCH' : 'MATCH';
    },
    async delegationRevocation() {
      return o.delegationRevoked === true ? 'REVOKED' : 'CLEAR';
    },
    async rootPrincipalStatus() {
      return o.rootPrincipalVerified === false ? 'NOT_VERIFIED' : 'VERIFIED';
    },
    async resolveMode() {
      return { mode: o.mode ?? 'PLAY', seamAmbiguous: o.seamAmbiguous === true };
    },
    async reputationEpoch() {
      // Harness semantics: the reputation signal exists iff the oracle carries
      // reputationPastValidUntil; STALE_EPOCH requires an explicit
      // insideOverlapWindow=false (mock: pastValidUntil && insideOverlapWindow === false).
      if (o.reputationPastValidUntil === undefined) return null;
      return {
        pastValidUntil: o.reputationPastValidUntil,
        insideOverlapWindow: o.insideOverlapWindow !== false,
      };
    },
    async trustProfileThreshold() {
      return o.trustProfileThresholdMet === false ? 'UNMET' : 'MET';
    },
  };
}
