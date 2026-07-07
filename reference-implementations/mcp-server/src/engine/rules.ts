/**
 * Sovrn Agent Protocol — MCP Server Reference Implementation
 * Single source of citedRule strings (conformance JC-F3: citedRule-exact).
 *
 * NOTHING outside this module constructs a citedRule. Providers return check
 * outcomes; the procedures look failure modes up here. This is deliberate: it
 * makes the conformance fixture-adapter structurally incapable of smuggling
 * verdict logic, and it gives auditors one place to diff against the
 * resolution algorithm's §7 failure-mode table.
 *
 * License: Apache-2.0.
 */

import type { CitedRule, FailureModeB } from './types.js';

/** Hard failure modes → locking rule (resolution algorithm §7). */
export const RULE_FOR: Record<FailureModeB, CitedRule> = {
  DID_UNRESOLVABLE: 'Layer 0 §4',
  SIGNATURE_INVALID: 'L1 §8.2 / L2 §5',
  CREDENTIAL_REVOKED: 'L1 §9.1 / L2 §8.1',
  STALE_EMBEDDED_AUTHORITY: 'L1 D8/§9.2',
  CROSS_LAYER_REVOKED: '§6 / L2 §8 / master §9.1',
  DELEGATION_EXPIRED: 'L2 §5 Time Bounds',
  CHAIN_INVARIANT_VIOLATION: 'L2 §5/§7.4 (DL6)',
  RESOURCE_MISMATCH: 'L2 DL7/E3 / master §9.7',
  DELEGATION_REVOKED: 'L2 §8.2',
  ROOT_PRINCIPAL_NO_LONGER_VERIFIED: 'master §9.7',
};

/** Graded (non-blocking) signals → the rule cited in the verdict trace. */
export const GRADED_RULE = {
  STALE_EPOCH: 'L3 §6 / master §9.6',
  TRUST_PROFILE_THRESHOLD_UNMET: 'master §9.1',
  PLAY_GOV_SEAM_AMBIGUOUS: 'L3 §5 / master §9.2',
} as const satisfies Record<string, CitedRule>;
