/**
 * Sovrn Agent Protocol — MCP Server Reference Implementation
 * Contract parity pins (compile-time only).
 *
 * The engine re-declares the harness Verdict/CitedRule/FailureMode types so the
 * package stays self-contained and publishable (src/ never imports from the
 * protocol repo's tests/). This file pins the two declarations together with
 * mutual-assignability asserts: if either side drifts, `npm run
 * typecheck:conformance` fails. Type-only imports — nothing here executes.
 *
 * Dev-only file: excluded from the server runtime. License: Apache-2.0.
 */

import type {
  Verdict as EngineVerdict,
  CitedRule as EngineCitedRule,
  FailureModeA as EngineFailureModeA,
  FailureModeB as EngineFailureModeB,
} from '../src/engine/types.js';
import type {
  Verdict as ContractVerdict,
  CitedRule as ContractCitedRule,
  FailureModeA as ContractFailureModeA,
  FailureModeB as ContractFailureModeB,
} from '../../../tests/fixtures/agent-protocol/verifier-contract.js';

/** Mutual assignability: A extends B AND B extends A, else `never`. */
type AssertMutual<A, B> = [A] extends [B] ? ([B] extends [A] ? true : never) : never;

export const citedRuleParity: AssertMutual<EngineCitedRule, ContractCitedRule> = true;
export const verdictParity: AssertMutual<EngineVerdict, ContractVerdict> = true;
export const failureModeAParity: AssertMutual<EngineFailureModeA, ContractFailureModeA> = true;
export const failureModeBParity: AssertMutual<EngineFailureModeB, ContractFailureModeB> = true;
