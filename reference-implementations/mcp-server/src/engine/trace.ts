/**
 * Sovrn Agent Protocol — MCP Server Reference Implementation
 * Verdict trace — the audit-evasion mitigation (design §10, AIP class 5).
 *
 * Every Procedure A/B run emits a step-by-step trace (step id, check outcome,
 * cited rule where a rule fired). The reference server is STATELESS, so the
 * trace is returned to the caller with the verdict; the agent-memory-board
 * (separate repo) is the durable system-of-record. Stated honestly as a seam,
 * not a hole.
 *
 * License: Apache-2.0.
 */

import type { CitedRule } from './types.js';

export interface TraceEntry {
  /** Step id in resolution-algorithm numbering ('A1'..'A9', 'B1'..'B9'). */
  step: string;
  /** What was checked (human-auditable label, no proprietary vocabulary). */
  check: string;
  /** The check outcome as observed by the engine. */
  outcome: string;
  /** The rule cited when this step decided (hard failure) or graded the verdict. */
  citedRule?: CitedRule;
}

export interface VerdictTrace {
  procedure: 'A' | 'B';
  entries: TraceEntry[];
}

/** Collects trace entries during a procedure run. */
export class TraceCollector {
  readonly trace: VerdictTrace;

  constructor(procedure: 'A' | 'B') {
    this.trace = { procedure, entries: [] };
  }

  add(step: string, check: string, outcome: string, citedRule?: CitedRule): void {
    const entry: TraceEntry = { step, check, outcome };
    if (citedRule !== undefined) entry.citedRule = citedRule;
    this.trace.entries.push(entry);
  }
}
