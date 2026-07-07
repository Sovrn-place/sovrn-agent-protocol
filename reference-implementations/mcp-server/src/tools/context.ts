/**
 * Sovrn Agent Protocol — MCP Server Reference Implementation
 * Tool context + shared result helpers. Tools are SDK-agnostic definitions;
 * server.ts (the only SDK importer) registers them.
 *
 * License: Apache-2.0.
 */

import type { CheckProviders } from '../engine/types.js';
import type { GateResult } from '../auth/ucan-gate.js';

export interface ToolContext {
  providers: CheckProviders;
  /** The transport-independent UCAN conjunction gate (auth/ucan-gate.ts). */
  gate(toolName: string, capabilityToken: unknown): Promise<GateResult>;
}

export interface ToolTextResult {
  content: { type: 'text'; text: string }[];
  isError?: boolean;
}

export function jsonResult(value: unknown, isError = false): ToolTextResult {
  const result: ToolTextResult = { content: [{ type: 'text', text: JSON.stringify(value, null, 2) }] };
  if (isError) result.isError = true;
  return result;
}

export function gateDenied(reason: string): ToolTextResult {
  return jsonResult({ error: 'capability_denied', reason }, true);
}
