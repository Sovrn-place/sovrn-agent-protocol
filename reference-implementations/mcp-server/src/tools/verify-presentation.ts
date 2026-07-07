/**
 * Sovrn Agent Protocol — MCP Server Reference Implementation
 * MCP tool `verify_presentation` — resolution algorithm Procedure A
 * (presentation-time). VERIFIER sense: verifies a presented credential
 * bundle. NOT a holder-side present_credential (that constructs and signs a
 * presentation, needs a holder key, and is a managed-server concern — design
 * §2.2 / §11 extension point).
 *
 * License: Apache-2.0.
 */

import { z } from 'zod';
import { procedureA } from '../engine/procedure-a.js';
import { jsonResult, gateDenied, type ToolContext, type ToolTextResult } from './context.js';

export const verifyPresentationTool = {
  name: 'verify_presentation',
  title: 'Verify a credential presentation (Procedure A)',
  description:
    'Verifies a presented Sovrn agent-credential bundle (agent identity + agent credential + optional reputation VC) ' +
    'per the resolution algorithm, Procedure A: A1 resolve DID (hard-fail, no fallback) -> A2 verify every proof[] entry -> ' +
    'A3 credential status + authority key generation -> A5 cross-layer revocation walk -> A6 issuer-trusted-list + Play/Gov seam -> ' +
    'A8 trust profile (graded) -> A9 verdict. Returns the verdict, the cited rule on rejection, and the full step trace.',
  inputShape: {
    credential: z.any().describe('The agent credential: a SovrnAgentCredential JSON object (W3C VC 2.0, multi-proof) or a compact SD-JWT-VC string'),
    reputationVC: z.any().optional().describe('Optional reputation VC. Read as an OPAQUE envelope (epoch freshness only) — Layer 3 internals are never interpreted'),
    capabilityToken: z.string().optional().describe('UCAN capability for this call (compact JWT, or a JSON array chain root-first). Required: an OAuth session alone is not sufficient'),
  },
  async handler(args: { credential: unknown; reputationVC?: unknown; capabilityToken?: string }, ctx: ToolContext): Promise<ToolTextResult> {
    const gate = await ctx.gate('verify_presentation', args.capabilityToken);
    if (!gate.allowed) return gateDenied(gate.reason);

    const { verdict, trace } = await procedureA(
      { credential: args.credential, reputationVC: args.reputationVC },
      ctx.providers,
    );
    return jsonResult({ verdict, trace, ...(gate.warning ? { warning: gate.warning } : {}) });
  },
};
