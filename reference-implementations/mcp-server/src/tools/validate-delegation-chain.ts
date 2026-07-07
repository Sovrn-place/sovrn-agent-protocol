/**
 * Sovrn Agent Protocol — MCP Server Reference Implementation
 * MCP tool `validate_delegation_chain` — resolution algorithm Procedure B
 * (invocation-time). Gates a UCAN-chain invocation: the chain is taken AS
 * INPUT (a verifier does not fetch it from any memory board — design §2).
 *
 * License: Apache-2.0.
 */

import { z } from 'zod';
import { procedureB } from '../engine/procedure-b.js';
import { jsonResult, gateDenied, type ToolContext, type ToolTextResult } from './context.js';

export const validateDelegationChainTool = {
  name: 'validate_delegation_chain',
  title: 'Validate a UCAN delegation chain (Procedure B)',
  description:
    'Gates a UCAN-chain invocation per the resolution algorithm, Procedure B: B1 resolve DID -> B2/B3 parse + verify every ' +
    'delegation signature -> B4 time bounds -> B5 chain-validation invariant (sub->iss line, invoker = terminal aud, attenuation) -> ' +
    'B6 resource-identifier match -> B7 revocation (cross-layer walk + UCAN blocklist + credential status + key generation) -> ' +
    'B8 root-principal-still-verified -> B9 verdict. Returns permit/deny, the cited rule on denial, and the full step trace.',
  inputShape: {
    credential: z.any().describe('The agent credential (with its evidence[] chain) the invocation rides on'),
    delegationChain: z.any().describe('The UCAN delegation chain, root first: compact 0.10 JWTs (wire) or decoded {header,payload} objects (schema shape)'),
    targetResource: z.string().optional().describe('The invocation target resource (sovrn: URI) matched against the terminal att.with'),
    capabilityToken: z.string().optional().describe('UCAN capability for this call (compact JWT, or a JSON array chain root-first). Required: an OAuth session alone is not sufficient'),
  },
  async handler(
    args: { credential: unknown; delegationChain: unknown; targetResource?: string; capabilityToken?: string },
    ctx: ToolContext,
  ): Promise<ToolTextResult> {
    const gate = await ctx.gate('validate_delegation_chain', args.capabilityToken);
    if (!gate.allowed) return gateDenied(gate.reason);

    const { verdict, trace } = await procedureB(
      { credential: args.credential, delegationChain: args.delegationChain, targetResource: args.targetResource },
      ctx.providers,
    );
    return jsonResult({ verdict, trace, ...(gate.warning ? { warning: gate.warning } : {}) });
  },
};
