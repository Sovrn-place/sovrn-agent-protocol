/**
 * Sovrn Agent Protocol — MCP Server Reference Implementation
 * MCP tool `request_credential` — THIN ISSUANCE HANDOFF (design §5).
 *
 * The reference implementation runs NO KYC backend and issues NO credentials
 * — issuance against a KYC/attestation backend is the managed-server concern
 * (design §1.1 firewall). This tool returns a session-handoff reference the
 * caller takes to a zone's issuance endpoint (OID4VCI). It is gated in BOTH
 * gate modes: credential request is the credential-touching call the design
 * §7 conjunction quote names.
 *
 * License: Apache-2.0.
 */

import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import { jsonResult, gateDenied, type ToolContext, type ToolTextResult } from './context.js';

export const requestCredentialTool = {
  name: 'request_credential',
  title: 'Request a credential (issuance handoff)',
  description:
    'Returns an issuance-handoff reference for obtaining a Sovrn agent credential from a zone authority. ' +
    'The reference implementation is a stateless verifier: it runs no KYC and issues nothing — the handoff points the caller ' +
    'at the zone\'s own issuance endpoint (OID4VCI). Requires a UCAN capability in every gate mode.',
  inputShape: {
    agentDid: z.string().describe('The agent DID the credential is requested for (did:sovrn:agent:* primary, did:web accepted)'),
    zone: z.string().describe('The zone identifier the credential is requested from (e.g. zone-a)'),
    capabilityToken: z.string().optional().describe('UCAN capability for this call. ALWAYS required for request_credential (design §7)'),
  },
  async handler(args: { agentDid: string; zone: string; capabilityToken?: string }, ctx: ToolContext): Promise<ToolTextResult> {
    const gate = await ctx.gate('request_credential', args.capabilityToken);
    if (!gate.allowed) return gateDenied(gate.reason);

    return jsonResult({
      handoff: {
        type: 'issuance-handoff',
        sessionRef: randomUUID(),
        agentDid: args.agentDid,
        zone: args.zone,
        issuanceProtocol: 'OID4VCI',
        issuanceEndpoint: `https://${args.zone}.example/oid4vci`,
        note: 'Reference implementation: no KYC backend, no issuance. Present this handoff to the zone authority\'s issuance endpoint. Issuance against a live backend is a managed-server concern.',
      },
    });
  },
};
