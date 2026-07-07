/**
 * Sovrn Agent Protocol — MCP Server Reference Implementation
 * The per-tool-call UCAN capability gate — TRANSPORT-INDEPENDENT.
 *
 * Design §7 conjunction, verbatim: "A credential-touching tool call is
 * refused without a valid UCAN chain even when the OAuth session is valid —
 * the per-action capability is the structural confused-deputy fix; the OAuth
 * session is not a substitute." The gate runs ABOVE MCP native auth on BOTH
 * transports and is enforced in this single module so stdio cannot get a
 * weaker path.
 *
 * Capability model (documented, reference-level): each tool maps to an
 * ability `mcp/<toolName>` over the server's resource URI. The presented
 * capability token is a UCAN 0.10 compact JWT (or an ordered chain of them,
 * root first) whose terminal audience is THIS server's DID and whose terminal
 * attenuation covers the tool's ability.
 *
 * Zone-attestation conjunct: Gov-Mode-scoped operations additionally require
 * a zone attestation as an INDEPENDENT second check (memory-board JC-M1 —
 * conjunction, not embedding, so attestation revocation stays independent of
 * capability issuance). None of the three v0.1.0 reference tools is
 * Gov-scoped; the seam ships as an interface (ZoneAttestationCheck) and is
 * documented in docs/extension-points.md. No Gov Mode logic exists here.
 *
 * License: Apache-2.0.
 */

import { getLinkPayload, resourceCovers, abilityCovers, timeBoundsStatus, chainInvariantStatus, attEntries } from '../engine/checks.js';
import { verifyUcanJwtSignature, ucanTokenId, type UcanBlocklist } from '../crypto/ucan.js';
import type { IssuerKeyResolver } from '../crypto/sd-jwt.js';

/** Tool name → required ability. Single source of the tool-capability map. */
export const TOOL_ABILITY: Record<string, string> = {
  request_credential: 'mcp/request_credential',
  verify_presentation: 'mcp/verify_presentation',
  validate_delegation_chain: 'mcp/validate_delegation_chain',
};

/** Gov-Mode zone-attestation conjunct seam (extension point; see module doc). */
export interface ZoneAttestationCheck {
  verify(attestation: unknown, toolName: string): Promise<'VALID' | 'INVALID'>;
}

export interface UcanGateConfig {
  /** This server's DID — the REQUIRED terminal audience of presented capabilities. */
  serverDid?: string;
  /** The resource URI capabilities must cover (default: 'sovrn:mcp:server'). */
  resourceUri?: string;
  /**
   * 'enforce' (default): no valid capability, no tool call — the conjunction.
   * 'optional': verifier-only local evaluation convenience; calls without a
   * token are admitted WITH a warning. NEVER run 'optional' in production
   * (SECURITY.md). request_credential is enforced in BOTH modes — it is the
   * credential-touching call the design quote names.
   */
  mode?: 'enforce' | 'optional';
  resolveIssuerJwk: IssuerKeyResolver;
  blocklist?: UcanBlocklist;
  clock?: () => number;
}

export type GateResult =
  | { allowed: true; warning?: string }
  | { allowed: false; reason: string };

function parseChain(capabilityToken: unknown): unknown[] | undefined {
  if (typeof capabilityToken === 'string') {
    const trimmed = capabilityToken.trim();
    if (trimmed.startsWith('[')) {
      try {
        const arr = JSON.parse(trimmed);
        return Array.isArray(arr) ? arr : undefined;
      } catch {
        return undefined;
      }
    }
    return [trimmed];
  }
  if (Array.isArray(capabilityToken)) return capabilityToken;
  return undefined;
}

export async function checkUcanGate(
  toolName: string,
  capabilityToken: unknown,
  config: UcanGateConfig,
): Promise<GateResult> {
  const mode = config.mode ?? 'enforce';
  const ability = TOOL_ABILITY[toolName];
  if (!ability) return { allowed: false, reason: `unknown tool: ${toolName}` };

  if (capabilityToken === undefined || capabilityToken === null || capabilityToken === '') {
    if (mode === 'optional' && toolName !== 'request_credential') {
      return { allowed: true, warning: 'UCAN gate is in optional mode and no capability was presented — evaluation only, never production' };
    }
    return {
      allowed: false,
      reason: 'capability token required: a valid OAuth session alone is not sufficient for a credential-touching tool call (design §7 conjunction)',
    };
  }

  const chain = parseChain(capabilityToken);
  if (!chain || chain.length === 0) {
    return { allowed: false, reason: 'capability token is neither a compact UCAN JWT nor a JSON array chain of them' };
  }

  const clock = config.clock ?? ((): number => Math.floor(Date.now() / 1000));

  // 1 — every link's signature (reject bearer-only/unsigned: design §10 class 4)
  for (const link of chain) {
    if ((await verifyUcanJwtSignature(link, config.resolveIssuerJwk)) === 'INVALID') {
      return { allowed: false, reason: 'capability chain signature verification failed' };
    }
  }
  // 2 — time bounds per link
  for (const link of chain) {
    if (timeBoundsStatus(getLinkPayload(link), clock()) === 'EXPIRED') {
      return { allowed: false, reason: 'capability chain link outside its time bounds' };
    }
  }
  // 3 — blocklist per link (UCAN-native revocation)
  if (config.blocklist) {
    for (const link of chain) {
      if (await config.blocklist.isRevoked(ucanTokenId(link))) {
        return { allowed: false, reason: 'capability chain link is revoked' };
      }
    }
  }
  // 4 — terminal audience must be THIS server (the anti-replay / anti-confused-deputy pin)
  const terminal = getLinkPayload(chain[chain.length - 1]);
  if (!config.serverDid || terminal?.aud !== config.serverDid) {
    return { allowed: false, reason: 'capability terminal audience is not this server' };
  }
  // 5 — multi-link chains must satisfy the chain-validation invariant
  if (chain.length > 1) {
    const invariant = chainInvariantStatus(chain, config.serverDid);
    if (invariant.status === 'VIOLATED') {
      return { allowed: false, reason: `capability chain invariant violated (${invariant.violation})` };
    }
  }
  // 6 — the terminal attenuation must cover this tool's ability over the server resource
  const resource = config.resourceUri ?? 'sovrn:mcp:server';
  const atts = attEntries(terminal); // defend against a non-array att (adversarial H1)
  const covered = atts.some((att) => resourceCovers(att?.with, resource) && abilityCovers(att?.can, ability));
  if (!covered) {
    return { allowed: false, reason: `capability does not cover ${ability} on ${resource} (attenuation)` };
  }

  return { allowed: true };
}
