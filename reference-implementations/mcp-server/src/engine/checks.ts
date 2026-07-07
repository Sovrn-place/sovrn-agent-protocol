/**
 * Sovrn Agent Protocol — MCP Server Reference Implementation
 * Pure structural check helpers shared by the engine and the production
 * providers. No I/O, no crypto — crypto lives behind CheckProviders.
 *
 * License: Apache-2.0.
 */

// ---------------------------------------------------------------------------
// Credential structure
// ---------------------------------------------------------------------------

/**
 * Normalize the credential's proof to an array.
 * The locked schema (Layer 1 D3) makes `proof` an ARRAY (multi-proof
 * co-signing); the draft schema still carries a single object (the JC-F2
 * reconciliation is open at Step 9). The verifier accepts both and treats a
 * single object as a one-entry array. An SD-JWT-VC presentation carries no
 * embedded proof[] — its integrity is the JWS envelope (returns []).
 */
export function normalizeProofs(credential: unknown): unknown[] {
  const proof = (credential as { proof?: unknown } | null | undefined)?.proof;
  if (proof === undefined || proof === null) return [];
  return Array.isArray(proof) ? proof : [proof];
}

/** The agent DID Procedure A/B resolves at step 1: credentialSubject.id. */
export function getAgentDid(credential: unknown): string | undefined {
  const subject = (credential as { credentialSubject?: { id?: unknown } } | null | undefined)?.credentialSubject;
  const id = subject?.id;
  return typeof id === 'string' ? id : undefined;
}

// ---------------------------------------------------------------------------
// Delegation-chain structure (UCAN 0.10 JWT-shaped accepted input)
// ---------------------------------------------------------------------------

export interface UcanPayload {
  iss?: string;
  aud?: string;
  sub?: string;
  nbf?: number;
  exp?: number;
  att?: { with?: string; can?: string; constraints?: Record<string, unknown> }[];
  prf?: unknown[];
}

/** Normalize the delegation chain to an ordered array of links (root first). */
export function getChainLinks(delegationChain: unknown): unknown[] {
  if (delegationChain === undefined || delegationChain === null) return [];
  return Array.isArray(delegationChain) ? delegationChain : [delegationChain];
}

/**
 * Extract a link's UCAN payload. Accepts the decoded { header, payload } wire
 * shape (the draft delegation-token schema) or a compact JWS string
 * (header.payload.signature — base64url). DAG-CBOR (UCAN 1.0-rc.1) decoding is
 * a documented extension point, NOT implemented at v0.1.0 (design §11).
 */
export function getLinkPayload(link: unknown): UcanPayload | undefined {
  if (link === null || link === undefined) return undefined;
  if (typeof link === 'string') {
    const parts = link.split('.');
    if (parts.length !== 3) return undefined;
    try {
      const json = Buffer.from(parts[1], 'base64url').toString('utf8');
      const parsed = JSON.parse(json) as unknown;
      // A compact JWS payload must decode to a non-null object; JSON null,
      // arrays, and scalars are not valid payloads (else downstream field
      // access throws on `null`/non-object — adversarial M7).
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return undefined;
      return parsed as UcanPayload;
    } catch {
      return undefined;
    }
  }
  const payload = (link as { payload?: unknown }).payload;
  if (payload && typeof payload === 'object' && !Array.isArray(payload)) return payload as UcanPayload;
  return undefined;
}

/** The `att` entries of a payload, defended against a non-array `att` (adversarial H1). */
export function attEntries(payload: UcanPayload | undefined): NonNullable<UcanPayload['att']> {
  const att = payload?.att;
  return Array.isArray(att) ? att : [];
}

/** Time-bounds check for one link payload against a clock (seconds since epoch). */
export function timeBoundsStatus(payload: UcanPayload | undefined, nowSeconds: number): 'WITHIN' | 'EXPIRED' {
  if (!payload) return 'EXPIRED';
  // A present-but-non-numeric exp/nbf must not be silently ignored (a string
  // `exp` would otherwise read as non-expiring — adversarial M6): treat a
  // malformed bound as EXPIRED (fail closed).
  if (payload.exp !== undefined) {
    if (typeof payload.exp !== 'number' || Number.isNaN(payload.exp)) return 'EXPIRED';
    if (nowSeconds >= payload.exp) return 'EXPIRED';
  }
  if (payload.nbf !== undefined) {
    if (typeof payload.nbf !== 'number' || Number.isNaN(payload.nbf)) return 'EXPIRED';
    if (nowSeconds < payload.nbf) return 'EXPIRED';
  }
  return 'WITHIN';
}

// ---------------------------------------------------------------------------
// Resource-identifier matching (L2 DL7/E3)
// ---------------------------------------------------------------------------

/**
 * Normalize a `sovrn:` resource identifier for comparison: trim whitespace and
 * trailing slashes. Per the RESOURCE_IDENTIFIER_BOUNDARY conformance fixture,
 * a trailing slash is NOT a different resource.
 */
export function normalizeResource(resource: string): string {
  return resource.trim().replace(/\/+$/, '');
}

/** Whether a parent resource identifier covers a child (equality or `:*` wildcard). */
export function resourceCovers(parentWith: string | undefined, childWith: string | undefined): boolean {
  if (parentWith === undefined || childWith === undefined) return false;
  const parent = normalizeResource(parentWith);
  const child = normalizeResource(childWith);
  if (parent === child) return true;
  if (parent.endsWith(':*')) return child.startsWith(parent.slice(0, -1));
  return false;
}

/** Exact (normalized) resource match for B6 — the invocation target vs att.with. */
export function resourceMatches(attWith: string | undefined, targetResource: string | undefined): boolean {
  if (attWith === undefined || targetResource === undefined) return false;
  return normalizeResource(attWith) === normalizeResource(targetResource);
}

/** All att.with values on the chain's terminal link (the invoked capability set). */
export function terminalAttWiths(chain: unknown[]): (string | undefined)[] {
  const terminal = getLinkPayload(chain[chain.length - 1]);
  const atts = terminal?.att;
  if (!Array.isArray(atts) || atts.length === 0) return [undefined];
  return atts.map((a) => (typeof a?.with === 'string' ? a.with : undefined));
}

// ---------------------------------------------------------------------------
// Chain-validation invariant (L2 §5/§7.4, DL6 — the Karp confused-deputy rule)
// ---------------------------------------------------------------------------

/** Whether a parent ability covers a child ability (equality or `*`). */
export function abilityCovers(parentCan: string | undefined, childCan: string | undefined): boolean {
  if (parentCan === undefined || childCan === undefined) return false;
  if (parentCan === '*') return true;
  if (parentCan === childCan) return true;
  // namespace wildcard: "residency/*" covers "residency/apply"
  if (parentCan.endsWith('/*')) return childCan.startsWith(parentCan.slice(0, -1));
  return false;
}

export type ChainInvariantViolation = 'SUB_ISS_BREAK' | 'INVOKER_AUD' | 'ATTENUATION';

/**
 * The three-part chain-validation invariant, chain ordered root-first:
 *  1. sub→iss line: each non-root link's iss equals its parent's aud, and the
 *     explicit sub (Powerline rejected — L2 DL5) is constant down the chain.
 *  2. invoker = terminal aud.
 *  3. attenuation: every child att entry is covered by some parent att entry
 *     (resource + ability; each link ⊆ its parent).
 */
export function chainInvariantStatus(
  chain: unknown[],
  invokerDid: string | undefined,
): { status: 'HOLDS' } | { status: 'VIOLATED'; violation: ChainInvariantViolation } {
  const payloads = chain.map(getLinkPayload);
  if (payloads.length === 0 || payloads.some((p) => p === undefined)) {
    return { status: 'VIOLATED', violation: 'SUB_ISS_BREAK' };
  }
  const links = payloads as UcanPayload[];

  // 1 — sub→iss line + constant explicit sub
  const rootSub = links[0].sub;
  for (let i = 1; i < links.length; i++) {
    if (links[i].iss !== links[i - 1].aud) return { status: 'VIOLATED', violation: 'SUB_ISS_BREAK' };
    if (links[i].sub !== undefined && rootSub !== undefined && links[i].sub !== rootSub) {
      return { status: 'VIOLATED', violation: 'SUB_ISS_BREAK' };
    }
  }

  // 2 — invoker = terminal aud
  const terminalAud = links[links.length - 1].aud;
  if (invokerDid === undefined || terminalAud !== invokerDid) {
    return { status: 'VIOLATED', violation: 'INVOKER_AUD' };
  }

  // 3 — attenuation: each link's att ⊆ its parent's att
  for (let i = 1; i < links.length; i++) {
    const parentAtts = attEntries(links[i - 1]);
    const childAtts = attEntries(links[i]);
    for (const child of childAtts) {
      const covered = parentAtts.some(
        (parent) => resourceCovers(parent?.with, child?.with) && abilityCovers(parent?.can, child?.can),
      );
      if (!covered) return { status: 'VIOLATED', violation: 'ATTENUATION' };
    }
  }

  return { status: 'HOLDS' };
}
