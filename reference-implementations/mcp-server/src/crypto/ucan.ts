/**
 * Sovrn Agent Protocol — MCP Server Reference Implementation
 * UCAN delegation-link verification — 0.10 JWT-shaped accepted-input.
 *
 * Design-of-record (Layer 2): UCAN 1.0-rc.1 (DAG-CBOR/IPLD) is NORMATIVE on
 * the wire and 0.10 JWT is ACCEPTED-INPUT. At v0.1.0 the reference impl
 * verifies the 0.10 JWT wire for real; DAG-CBOR decoding is a DOCUMENTED
 * EXTENSION POINT (design §11 — the conformance fixture for it ships xfail).
 *
 * Production accepts compact JWT strings on the wire. A decoded
 * { header, payload } JSON object (the draft schema shape) carries no
 * signature bytes and therefore CANNOT be cryptographically verified — the
 * production provider fails it closed (reject bearer-only/unsigned
 * delegations: design §10 class 4).
 *
 * License: Apache-2.0.
 */

import { createHash } from 'node:crypto';
import { compactVerify, importJWK } from 'jose';
import { canonicalJson } from './jcs.js';
import type { IssuerKeyResolver } from './sd-jwt.js';

function b64urlJson(segment: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(segment, 'base64url').toString('utf8')) as Record<string, unknown>;
}

/** Verify ONE UCAN 0.10 compact-JWT link's signature against its iss key. */
export async function verifyUcanJwtSignature(link: unknown, resolveIssuerJwk: IssuerKeyResolver): Promise<'VALID' | 'INVALID'> {
  if (typeof link !== 'string') return 'INVALID'; // no signature bytes -> fail closed
  const segments = link.split('.');
  if (segments.length !== 3) return 'INVALID';
  try {
    const header = b64urlJson(segments[0]);
    const payload = b64urlJson(segments[1]);
    const iss = typeof payload.iss === 'string' ? payload.iss : undefined;
    if (!iss) return 'INVALID';
    const jwk = await resolveIssuerJwk(iss, typeof header.kid === 'string' ? header.kid : undefined);
    const key = await importJWK(jwk as Parameters<typeof importJWK>[0], typeof header.alg === 'string' ? header.alg : 'EdDSA');
    await compactVerify(link, key);
    return 'VALID';
  } catch {
    return 'INVALID';
  }
}

export function sha256Hex(input: string): string {
  return createHash('sha256').update(input, 'utf8').digest('hex');
}

/**
 * Stable identifier for a delegation link, used as the UCAN-native blocklist
 * key. For the 0.10 JWT accepted-input this is sha256 of the compact token
 * (decoded shapes hash their canonical JSON). CID-based identifiers arrive
 * with the 1.0-rc.1 DAG-CBOR wire (extension point).
 */
export function ucanTokenId(link: unknown): string {
  if (typeof link === 'string') return sha256Hex(link);
  return sha256Hex(canonicalJson(link));
}

export interface UcanBlocklist {
  isRevoked(tokenId: string): Promise<boolean>;
}

/** Static blocklist (config-injected). A live revocation feed is integrator config. */
export class StaticBlocklist implements UcanBlocklist {
  private readonly revoked: Set<string>;

  constructor(revokedTokenIds: string[] = []) {
    this.revoked = new Set(revokedTokenIds);
  }

  async isRevoked(tokenId: string): Promise<boolean> {
    return this.revoked.has(tokenId);
  }
}

/** UCAN 1.0-rc.1 DAG-CBOR wire decoding — documented v0.1.0 extension point. */
export function decodeDagCborUcan(): never {
  throw new Error('UCAN 1.0-rc.1 DAG-CBOR wire decoding is a documented v0.1.0 extension point (design §11); not implemented');
}
