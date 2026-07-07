/**
 * Shared test helpers: genuine ed25519 identities + compact UCAN 0.10 JWT
 * construction. License: Apache-2.0.
 */

import { generateKeyPairSync, sign as edSign, type KeyObject } from 'node:crypto';
import type { UcanPayload } from '../src/engine/checks.js';

export interface TestIdentity {
  did: string;
  publicJwk: Record<string, unknown>;
  privateKey: KeyObject;
}

export function makeIdentity(did: string): TestIdentity {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return { did, publicJwk: publicKey.export({ format: 'jwk' }) as Record<string, unknown>, privateKey };
}

/** Key registry -> IssuerKeyResolver for verify functions. */
export function registryResolver(identities: TestIdentity[]): (iss: string) => Promise<Record<string, unknown>> {
  const map = new Map(identities.map((i) => [i.did, i.publicJwk]));
  return async (iss: string) => {
    const jwk = map.get(iss);
    if (!jwk) throw new Error(`unknown issuer: ${iss}`);
    return jwk;
  };
}

function b64url(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

/** Build a genuinely signed compact UCAN 0.10 JWT. */
export function makeUcan(signer: TestIdentity, payload: UcanPayload): string {
  const header = { alg: 'EdDSA', typ: 'JWT', ucv: '0.10.0' };
  const signingInput = `${b64url(header)}.${b64url(payload)}`;
  const signature = edSign(null, Buffer.from(signingInput, 'utf8'), signer.privateKey).toString('base64url');
  return `${signingInput}.${signature}`;
}

export const FAR_FUTURE = 4102444800; // 2100-01-01
