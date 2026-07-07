/**
 * Sovrn Agent Protocol — MCP Server Reference Implementation
 * SD-JWT-VC verification — the v0.1.0 cryptosuite FLOOR (cryptosuite memo:
 * SD-JWT-VC is verifiable with standard tooling today; EUDI ARF §5.3.3 names
 * it ARF-conformant).
 *
 * Verification is real: the issuer JWT signature is verified against key
 * material resolved from the issuer's DID document (via the injected
 * resolver), and disclosures are validated by @sd-jwt/sd-jwt-vc with the
 * Node hasher. Selective disclosure means withheld claims simply do not
 * appear in the verified payload.
 *
 * License: Apache-2.0.
 */

import { SDJwtVcInstance } from '@sd-jwt/sd-jwt-vc';
import { digest } from '@sd-jwt/crypto-nodejs';
import { compactVerify, importJWK } from 'jose';

export type IssuerKeyResolver = (iss: string, kid?: string) => Promise<Record<string, unknown>>;

export interface SdJwtVerifyResult {
  valid: boolean;
  /** The issuer-JWT payload (claims), when valid. */
  payload?: Record<string, unknown>;
  error?: string;
}

function b64urlJson(segment: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(segment, 'base64url').toString('utf8')) as Record<string, unknown>;
}

/** Verify a compact SD-JWT-VC (`<issuer-jwt>~<disclosure>~...~`). */
export async function verifySdJwtVc(compact: string, resolveIssuerJwk: IssuerKeyResolver): Promise<SdJwtVerifyResult> {
  try {
    const issuerJwt = compact.split('~')[0];
    const segments = issuerJwt.split('.');
    if (segments.length !== 3) return { valid: false, error: 'not a compact JWS' };

    const header = b64urlJson(segments[0]);
    const payload = b64urlJson(segments[1]);
    const iss = typeof payload.iss === 'string' ? payload.iss : undefined;
    if (!iss) return { valid: false, error: 'issuer JWT carries no iss' };

    const jwk = await resolveIssuerJwk(iss, typeof header.kid === 'string' ? header.kid : undefined);
    const key = await importJWK(jwk as Parameters<typeof importJWK>[0], typeof header.alg === 'string' ? header.alg : 'EdDSA');

    const verifier = async (data: string, signature: string): Promise<boolean> => {
      try {
        await compactVerify(`${data}.${signature}`, key);
        return true;
      } catch {
        return false;
      }
    };

    const instance = new SDJwtVcInstance({ verifier, hasher: digest });
    await instance.verify(compact);
    return { valid: true, payload };
  } catch (err) {
    return { valid: false, error: (err as Error).message };
  }
}
