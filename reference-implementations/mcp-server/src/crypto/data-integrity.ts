/**
 * Sovrn Agent Protocol — MCP Server Reference Implementation
 * W3C Data Integrity proof verification — eddsa-jcs-2022 cryptosuite.
 *
 * Verification per the cryptosuite: hashData = sha256(canonical(proofOptions))
 * || sha256(canonical(unsecuredDocument)); the Ed25519 signature in
 * `proofValue` (multibase base58btc, z-prefixed) is verified over hashData.
 * Multi-`proof` co-signing (Layer 1 D3) is handled by the ENGINE iterating
 * proof[] — this module verifies ONE proof entry.
 *
 * Canonicalization is the JCS-style sorted-key form (see jcs.ts; RFC 8785
 * number-form interop is a documented Track-2 item). BBS-2023 is the declared
 * promotion target (cryptosuite memo), NOT implemented at v0.1.0.
 *
 * License: Apache-2.0.
 */

import { createHash, createPublicKey, verify as edVerify } from 'node:crypto';
import { canonicalJson } from './jcs.js';
import { base58btcDecode } from './keys.js';

export interface DataIntegrityProof {
  type?: string;
  cryptosuite?: string;
  created?: string;
  verificationMethod?: string;
  proofPurpose?: string;
  proofValue?: string;
  '@context'?: unknown;
}

function sha256(data: string): Buffer {
  return createHash('sha256').update(data, 'utf8').digest();
}

/**
 * Verify one eddsa-jcs-2022 DataIntegrityProof over a credential.
 * `publicKeyJwk` is the issuer/co-signer key selected from the DID document
 * the proof's verificationMethod resolves to (DID resolution happens at A1
 * and in the production provider — never here).
 */
export function verifyEddsaJcs2022(
  credential: Record<string, unknown>,
  proof: DataIntegrityProof,
  publicKeyJwk: Record<string, unknown>,
): boolean {
  if (proof.type !== 'DataIntegrityProof' || proof.cryptosuite !== 'eddsa-jcs-2022') return false;
  const proofValue = proof.proofValue;
  if (typeof proofValue !== 'string' || !proofValue.startsWith('z')) return false;

  let signature: Uint8Array;
  try {
    signature = base58btcDecode(proofValue.slice(1));
  } catch {
    return false;
  }

  // unsecured document = credential minus proof
  const unsecured: Record<string, unknown> = { ...credential };
  delete unsecured.proof;

  // proof options = proof minus proofValue, with the document's @context
  const options: Record<string, unknown> = { ...proof };
  delete options.proofValue;
  if (credential['@context'] !== undefined) options['@context'] = credential['@context'];

  const hashData = Buffer.concat([sha256(canonicalJson(options)), sha256(canonicalJson(unsecured))]);

  try {
    const key = createPublicKey({ key: publicKeyJwk as never, format: 'jwk' });
    return edVerify(null, hashData, key, signature);
  } catch {
    return false;
  }
}
