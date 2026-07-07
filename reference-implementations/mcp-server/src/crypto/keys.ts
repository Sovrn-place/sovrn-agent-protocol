/**
 * Sovrn Agent Protocol — MCP Server Reference Implementation
 * Key material helpers: DID verification method → usable public key.
 *
 * Supports publicKeyJwk (preferred) and Ed25519 publicKeyMultibase (Multikey,
 * base58btc `z...` with the 0xed01 multicodec prefix). No other encodings at
 * v0.1.0. License: Apache-2.0.
 */

import { importJWK, type CryptoKey as JoseKey } from 'jose';
import type { DidVerificationMethod } from '../did/resolve.js';

// base58btc alphabet (Bitcoin)
const B58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const B58_MAP = new Map([...B58_ALPHABET].map((c, i) => [c, i]));

/** Decode a base58btc string to bytes. */
export function base58btcDecode(input: string): Uint8Array {
  let bytes: number[] = [0];
  for (const char of input) {
    const value = B58_MAP.get(char);
    if (value === undefined) throw new Error(`invalid base58btc character: ${char}`);
    let carry = value;
    for (let i = 0; i < bytes.length; i++) {
      const x = bytes[i] * 58 + carry;
      bytes[i] = x & 0xff;
      carry = x >> 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  // leading zeros
  for (const char of input) {
    if (char !== '1') break;
    bytes.push(0);
  }
  return Uint8Array.from(bytes.reverse());
}

/** Encode bytes as base58btc (used by tests to construct proofValue vectors). */
export function base58btcEncode(input: Uint8Array): string {
  let digits: number[] = [0];
  for (const byte of input) {
    let carry = byte;
    for (let i = 0; i < digits.length; i++) {
      const x = digits[i] * 256 + carry;
      digits[i] = x % 58;
      carry = Math.floor(x / 58);
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }
  let output = '';
  for (const byte of input) {
    if (byte !== 0) break;
    output += '1';
  }
  for (let i = digits.length - 1; i >= 0; i--) output += B58_ALPHABET[digits[i]];
  return output;
}

const ED25519_MULTICODEC = Uint8Array.from([0xed, 0x01]);

/** Extract the raw Ed25519 public key bytes from a Multikey publicKeyMultibase. */
export function ed25519FromMultibase(publicKeyMultibase: string): Uint8Array {
  if (!publicKeyMultibase.startsWith('z')) {
    throw new Error('publicKeyMultibase must be base58btc (z-prefixed)');
  }
  const decoded = base58btcDecode(publicKeyMultibase.slice(1));
  if (decoded.length !== 34 || decoded[0] !== ED25519_MULTICODEC[0] || decoded[1] !== ED25519_MULTICODEC[1]) {
    throw new Error('publicKeyMultibase is not an Ed25519 Multikey (0xed01 prefix expected)');
  }
  return decoded.slice(2);
}

function base64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url');
}

/** Import a verification method's public key for jose (EdDSA at v0.1.0). */
export async function importVerificationKey(method: DidVerificationMethod): Promise<JoseKey> {
  if (method.publicKeyJwk) {
    return (await importJWK(method.publicKeyJwk as Parameters<typeof importJWK>[0], 'EdDSA')) as JoseKey;
  }
  if (method.publicKeyMultibase) {
    const raw = ed25519FromMultibase(method.publicKeyMultibase);
    return (await importJWK({ kty: 'OKP', crv: 'Ed25519', x: base64url(raw) }, 'EdDSA')) as JoseKey;
  }
  throw new Error(`verification method ${method.id} carries no supported key material`);
}
