/**
 * SD-JWT-VC tests: genuine ed25519 sign + verify roundtrip, tamper detection,
 * selective disclosure (withheld claims absent from the verified payload).
 * License: Apache-2.0.
 */

import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign as edSign } from 'node:crypto';
import { SDJwtVcInstance } from '@sd-jwt/sd-jwt-vc';
import { digest, generateSalt } from '@sd-jwt/crypto-nodejs';
import { verifySdJwtVc } from '../src/crypto/sd-jwt.js';

const ISSUER_DID = 'did:sovrn:zone:zone-a';
const { publicKey, privateKey } = generateKeyPairSync('ed25519');
const issuerJwk = publicKey.export({ format: 'jwk' }) as Record<string, unknown>;

const resolveIssuerJwk = async (iss: string): Promise<Record<string, unknown>> => {
  if (iss !== ISSUER_DID) throw new Error(`unknown issuer ${iss}`);
  return issuerJwk;
};

async function issueSdJwtVc(claims: Record<string, unknown>, disclosureFrame: { _sd: string[] }): Promise<string> {
  const issuer = new SDJwtVcInstance({
    signer: async (data: string) => edSign(null, Buffer.from(data, 'utf8'), privateKey).toString('base64url'),
    signAlg: 'EdDSA',
    hasher: digest,
    saltGenerator: generateSalt,
  });
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return issuer.issue(claims as any, disclosureFrame as any);
}

const BASE_CLAIMS = {
  vct: 'https://schema.sovrn.place/agent/v1',
  iss: ISSUER_DID,
  iat: Math.floor(Date.now() / 1000),
  agentType: 'SUPERVISED',
  principalDID: 'did:sovrn:citizen:7c9e6679-7425-40de-944b-e07fc1f90ae7',
  issuanceMethod: 'ZONE_ISSUED',
};

describe('SD-JWT-VC verification (v0.1.0 crypto floor)', () => {
  test('sign -> verify roundtrip succeeds against the issuer DID key', async () => {
    const compact = await issueSdJwtVc(BASE_CLAIMS, { _sd: ['principalDID'] });
    const result = await verifySdJwtVc(compact, resolveIssuerJwk);
    assert.equal(result.valid, true, result.error);
    assert.equal(result.payload?.iss, ISSUER_DID);
  });

  test('selective disclosure: the disclosed set travels as disclosures, not plaintext claims', async () => {
    const compact = await issueSdJwtVc(BASE_CLAIMS, { _sd: ['principalDID'] });
    const issuerJwtPayload = JSON.parse(Buffer.from(compact.split('~')[0].split('.')[1], 'base64url').toString('utf8'));
    assert.equal(issuerJwtPayload.principalDID, undefined); // withheld from the JWT body
    assert.ok(Array.isArray(issuerJwtPayload._sd) && issuerJwtPayload._sd.length > 0);
  });

  test('tampered payload fails verification', async () => {
    const compact = await issueSdJwtVc(BASE_CLAIMS, { _sd: [] });
    const [jwt, ...rest] = compact.split('~');
    const [h, p, s] = jwt.split('.');
    const tamperedPayload = JSON.parse(Buffer.from(p, 'base64url').toString('utf8'));
    tamperedPayload.agentType = 'AUTONOMOUS';
    const tampered = [
      [h, Buffer.from(JSON.stringify(tamperedPayload)).toString('base64url'), s].join('.'),
      ...rest,
    ].join('~');
    const result = await verifySdJwtVc(tampered, resolveIssuerJwk);
    assert.equal(result.valid, false);
  });

  test('unknown issuer fails closed', async () => {
    const compact = await issueSdJwtVc({ ...BASE_CLAIMS, iss: 'did:sovrn:zone:zone-b' }, { _sd: [] });
    const result = await verifySdJwtVc(compact, resolveIssuerJwk);
    assert.equal(result.valid, false);
  });
});
