/**
 * Provider parity: the PRODUCTION providers, running on genuinely signed
 * vectors, emit the same outcome-union values the conformance fixture-adapter
 * emits — closing the "passes conformance with injected providers, diverges
 * in production" gap. Also exercises Data Integrity eddsa-jcs-2022 and the
 * BitstringStatusList decoder end to end.
 * License: Apache-2.0.
 */

import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { sign as edSign } from 'node:crypto';
import { gzipSync } from 'node:zlib';
import { createHash } from 'node:crypto';
import { canonicalJson } from '../src/crypto/jcs.js';
import { base58btcEncode } from '../src/crypto/keys.js';
import { verifyEddsaJcs2022 } from '../src/crypto/data-integrity.js';
import { readStatusBit, StaticStatusSource } from '../src/providers/status.js';
import { productionContext } from '../src/providers/production.js';
import { makeIdentity, type TestIdentity } from './helpers.js';
import type { DidDocument } from '../src/did/resolve.js';

const issuer = makeIdentity('did:sovrn:zone:zone-a');
const agentDid = 'did:sovrn:agent:550e8400-e29b-41d4-a716-446655440000';

function didDoc(identity: TestIdentity): DidDocument {
  return {
    id: identity.did,
    verificationMethod: [{ id: `${identity.did}#key-1`, type: 'JsonWebKey2020', controller: identity.did, publicKeyJwk: identity.publicJwk }],
  };
}

/** Sign a credential with a genuine eddsa-jcs-2022 DataIntegrityProof. */
function signCredential(credential: Record<string, unknown>, signer: TestIdentity): Record<string, unknown> {
  const options = {
    type: 'DataIntegrityProof',
    cryptosuite: 'eddsa-jcs-2022',
    created: '2026-07-07T00:00:00Z',
    verificationMethod: `${signer.did}#key-1`,
    proofPurpose: 'assertionMethod',
    '@context': credential['@context'],
  };
  const sha256 = (s: string) => createHash('sha256').update(s, 'utf8').digest();
  const hashData = Buffer.concat([sha256(canonicalJson(options)), sha256(canonicalJson(credential))]);
  const signature = edSign(null, hashData, signer.privateKey);
  const proof = { ...options, proofValue: `z${base58btcEncode(signature)}` };
  delete (proof as Record<string, unknown>)['@context'];
  return { ...credential, proof: [proof] };
}

const UNSIGNED = {
  '@context': ['https://www.w3.org/ns/credentials/v2', 'https://schema.sovrn.place/agent/v1'],
  id: 'urn:uuid:test-credential-1',
  type: ['VerifiableCredential', 'SovrnAgentCredential'],
  issuer: { id: issuer.did },
  validFrom: '2026-07-07T00:00:00Z',
  credentialSubject: {
    id: agentDid,
    principalDID: 'did:sovrn:citizen:7c9e6679-7425-40de-944b-e07fc1f90ae7',
    issuanceMethod: 'ZONE_ISSUED',
  },
};

describe('Data Integrity eddsa-jcs-2022 (real sign/verify roundtrip)', () => {
  test('signed credential verifies; tampered credential fails', () => {
    const signed = signCredential(UNSIGNED, issuer);
    const proof = (signed.proof as Record<string, unknown>[])[0];
    assert.equal(verifyEddsaJcs2022(signed, proof, issuer.publicJwk), true);

    const tampered = { ...signed, credentialSubject: { ...(signed.credentialSubject as object), issuanceMethod: 'SELF_ATTESTED' } };
    assert.equal(verifyEddsaJcs2022(tampered as Record<string, unknown>, proof, issuer.publicJwk), false);
  });
});

describe('BitstringStatusList decoder', () => {
  test('set bit reads REVOKED; clear bit reads ACTIVE (spec bit order)', async () => {
    const bitstring = Buffer.alloc(16);
    bitstring[0] |= 1 << (7 - 5); // index 5 set
    const encodedList = Buffer.from(gzipSync(bitstring)).toString('base64url');
    assert.equal(readStatusBit(encodedList, 5), true);
    assert.equal(readStatusBit(encodedList, 6), false);

    const listUrl = 'https://zone-a.example/status/1';
    const source = new StaticStatusSource([], { [listUrl]: encodedList });
    const revoked = { id: 'urn:uuid:c1', credentialStatus: { statusListCredential: listUrl, statusListIndex: '5' } };
    const active = { id: 'urn:uuid:c2', credentialStatus: { statusListCredential: listUrl, statusListIndex: '6' } };
    assert.equal(await source.credentialStatus(revoked), 'REVOKED');
    assert.equal(await source.credentialStatus(active), 'ACTIVE');
  });
});

describe('Production providers emit adapter-identical outcome shapes on genuine vectors', () => {
  const staticDidDocuments = {
    [issuer.did]: didDoc(issuer),
    [agentDid]: { id: agentDid, verificationMethod: [{ id: `${agentDid}#key-1`, publicKeyJwk: makeIdentity(agentDid).publicJwk }] },
  };
  const fixedClock = () => 1_800_000_000; // 2027-01-15ish

  test('resolveDid: RESOLVED via static store; UNRESOLVABLE for unsupported method (no fallback)', async () => {
    const { providers } = productionContext({ staticDidDocuments });
    assert.equal(await providers.resolveDid(agentDid), 'RESOLVED');
    assert.equal(await providers.resolveDid('did:key:z6Mk'), 'UNRESOLVABLE');
    assert.equal(await providers.resolveDid(undefined), 'UNRESOLVABLE');
  });

  test('verifyCredentialProof: VALID on the genuinely signed proof, INVALID on tamper', async () => {
    const { providers } = productionContext({ staticDidDocuments });
    const signed = signCredential(UNSIGNED, issuer);
    const proof = (signed.proof as unknown[])[0];
    assert.equal(await providers.verifyCredentialProof(proof, signed), 'VALID');

    const tampered = { ...signed, validFrom: '2020-01-01T00:00:00Z' };
    assert.equal(await providers.verifyCredentialProof(proof, tampered), 'INVALID');
  });

  test('resourceMatch honors the trailing-slash boundary (RESOURCE_IDENTIFIER_BOUNDARY semantics)', async () => {
    const { providers } = productionContext({});
    assert.equal(await providers.resourceMatch('sovrn:zone:zone-a', 'sovrn:zone:zone-a/'), 'MATCH');
    assert.equal(await providers.resourceMatch('sovrn:zone:zone-a', 'sovrn:zone:zone-b'), 'MISMATCH');
  });

  test('reputationEpoch reads ONLY the opaque envelope validity window', async () => {
    const { providers } = productionContext({ clock: fixedClock, epochOverlapSeconds: 3600 });
    assert.equal(await providers.reputationEpoch(undefined), null);
    assert.equal(await providers.reputationEpoch({ tierIrrelevant: true }), null); // no validUntil -> no signal

    const boundary = new Date((fixedClock() - 60) * 1000).toISOString(); // 60s past
    const signal = await providers.reputationEpoch({ validUntil: boundary });
    assert.deepEqual(signal, { pastValidUntil: true, insideOverlapWindow: true }); // inside the 3600s overlap
  });

  test('resolveMode: GOV needs BOTH signals; ZONE_ISSUED without a trusted issuer is the ambiguous seam', async () => {
    const { providers } = productionContext({ trustedIssuers: [issuer.did] });
    assert.deepEqual(await providers.resolveMode(UNSIGNED), { mode: 'GOV', seamAmbiguous: false });

    const untrusted = { ...UNSIGNED, issuer: { id: 'did:sovrn:zone:zone-x' } };
    assert.deepEqual(await providers.resolveMode(untrusted), { mode: 'PLAY', seamAmbiguous: true });

    const selfAttested = { ...UNSIGNED, credentialSubject: { ...UNSIGNED.credentialSubject, issuanceMethod: 'SELF_ATTESTED' } };
    assert.deepEqual(await providers.resolveMode(selfAttested), { mode: 'PLAY', seamAmbiguous: false });
  });

  test('trustProfileThreshold ranks issuance methods against the configured floor', async () => {
    const { providers } = productionContext({ minIssuanceMethod: 'COMMUNITY_ATTESTED' });
    assert.equal(await providers.trustProfileThreshold(UNSIGNED, undefined), 'MET'); // ZONE_ISSUED >= floor
    const self = { ...UNSIGNED, credentialSubject: { ...UNSIGNED.credentialSubject, issuanceMethod: 'SELF_ATTESTED' } };
    assert.equal(await providers.trustProfileThreshold(self, undefined), 'UNMET'); // the Sybil-floor downgrade
  });

  test('crossLayerWalk flags a revoked embedded evidence link', async () => {
    const { providers } = productionContext({ revokedEvidenceLinkIds: ['urn:ucan:revoked-link-1'] });
    const cred = { ...UNSIGNED, credentialSubject: { ...UNSIGNED.credentialSubject, evidence: [{ id: 'urn:ucan:revoked-link-1' }] } };
    assert.equal(await providers.crossLayerWalk(cred), 'REVOKED_LINK');
    assert.equal(await providers.crossLayerWalk(UNSIGNED), 'CLEAR');
  });

  test('authorityKeyGeneration: embedded generation older than the authority current -> STALE', async () => {
    const { providers } = productionContext({ authorityKeyGenerations: { [issuer.did]: 3 } });
    const stale = { ...UNSIGNED, credentialSubject: { ...UNSIGNED.credentialSubject, authorityKeyGeneration: 2 } };
    const current = { ...UNSIGNED, credentialSubject: { ...UNSIGNED.credentialSubject, authorityKeyGeneration: 3 } };
    assert.equal(await providers.authorityKeyGeneration(stale), 'STALE');
    assert.equal(await providers.authorityKeyGeneration(current), 'CURRENT');
    assert.equal(await providers.authorityKeyGeneration(UNSIGNED), 'CURRENT'); // no embedded generation claim
  });
});
