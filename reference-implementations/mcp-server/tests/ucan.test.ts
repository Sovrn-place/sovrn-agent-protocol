/**
 * UCAN 0.10 tests: genuine signed chains (1/3/5 links), signature tamper,
 * expiry, the three chain-invariant sub-cases, blocklist, unsigned rejection.
 * License: Apache-2.0.
 */

import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { verifyUcanJwtSignature, ucanTokenId, StaticBlocklist } from '../src/crypto/ucan.js';
import { chainInvariantStatus, timeBoundsStatus, getLinkPayload } from '../src/engine/checks.js';
import { makeIdentity, registryResolver, makeUcan, FAR_FUTURE } from './helpers.js';

const root = makeIdentity('did:sovrn:citizen:root');
const mid = makeIdentity('did:sovrn:agent:mid');
const leaf = makeIdentity('did:sovrn:agent:leaf');
const resolve = registryResolver([root, mid, leaf]);

const ATT_WIDE = [{ with: 'sovrn:zone:zone-a', can: 'residency/*' }];
const ATT_NARROW = [{ with: 'sovrn:zone:zone-a', can: 'residency/apply' }];

describe('UCAN signature verification', () => {
  test('genuinely signed link verifies; tampered payload fails', async () => {
    const token = makeUcan(root, { iss: root.did, aud: mid.did, sub: root.did, exp: FAR_FUTURE, att: ATT_WIDE });
    assert.equal(await verifyUcanJwtSignature(token, resolve), 'VALID');

    const [h, p, s] = token.split('.');
    const tampered = JSON.parse(Buffer.from(p, 'base64url').toString('utf8'));
    tampered.att = [{ with: 'sovrn:zone:*', can: '*' }]; // scope-widening attempt
    const forged = [h, Buffer.from(JSON.stringify(tampered)).toString('base64url'), s].join('.');
    assert.equal(await verifyUcanJwtSignature(forged, resolve), 'INVALID');
  });

  test('decoded {header,payload} objects fail closed (no signature bytes — design §10 class 4)', async () => {
    assert.equal(await verifyUcanJwtSignature({ header: {}, payload: { iss: root.did } }, resolve), 'INVALID');
  });

  test('unknown issuer fails closed', async () => {
    const stranger = makeIdentity('did:sovrn:agent:stranger');
    const token = makeUcan(stranger, { iss: stranger.did, aud: mid.did, exp: FAR_FUTURE, att: ATT_WIDE });
    assert.equal(await verifyUcanJwtSignature(token, resolve), 'INVALID');
  });
});

describe('time bounds', () => {
  test('expired and not-yet-valid links are EXPIRED; open window is WITHIN', () => {
    const now = 1_800_000_000;
    const expired = makeUcan(root, { iss: root.did, aud: mid.did, exp: now - 10, att: ATT_WIDE });
    const notYet = makeUcan(root, { iss: root.did, aud: mid.did, nbf: now + 10, exp: FAR_FUTURE, att: ATT_WIDE });
    const open = makeUcan(root, { iss: root.did, aud: mid.did, nbf: now - 10, exp: FAR_FUTURE, att: ATT_WIDE });
    assert.equal(timeBoundsStatus(getLinkPayload(expired), now), 'EXPIRED');
    assert.equal(timeBoundsStatus(getLinkPayload(notYet), now), 'EXPIRED');
    assert.equal(timeBoundsStatus(getLinkPayload(open), now), 'WITHIN');
  });
});

describe('chain-validation invariant (compact-JWT chains)', () => {
  const link1 = makeUcan(root, { iss: root.did, aud: mid.did, sub: root.did, exp: FAR_FUTURE, att: ATT_WIDE });
  const link2 = makeUcan(mid, { iss: mid.did, aud: leaf.did, sub: root.did, exp: FAR_FUTURE, att: ATT_NARROW });

  test('well-formed 2-link chain HOLDS for the terminal invoker', () => {
    assert.deepEqual(chainInvariantStatus([link1, link2], leaf.did), { status: 'HOLDS' });
  });

  test('SUB_ISS_BREAK: link issued by a principal outside the aud line', () => {
    const rogue = makeUcan(leaf, { iss: leaf.did, aud: leaf.did, sub: root.did, exp: FAR_FUTURE, att: ATT_NARROW });
    const verdict = chainInvariantStatus([link1, rogue], leaf.did);
    assert.deepEqual(verdict, { status: 'VIOLATED', violation: 'SUB_ISS_BREAK' });
  });

  test('INVOKER_AUD: invoker is not the terminal audience', () => {
    const verdict = chainInvariantStatus([link1, link2], mid.did);
    assert.deepEqual(verdict, { status: 'VIOLATED', violation: 'INVOKER_AUD' });
  });

  test('ATTENUATION: child widens beyond the parent grant', () => {
    const widened = makeUcan(mid, { iss: mid.did, aud: leaf.did, sub: root.did, exp: FAR_FUTURE, att: [{ with: 'sovrn:zone:zone-b', can: 'residency/apply' }] });
    const verdict = chainInvariantStatus([link1, widened], leaf.did);
    assert.deepEqual(verdict, { status: 'VIOLATED', violation: 'ATTENUATION' });
  });

  test('wildcard parent (sovrn:zone:*) covers concrete child resources', () => {
    const wideRoot = makeUcan(root, { iss: root.did, aud: mid.did, sub: root.did, exp: FAR_FUTURE, att: [{ with: 'sovrn:zone:*', can: '*' }] });
    assert.deepEqual(chainInvariantStatus([wideRoot, link2], leaf.did), { status: 'HOLDS' });
  });

  test('5-link chain HOLDS end to end', () => {
    const ids = [root, mid, leaf, makeIdentity('did:sovrn:agent:l4'), makeIdentity('did:sovrn:agent:l5')];
    const chain = ids.slice(0, -1).map((issuer, i) =>
      makeUcan(issuer, { iss: issuer.did, aud: ids[i + 1].did, sub: root.did, exp: FAR_FUTURE, att: ATT_NARROW }),
    );
    assert.deepEqual(chainInvariantStatus(chain, ids[ids.length - 1].did), { status: 'HOLDS' });
  });
});

describe('UCAN-native blocklist', () => {
  test('revoked token id blocks; clean token passes', async () => {
    const token = makeUcan(root, { iss: root.did, aud: mid.did, exp: FAR_FUTURE, att: ATT_WIDE });
    const blocklist = new StaticBlocklist([ucanTokenId(token)]);
    assert.equal(await blocklist.isRevoked(ucanTokenId(token)), true);
    assert.equal(await blocklist.isRevoked(ucanTokenId('other')), false);
  });
});
