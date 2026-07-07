/**
 * Engine ordering tests: short-circuit sequencing, provider-call laziness,
 * graded-field presence semantics, B7 internal order.
 * License: Apache-2.0.
 */

import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { procedureA } from '../src/engine/procedure-a.js';
import { procedureB } from '../src/engine/procedure-b.js';
import type { CheckProviders } from '../src/engine/types.js';

/** All-pass providers with a call recorder; override individual checks per test. */
function stubProviders(overrides: Partial<CheckProviders>, calls: string[]): CheckProviders {
  const record = <T>(name: string, value: T) => async (): Promise<T> => {
    calls.push(name);
    return value;
  };
  return {
    resolveDid: record('resolveDid', 'RESOLVED' as const),
    verifyCredentialProof: record('verifyCredentialProof', 'VALID' as const),
    verifyDelegationSignature: record('verifyDelegationSignature', 'VALID' as const),
    credentialStatus: record('credentialStatus', 'ACTIVE' as const),
    authorityKeyGeneration: record('authorityKeyGeneration', 'CURRENT' as const),
    crossLayerWalk: record('crossLayerWalk', 'CLEAR' as const),
    linkTimeBounds: record('linkTimeBounds', 'WITHIN' as const),
    chainInvariant: record('chainInvariant', 'HOLDS' as const),
    resourceMatch: record('resourceMatch', 'MATCH' as const),
    delegationRevocation: record('delegationRevocation', 'CLEAR' as const),
    rootPrincipalStatus: record('rootPrincipalStatus', 'VERIFIED' as const),
    resolveMode: async () => {
      calls.push('resolveMode');
      return { mode: 'PLAY', seamAmbiguous: false };
    },
    reputationEpoch: async () => {
      calls.push('reputationEpoch');
      return null;
    },
    trustProfileThreshold: record('trustProfileThreshold', 'MET' as const),
    ...overrides,
  };
}

const CRED = { credentialSubject: { id: 'did:sovrn:agent:x' }, proof: [{ proofValue: 'z1' }, { proofValue: 'z2' }] };
const CHAIN = [{ header: {}, payload: { iss: 'a', aud: 'b', att: [{ with: 'sovrn:zone:zone-a', can: 'x/y' }] } }];

describe('Procedure A ordering', () => {
  test('A1 hard failure short-circuits: no later provider is invoked', async () => {
    const calls: string[] = [];
    const p = stubProviders({ resolveDid: async () => { calls.push('resolveDid'); return 'UNRESOLVABLE'; } }, calls);
    const { verdict } = await procedureA({ credential: CRED }, p);
    assert.deepEqual(verdict, { kind: 'REJECT', citedRule: 'Layer 0 §4', failureMode: 'DID_UNRESOLVABLE' });
    assert.deepEqual(calls, ['resolveDid']); // nothing after A1
  });

  test('A2 iterates EVERY proof entry (multi-proof co-signing)', async () => {
    const calls: string[] = [];
    const { verdict } = await procedureA({ credential: CRED }, stubProviders({}, calls));
    assert.equal(verdict.kind, 'ACCEPT');
    assert.equal(calls.filter((c) => c === 'verifyCredentialProof').length, 2);
  });

  test('double fault (A2 + A3): earlier failure wins', async () => {
    const calls: string[] = [];
    const p = stubProviders(
      {
        verifyCredentialProof: async () => { calls.push('verifyCredentialProof'); return 'INVALID'; },
        credentialStatus: async () => { calls.push('credentialStatus'); return 'REVOKED'; },
      },
      calls,
    );
    const { verdict } = await procedureA({ credential: CRED }, p);
    assert.equal(verdict.kind, 'REJECT');
    assert.equal((verdict as { failureMode: string }).failureMode, 'SIGNATURE_INVALID');
    assert.ok(!calls.includes('credentialStatus'));
  });

  test('graded fields are ABSENT on a clean ACCEPT (field-presence semantics)', async () => {
    const { verdict } = await procedureA({ credential: CRED }, stubProviders({}, []));
    assert.deepEqual(verdict, { kind: 'ACCEPT', mode: 'PLAY' });
    assert.ok(!('reputationStatus' in verdict));
    assert.ok(!('trustProfileDowngraded' in verdict));
  });

  test('graded signals downgrade without blocking', async () => {
    const p = stubProviders(
      {
        reputationEpoch: async () => ({ pastValidUntil: true, insideOverlapWindow: false }),
        trustProfileThreshold: async () => 'UNMET',
      },
      [],
    );
    const { verdict } = await procedureA({ credential: CRED }, p);
    assert.deepEqual(verdict, { kind: 'ACCEPT', mode: 'PLAY', reputationStatus: 'STALE_EPOCH', trustProfileDowngraded: true });
  });

  test('epoch inside the overlap window grades FRESH', async () => {
    const p = stubProviders({ reputationEpoch: async () => ({ pastValidUntil: true, insideOverlapWindow: true }) }, []);
    const { verdict } = await procedureA({ credential: CRED }, p);
    assert.deepEqual(verdict, { kind: 'ACCEPT', mode: 'PLAY', reputationStatus: 'FRESH' });
  });
});

describe('Procedure B ordering', () => {
  test('B1 hard failure short-circuits (double fault with B4)', async () => {
    const calls: string[] = [];
    const p = stubProviders(
      {
        resolveDid: async () => { calls.push('resolveDid'); return 'UNRESOLVABLE'; },
        linkTimeBounds: async () => { calls.push('linkTimeBounds'); return 'EXPIRED'; },
      },
      calls,
    );
    const { verdict } = await procedureB({ credential: CRED, delegationChain: CHAIN, targetResource: 'sovrn:zone:zone-a' }, p);
    assert.deepEqual(verdict, { kind: 'DENY', citedRule: 'Layer 0 §4', failureMode: 'DID_UNRESOLVABLE' });
    assert.deepEqual(calls, ['resolveDid']);
  });

  test('B7 internal order: cross-layer walk beats blocklist beats VC bit beats key-gen', async () => {
    const calls: string[] = [];
    const p = stubProviders(
      {
        crossLayerWalk: async () => { calls.push('crossLayerWalk'); return 'REVOKED_LINK'; },
        delegationRevocation: async () => { calls.push('delegationRevocation'); return 'REVOKED'; },
        credentialStatus: async () => { calls.push('credentialStatus'); return 'REVOKED'; },
      },
      calls,
    );
    const { verdict } = await procedureB({ credential: CRED, delegationChain: CHAIN, targetResource: 'sovrn:zone:zone-a' }, p);
    assert.equal((verdict as { failureMode: string }).failureMode, 'CROSS_LAYER_REVOKED');
    assert.ok(!calls.includes('delegationRevocation'));
    assert.ok(!calls.includes('credentialStatus'));
  });

  test('clean chain PERMITs and B8 runs last before verdict', async () => {
    const calls: string[] = [];
    const { verdict } = await procedureB({ credential: CRED, delegationChain: CHAIN, targetResource: 'sovrn:zone:zone-a' }, stubProviders({}, calls));
    assert.deepEqual(verdict, { kind: 'PERMIT' });
    assert.equal(calls[calls.length - 1], 'rootPrincipalStatus');
  });
});
