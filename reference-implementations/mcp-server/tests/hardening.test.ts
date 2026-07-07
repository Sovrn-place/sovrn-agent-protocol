/**
 * Adversarial-hardening regression tests (2026-07-07 pre-publication review).
 * Each test pins a fix for a finding so a future edit cannot silently
 * reintroduce a crash-where-a-DENY-is-promised or an auth/soundness gap.
 * License: Apache-2.0.
 */

import { describe, test, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type Server } from 'node:http';
import { gzipSync } from 'node:zlib';

import {
  getLinkPayload,
  timeBoundsStatus,
  chainInvariantStatus,
  attEntries,
} from '../src/engine/checks.js';
import { canonicalJson, MAX_CANONICAL_DEPTH } from '../src/crypto/jcs.js';
import { checkUcanGate } from '../src/auth/ucan-gate.js';
import { OAuthValidator } from '../src/auth/oauth.js';
import { readStatusBit, StaticStatusSource } from '../src/providers/status.js';
import { productionContext } from '../src/providers/production.js';
import { readCredentialMetadata } from '../src/resources/credential-metadata.js';
import { didWebToUrl, resolveDidDocument, DidResolutionError } from '../src/did/resolve.js';
import { makeIdentity, registryResolver, makeUcan, FAR_FUTURE } from './helpers.js';

const servers: Server[] = [];
after(() => {
  for (const s of servers) s.close();
});
function serve(handler: (req: import('node:http').IncomingMessage, res: import('node:http').ServerResponse) => void): Promise<number> {
  return new Promise((resolve) => {
    const s = createServer(handler);
    servers.push(s);
    s.listen(0, '127.0.0.1', () => resolve((s.address() as { port: number }).port));
  });
}

const server = makeIdentity('did:sovrn:agent:reference-server');
const user = makeIdentity('did:sovrn:citizen:user');
const resolve = registryResolver([user]);
function cap(att: unknown): string {
  return makeUcan(user, { iss: user.did, aud: server.did, sub: user.did, exp: FAR_FUTURE, att: att as never });
}

describe('H1 — non-array att never throws (clean DENY / VIOLATED)', () => {
  test('capability gate DENIES a token whose att is an object, no throw', async () => {
    const token = cap({ with: 'sovrn:mcp:server', can: 'mcp/verify_presentation' }); // object, not array
    const result = await checkUcanGate('verify_presentation', token, { serverDid: server.did, resolveIssuerJwk: resolve, mode: 'enforce' });
    assert.equal(result.allowed, false);
  });
  test('chainInvariantStatus does not throw on a non-array att', () => {
    const link = { payload: { iss: 'a', aud: 'b', sub: 'a', att: 'not-an-array' } };
    assert.doesNotThrow(() => chainInvariantStatus([link], 'b'));
  });
  test('attEntries coerces non-arrays to []', () => {
    assert.deepEqual(attEntries({ att: { x: 1 } } as never), []);
    assert.deepEqual(attEntries(undefined), []);
  });
});

describe('H2 — canonicalJson depth cap (no stack overflow)', () => {
  function deep(n: number): unknown {
    let o: unknown = 1;
    for (let i = 0; i < n; i++) o = { a: o };
    return o;
  }
  test('throws a bounded error past the depth cap, not RangeError', () => {
    assert.throws(() => canonicalJson(deep(MAX_CANONICAL_DEPTH + 50)), /maximum nesting depth/);
  });
  test('crossLayerWalk fails CLOSED (REVOKED_LINK) on a deep evidence entry, no throw', async () => {
    const { providers } = productionContext({});
    const credential = { credentialSubject: { evidence: [deep(MAX_CANONICAL_DEPTH + 50)] } };
    const outcome = await providers.crossLayerWalk(credential);
    assert.equal(outcome, 'REVOKED_LINK');
  });
});

describe('M4/M5 — status list fails closed', () => {
  test('readStatusBit rejects a negative or non-integer index (no silent ACTIVE)', () => {
    const list = Buffer.from(gzipSync(Buffer.alloc(8))).toString('base64url');
    assert.throws(() => readStatusBit(list, -1), /non-negative integer/);
    assert.throws(() => readStatusBit(list, 3.7), /non-negative integer/);
  });
  test('credentialStatus returns REVOKED (fail-closed) on an undecodable list', async () => {
    const src = new StaticStatusSource([], { 'https://z/list': 'not-gzip-bytes!!' });
    const cred = { id: 'urn:c', credentialStatus: { statusListCredential: 'https://z/list', statusListIndex: '0' } };
    assert.equal(await src.credentialStatus(cred), 'REVOKED');
  });
});

describe('M6 — non-numeric exp/nbf is EXPIRED (fail closed)', () => {
  test('a string exp does not read as non-expiring', () => {
    const link = { payload: { iss: 'a', aud: 'b', exp: '99999999999' } };
    assert.equal(timeBoundsStatus(getLinkPayload(link), 1_800_000_000), 'EXPIRED');
  });
  test('a numeric future exp is WITHIN', () => {
    const link = { payload: { iss: 'a', aud: 'b', exp: FAR_FUTURE } };
    assert.equal(timeBoundsStatus(getLinkPayload(link), 1_800_000_000), 'WITHIN');
  });
});

describe('M7 — compact link decoding to JSON null is undefined, not a crash', () => {
  test('getLinkPayload returns undefined for a null-payload compact string', () => {
    const b64 = (v: unknown) => Buffer.from(JSON.stringify(v)).toString('base64url');
    const nullLink = `${b64({ alg: 'EdDSA' })}.${b64(null)}.sig`;
    assert.equal(getLinkPayload(nullLink), undefined);
    assert.doesNotThrow(() => chainInvariantStatus([nullLink], 'x'));
  });
});

describe('M2 — did:web URL construction blocks traversal / SSRF', () => {
  test('rejects encoded-slash and traversal segments and empty host', () => {
    assert.throws(() => didWebToUrl('did:web:example.com%2F..%2Fsecret'), DidResolutionError);
    assert.throws(() => didWebToUrl('did:web:evil.com:..:..:etc'), DidResolutionError);
    assert.throws(() => didWebToUrl('did:web:'), DidResolutionError);
  });
  test('accepts a plain host and a normal path form', () => {
    assert.equal(didWebToUrl('did:web:example.com'), 'https://example.com/.well-known/did.json');
    assert.equal(didWebToUrl('did:web:example.com:user:alice'), 'https://example.com/user/alice/did.json');
  });
});

describe('M3 — resolveDidDocument does not follow redirects, caps body', () => {
  test('a 302 is rejected, not followed', async () => {
    const did = 'did:sovrn:agent:redir';
    const port = await serve((_req, res) => {
      res.writeHead(302, { location: 'http://127.0.0.1:1/evil' });
      res.end();
    });
    await assert.rejects(
      resolveDidDocument(did, { sovrnRegistryUrl: `http://127.0.0.1:${port}` }),
      (e: unknown) => e instanceof DidResolutionError && /redirect/.test((e as Error).message),
    );
  });
  test('an oversized body is rejected', async () => {
    const did = 'did:sovrn:agent:big';
    const port = await serve((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end('{"id":"' + 'x'.repeat(2000) + '"}');
    });
    await assert.rejects(
      resolveDidDocument(did, { sovrnRegistryUrl: `http://127.0.0.1:${port}`, maxBytes: 512 }),
      (e: unknown) => e instanceof DidResolutionError && /read failed/.test((e as Error).message),
    );
  });
});

describe('L1 — OAuth challenge falls back to a relative metadata URL for a non-http audience', () => {
  test('a "sovrn:mcp:server" audience yields a relative resource_metadata, never "null/..."', async () => {
    const v = new OAuthValidator({ audience: 'sovrn:mcp:server' });
    const r = await v.validate(undefined);
    assert.equal(r.ok, false);
    if (!r.ok) {
      assert.match(r.wwwAuthenticate, /resource_metadata="\/\.well-known\/oauth-protected-resource"/);
      assert.doesNotMatch(r.wwwAuthenticate, /null\/\.well-known/);
    }
  });
});

describe('L2 — readCredentialMetadata returns a clean miss for inherited keys', () => {
  test('__proto__ / constructor / toString return the miss shape', () => {
    for (const key of ['__proto__', 'constructor', 'toString', 'hasOwnProperty']) {
      const r = readCredentialMetadata(key);
      assert.ok('error' in r, `expected miss shape for ${key}`);
    }
  });
  test('a real type still resolves', () => {
    const r = readCredentialMetadata('agent-credential');
    assert.ok(!('error' in r));
  });
});
