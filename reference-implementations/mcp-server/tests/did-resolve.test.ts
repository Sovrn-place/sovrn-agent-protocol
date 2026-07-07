/**
 * DID resolution tests: did:web over a local ephemeral server, did:sovrn via
 * a registry endpoint, hard-fail semantics, NO cross-method fallback.
 * License: Apache-2.0.
 */

import { describe, test, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type Server } from 'node:http';
import { resolveDidDocument, didWebToUrl, DidResolutionError, selectVerificationMethod } from '../src/did/resolve.js';

const servers: Server[] = [];
after(() => {
  for (const s of servers) s.close();
});

function serve(handler: (path: string) => { status: number; body: unknown }): Promise<number> {
  return new Promise((resolve) => {
    const server = createServer((req, res) => {
      const { status, body } = handler(req.url ?? '/');
      res.writeHead(status, { 'content-type': 'application/json' });
      res.end(JSON.stringify(body));
    });
    servers.push(server);
    server.listen(0, '127.0.0.1', () => resolve((server.address() as { port: number }).port));
  });
}

describe('didWebToUrl', () => {
  test('bare host -> /.well-known/did.json; path form -> /path/did.json; %3A port decodes', () => {
    assert.equal(didWebToUrl('did:web:example.com'), 'https://example.com/.well-known/did.json');
    assert.equal(didWebToUrl('did:web:example.com:user:alice'), 'https://example.com/user/alice/did.json');
    assert.equal(didWebToUrl('did:web:127.0.0.1%3A8443', true), 'http://127.0.0.1:8443/.well-known/did.json');
  });
});

describe('resolveDidDocument', () => {
  test('did:web resolves against the well-known path', async () => {
    const port = await serve((path) =>
      path === '/.well-known/did.json'
        ? { status: 200, body: { id: `did:web:127.0.0.1%3A${port}`, verificationMethod: [{ id: 'k1', publicKeyJwk: { kty: 'OKP' } }] } }
        : { status: 404, body: {} },
    );
    const did = `did:web:127.0.0.1%3A${port}`;
    const doc = await resolveDidDocument(did, { allowInsecureLocalhost: true });
    assert.equal(doc.id, did);
    assert.equal(selectVerificationMethod(doc).id, 'k1');
  });

  test('did:sovrn resolves via the configured registry endpoint', async () => {
    const did = 'did:sovrn:agent:550e8400-e29b-41d4-a716-446655440000';
    const port = await serve((path) =>
      path === `/${encodeURIComponent(did)}` ? { status: 200, body: { id: did } } : { status: 404, body: {} },
    );
    const doc = await resolveDidDocument(did, { sovrnRegistryUrl: `http://127.0.0.1:${port}` });
    assert.equal(doc.id, did);
  });

  test('did:sovrn WITHOUT a registry config hard-fails — no fallback to any other method', async () => {
    await assert.rejects(
      resolveDidDocument('did:sovrn:agent:abc', {}),
      (err: unknown) => err instanceof DidResolutionError && /no fallback/.test((err as Error).message),
    );
  });

  test('unsupported DID method hard-fails (accepted: did:sovrn primary, did:web accepted-input)', async () => {
    await assert.rejects(resolveDidDocument('did:key:z6Mk...', {}), DidResolutionError);
    await assert.rejects(resolveDidDocument('did:ethr:0xabc', {}), DidResolutionError);
  });

  test('document id mismatch hard-fails', async () => {
    const did = 'did:sovrn:agent:mismatch';
    const port = await serve(() => ({ status: 200, body: { id: 'did:sovrn:agent:SOMEONE_ELSE' } }));
    await assert.rejects(
      resolveDidDocument(did, { sovrnRegistryUrl: `http://127.0.0.1:${port}` }),
      (err: unknown) => err instanceof DidResolutionError && /does not match/.test((err as Error).message),
    );
  });

  test('non-200 hard-fails', async () => {
    const did = 'did:sovrn:agent:gone';
    const port = await serve(() => ({ status: 404, body: {} }));
    await assert.rejects(resolveDidDocument(did, { sovrnRegistryUrl: `http://127.0.0.1:${port}` }), DidResolutionError);
  });
});
