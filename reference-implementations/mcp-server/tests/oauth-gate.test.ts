/**
 * OAuth 2.1 resource-server + UCAN conjunction gate tests.
 * The load-bearing assertion: a VALID OAuth session alone does NOT admit a
 * credential-touching tool call (design §7 conjunction).
 * License: Apache-2.0.
 */

import { describe, test, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type Server } from 'node:http';
import { SignJWT } from 'jose';
import { OAuthValidator, protectedResourceMetadata } from '../src/auth/oauth.js';
import { checkUcanGate } from '../src/auth/ucan-gate.js';
import { makeIdentity, registryResolver, makeUcan, FAR_FUTURE } from './helpers.js';

const authServer = makeIdentity('did:example:authorization-server');
const user = makeIdentity('did:sovrn:citizen:user');
const SERVER_DID = 'did:sovrn:agent:reference-server';
const AUDIENCE = 'http://127.0.0.1:3900/mcp';
const ISSUER = 'https://auth.zone-a.example';
const resolve = registryResolver([user]);

const servers: Server[] = [];
after(() => {
  for (const s of servers) s.close();
});

function serveJwks(): Promise<string> {
  const jwks = { keys: [{ ...authServer.publicJwk, kid: 'k1', alg: 'EdDSA', use: 'sig' }] };
  return new Promise((resolveUrl) => {
    const server = createServer((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify(jwks));
    });
    servers.push(server);
    server.listen(0, '127.0.0.1', () => resolveUrl(`http://127.0.0.1:${(server.address() as { port: number }).port}/jwks`));
  });
}

async function accessToken(audience: string): Promise<string> {
  return new SignJWT({ scope: 'mcp' })
    .setProtectedHeader({ alg: 'EdDSA', kid: 'k1' })
    .setIssuer(ISSUER)
    .setAudience(audience)
    .setIssuedAt()
    .setExpirationTime('1h')
    .sign(authServer.privateKey);
}

describe('OAuth 2.1 resource-server validation (RFC 8707 audience binding)', () => {
  test('valid token bound to this resource passes; wrong audience fails', async () => {
    const jwksUrl = await serveJwks();
    const validator = new OAuthValidator({ audience: AUDIENCE, jwksUrl, issuer: ISSUER });

    const good = await validator.validate(`Bearer ${await accessToken(AUDIENCE)}`);
    assert.equal(good.ok, true);

    const replayed = await validator.validate(`Bearer ${await accessToken('http://some-other-server.example/mcp')}`);
    assert.equal(replayed.ok, false); // audience binding kills cross-server replay (class 2)
  });

  test('missing/garbage bearer -> 401 with RFC 9728 resource_metadata challenge', async () => {
    const validator = new OAuthValidator({ audience: AUDIENCE, jwksUrl: await serveJwks(), issuer: ISSUER });
    const missing = await validator.validate(undefined);
    assert.equal(missing.ok, false);
    if (!missing.ok) {
      assert.equal(missing.status, 401);
      assert.match(missing.wwwAuthenticate, /resource_metadata=/);
    }
    const garbage = await validator.validate('Bearer not-a-jwt');
    assert.equal(garbage.ok, false);
  });

  test('protected-resource metadata names the resource and its authorization server', () => {
    const meta = protectedResourceMetadata({ audience: AUDIENCE, issuer: ISSUER });
    assert.equal(meta.resource, AUDIENCE);
    assert.deepEqual(meta.authorization_servers, [ISSUER]);
  });
});

describe('UCAN conjunction gate (transport-independent)', () => {
  const gateConfig = { serverDid: SERVER_DID, resolveIssuerJwk: resolve, mode: 'enforce' as const };
  const capability = () =>
    makeUcan(user, {
      iss: user.did,
      aud: SERVER_DID,
      sub: user.did,
      exp: FAR_FUTURE,
      att: [{ with: 'sovrn:mcp:server', can: 'mcp/verify_presentation' }],
    });

  test('no capability -> refused EVEN THOUGH the OAuth session would be valid (the conjunction)', async () => {
    const result = await checkUcanGate('verify_presentation', undefined, gateConfig);
    assert.equal(result.allowed, false);
    if (!result.allowed) assert.match(result.reason, /OAuth session alone is not sufficient/);
  });

  test('valid capability for the tool -> allowed', async () => {
    const result = await checkUcanGate('verify_presentation', capability(), gateConfig);
    assert.deepEqual(result, { allowed: true });
  });

  test('capability aud pinned to another server -> refused (anti-replay)', async () => {
    const foreign = makeUcan(user, {
      iss: user.did,
      aud: 'did:sovrn:agent:some-other-server',
      exp: FAR_FUTURE,
      att: [{ with: 'sovrn:mcp:server', can: 'mcp/verify_presentation' }],
    });
    const result = await checkUcanGate('verify_presentation', foreign, gateConfig);
    assert.equal(result.allowed, false);
  });

  test('capability for a DIFFERENT tool -> refused (attenuation is per-ability)', async () => {
    const result = await checkUcanGate('validate_delegation_chain', capability(), gateConfig);
    assert.equal(result.allowed, false);
  });

  test('expired capability -> refused', async () => {
    const expired = makeUcan(user, {
      iss: user.did,
      aud: SERVER_DID,
      exp: 1000,
      att: [{ with: 'sovrn:mcp:server', can: 'mcp/verify_presentation' }],
    });
    const result = await checkUcanGate('verify_presentation', expired, gateConfig);
    assert.equal(result.allowed, false);
  });

  test('optional mode admits verifier tools WITH a warning — but request_credential stays enforced', async () => {
    const optional = { ...gateConfig, mode: 'optional' as const };
    const verifier = await checkUcanGate('verify_presentation', undefined, optional);
    assert.equal(verifier.allowed, true);
    if (verifier.allowed) assert.ok(verifier.warning);

    const credentialTouching = await checkUcanGate('request_credential', undefined, optional);
    assert.equal(credentialTouching.allowed, false);
  });
});
