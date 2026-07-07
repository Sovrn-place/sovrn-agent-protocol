/**
 * Sovrn Agent Protocol — MCP Server Reference Implementation
 * Streamable HTTP transport over raw node:http (no framework dependency).
 *
 * Hardening (design §3 / §10 classes 3 + 6):
 *  - Binds 127.0.0.1 by default.
 *  - SDK DNS-rebinding protection ON with an explicit allowed-hosts list;
 *    Origin allow-list (localhost origins + configured extras).
 *  - OAuth 2.1 resource-server validation runs STRICTLY BEFORE the MCP
 *    transport sees the request; RFC 8707 audience binding pins tokens to
 *    this server. RFC 9728 protected-resource metadata is served at
 *    /.well-known/oauth-protected-resource.
 *  - Stateless per-request server + transport instances (no session state to
 *    steal; request-ID collision safety per SDK guidance).
 *  - No credential pass-through to intermediaries: this process holds NO
 *    holder key (key-optional verifier, design §1.1) and never logs secrets.
 *
 * License: Apache-2.0.
 */

import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import type { ServerConfig } from '../config.js';
import { buildServer } from '../server.js';
import { OAuthValidator, protectedResourceMetadata, type OAuthConfig } from '../auth/oauth.js';

/** Maximum accepted request body. No legitimate MCP request approaches this. */
const MAX_BODY_BYTES = 1_048_576; // 1 MiB
/** Idle timeout for reading the body — kills a slow-drip / never-ending stream. */
const BODY_READ_TIMEOUT_MS = 30_000;

class PayloadTooLargeError extends Error {
  readonly statusCode = 413;
  constructor() {
    super(`request body exceeds the ${MAX_BODY_BYTES}-byte limit`);
    this.name = 'PayloadTooLargeError';
  }
}

function readBody(req: IncomingMessage): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    // Idle timeout: if the client stalls mid-body, abort rather than buffer forever.
    req.setTimeout(BODY_READ_TIMEOUT_MS, () => {
      req.destroy();
      reject(new Error('request body read timed out'));
    });
    req.on('data', (c: Buffer) => {
      total += c.length;
      if (total > MAX_BODY_BYTES) {
        req.destroy(); // stop buffering immediately — bounded memory (adversarial M1)
        reject(new PayloadTooLargeError());
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => {
      if (chunks.length === 0) return resolve(undefined);
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      } catch (err) {
        reject(err);
      }
    });
    req.on('error', reject);
  });
}

function json(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
  res.writeHead(status, { 'content-type': 'application/json', ...headers });
  res.end(JSON.stringify(body));
}

export async function runHttp(config: ServerConfig): Promise<void> {
  const oauthConfig: OAuthConfig = {
    audience: config.audience,
    jwksUrl: config.jwksUrl,
    issuer: config.oauthIssuer,
  };
  const oauth = new OAuthValidator(oauthConfig);

  const allowedHosts = [
    `127.0.0.1:${config.port}`,
    `localhost:${config.port}`,
    ...(config.bind !== '127.0.0.1' ? [`${config.bind}:${config.port}`] : []),
  ];
  const allowedOrigins = [
    `http://127.0.0.1:${config.port}`,
    `http://localhost:${config.port}`,
    ...config.allowedOrigins,
  ];

  const httpServer = createServer(async (req, res) => {
    try {
      const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);

      // RFC 9728 discovery — intentionally unauthenticated.
      if (url.pathname === '/.well-known/oauth-protected-resource') {
        json(res, 200, protectedResourceMetadata(oauthConfig));
        return;
      }
      if (url.pathname !== '/mcp') {
        json(res, 404, { error: 'not found (the MCP endpoint is /mcp)' });
        return;
      }

      // OAuth BEFORE the transport (never expose the transport pre-auth).
      const auth = await oauth.validate(req.headers.authorization);
      if (!auth.ok) {
        json(res, auth.status, { error: auth.error }, { 'www-authenticate': auth.wwwAuthenticate });
        return;
      }

      // Stateless mode: fresh server + transport per request (SDK guidance —
      // avoids request-ID collisions and keeps the verifier state-free).
      const server = buildServer(config);
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: undefined,
        enableJsonResponse: true,
        enableDnsRebindingProtection: true,
        allowedHosts,
        allowedOrigins,
      });
      res.on('close', () => {
        void transport.close();
        void server.close();
      });
      await server.connect(transport);

      const body = req.method === 'POST' ? await readBody(req) : undefined;
      await transport.handleRequest(req, res, body);
    } catch (err) {
      const status = (err as { statusCode?: number }).statusCode ?? 500;
      if (!res.headersSent) {
        json(res, status, { error: status === 413 ? (err as Error).message : `internal error: ${(err as Error).message}` });
      } else {
        res.end();
      }
    }
  });

  await new Promise<void>((resolve) => httpServer.listen(config.port, config.bind, resolve));
  console.error(
    '[sovrn-mcp-reference] streamable HTTP listening on http://%s:%d/mcp (OAuth: %s, UCAN gate: %s)',
    config.bind,
    config.port,
    config.jwksUrl ? 'JWKS-validated' : 'NOT CONFIGURED — all requests will 401',
    config.ucanGateMode,
  );
}
