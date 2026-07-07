/**
 * Sovrn Agent Protocol — MCP Server Reference Implementation
 * OAuth 2.1 resource-server validation (HTTP transport ONLY).
 *
 * The transport/auth asymmetry is load-bearing (design §3): on streamable
 * HTTP, OAuth 2.1 + RFC 8707 audience binding is REQUIRED — the audience
 * binding pins a token to THIS server, killing token replay across servers
 * (design §10, class 2). On stdio, OAuth is N/A: the client launched the
 * process and shares the local trust boundary; the per-tool-call UCAN
 * capability gate (ucan-gate.ts) carries on BOTH transports.
 *
 * This module validates JWT access tokens against the authorization server's
 * JWKS (jose createRemoteJWKSet) and serves RFC 9728 protected-resource
 * metadata so clients can discover the authorization server.
 *
 * License: Apache-2.0.
 */

import { createRemoteJWKSet, jwtVerify, type JWTPayload } from 'jose';

export interface OAuthConfig {
  /** REQUIRED on HTTP: the canonical resource URI tokens must be bound to (RFC 8707). */
  audience: string;
  /** The authorization server's JWKS endpoint. */
  jwksUrl?: string;
  /** Expected token issuer (the authorization server). */
  issuer?: string;
  /** Authorization server(s) advertised in RFC 9728 metadata. */
  authorizationServers?: string[];
}

export type OAuthResult =
  | { ok: true; claims: JWTPayload }
  | { ok: false; status: 401 | 403; error: string; wwwAuthenticate: string };

export class OAuthValidator {
  private readonly jwks?: ReturnType<typeof createRemoteJWKSet>;

  constructor(private readonly config: OAuthConfig) {
    if (config.jwksUrl) this.jwks = createRemoteJWKSet(new URL(config.jwksUrl));
  }

  private challenge(error: string): string {
    // RFC 9728: point the client at the protected-resource metadata, served at
    // the resource ORIGIN's well-known path (the audience URI may carry a path).
    let metadataUrl = '/.well-known/oauth-protected-resource';
    try {
      const origin = new URL(this.config.audience).origin;
      // A non-http(s) audience (e.g. "sovrn:mcp:server") yields origin "null"
      // rather than throwing — fall back to the relative path (adversarial L1).
      if (origin && origin !== 'null') {
        metadataUrl = `${origin}${metadataUrl}`;
      }
    } catch {
      /* keep the relative path */
    }
    return `Bearer error="${error}", resource_metadata="${metadataUrl}"`;
  }

  /** Validate the Authorization header. Runs BEFORE the MCP transport sees the request. */
  async validate(authorizationHeader: string | undefined): Promise<OAuthResult> {
    if (!authorizationHeader || !authorizationHeader.startsWith('Bearer ')) {
      return { ok: false, status: 401, error: 'missing bearer token', wwwAuthenticate: this.challenge('invalid_request') };
    }
    if (!this.jwks) {
      return { ok: false, status: 401, error: 'no authorization server configured (set the JWKS URL)', wwwAuthenticate: this.challenge('invalid_token') };
    }
    const token = authorizationHeader.slice('Bearer '.length).trim();
    try {
      const { payload } = await jwtVerify(token, this.jwks, {
        audience: this.config.audience, // RFC 8707 audience binding — non-negotiable
        ...(this.config.issuer ? { issuer: this.config.issuer } : {}),
      });
      return { ok: true, claims: payload };
    } catch (err) {
      return { ok: false, status: 401, error: `token validation failed: ${(err as Error).message}`, wwwAuthenticate: this.challenge('invalid_token') };
    }
  }
}

/** RFC 9728 protected-resource metadata document. */
export function protectedResourceMetadata(config: OAuthConfig): Record<string, unknown> {
  return {
    resource: config.audience,
    authorization_servers: config.authorizationServers ?? (config.issuer ? [config.issuer] : []),
    bearer_methods_supported: ['header'],
    resource_documentation: 'https://github.com/Sovrn-place/sovrn-agent-protocol',
  };
}
