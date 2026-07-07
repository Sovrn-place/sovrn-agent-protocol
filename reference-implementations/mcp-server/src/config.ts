/**
 * Sovrn Agent Protocol — MCP Server Reference Implementation
 * Configuration: environment variables (SOVRN_MCP_*) + CLI flags.
 *
 * License: Apache-2.0.
 */

import * as fs from 'node:fs';
import type { DidDocument } from './did/resolve.js';

export interface ServerConfig {
  transport: 'stdio' | 'http';
  /** HTTP bind address. Localhost by default — a deliberate hardening default. */
  bind: string;
  port: number;
  /** RFC 8707 canonical resource URI (OAuth audience binding). */
  audience: string;
  /** Authorization-server JWKS endpoint (HTTP transport OAuth). */
  jwksUrl?: string;
  /** Expected OAuth token issuer. */
  oauthIssuer?: string;
  /** This server's DID — terminal audience for the UCAN capability gate. */
  serverDid?: string;
  /** did:sovrn registry resolution endpoint (Layer 0). */
  sovrnRegistryUrl?: string;
  /** Issuer trusted list (A6 normative check). */
  trustedIssuers: string[];
  /** Static DID-document trust store, loaded from a JSON file (did -> document). */
  staticDidDocuments?: Record<string, DidDocument>;
  /** Zone federation map override (path to a JSON file). */
  zoneMapPath?: string;
  /** Additional allowed Origins for the HTTP transport (localhost is always allowed). */
  allowedOrigins: string[];
  /** UCAN gate mode. 'enforce' is the production default (see ucan-gate.ts). */
  ucanGateMode: 'enforce' | 'optional';
  /** Reputation epoch overlap window in seconds (L3 §6 envelope read). */
  epochOverlapSeconds: number;
}

function flag(argv: string[], name: string): string | undefined {
  const i = argv.indexOf(`--${name}`);
  if (i >= 0 && i + 1 < argv.length) return argv[i + 1];
  return undefined;
}

function csv(value: string | undefined): string[] {
  return value ? value.split(',').map((s) => s.trim()).filter(Boolean) : [];
}

export function loadConfig(argv: string[] = process.argv.slice(2), env: NodeJS.ProcessEnv = process.env): ServerConfig {
  const transport = (flag(argv, 'transport') ?? env.SOVRN_MCP_TRANSPORT ?? 'stdio') as 'stdio' | 'http';
  if (transport !== 'stdio' && transport !== 'http') {
    throw new Error(`unsupported transport: ${transport} (stdio | http)`);
  }
  const port = Number(flag(argv, 'port') ?? env.SOVRN_MCP_PORT ?? 3900);
  const bind = flag(argv, 'bind') ?? env.SOVRN_MCP_BIND ?? '127.0.0.1';

  let staticDidDocuments: Record<string, DidDocument> | undefined;
  const staticDidPath = flag(argv, 'static-did-docs') ?? env.SOVRN_MCP_STATIC_DID_DOCS;
  if (staticDidPath) {
    staticDidDocuments = JSON.parse(fs.readFileSync(staticDidPath, 'utf8')) as Record<string, DidDocument>;
  }

  const gateMode = (flag(argv, 'ucan-gate') ?? env.SOVRN_MCP_UCAN_GATE ?? 'enforce') as 'enforce' | 'optional';
  if (gateMode !== 'enforce' && gateMode !== 'optional') {
    throw new Error(`unsupported UCAN gate mode: ${gateMode} (enforce | optional)`);
  }

  return {
    transport,
    bind,
    port,
    audience: env.SOVRN_MCP_AUDIENCE ?? `http://${bind}:${port}/mcp`,
    jwksUrl: env.SOVRN_MCP_JWKS_URL,
    oauthIssuer: env.SOVRN_MCP_OAUTH_ISSUER,
    serverDid: env.SOVRN_MCP_SERVER_DID,
    sovrnRegistryUrl: env.SOVRN_MCP_REGISTRY_URL,
    trustedIssuers: csv(env.SOVRN_MCP_TRUSTED_ISSUERS),
    staticDidDocuments,
    zoneMapPath: flag(argv, 'zone-map') ?? env.SOVRN_MCP_ZONE_MAP,
    allowedOrigins: csv(env.SOVRN_MCP_ALLOWED_ORIGINS),
    ucanGateMode: gateMode,
    epochOverlapSeconds: Number(env.SOVRN_MCP_EPOCH_OVERLAP_SECONDS ?? 0),
  };
}
