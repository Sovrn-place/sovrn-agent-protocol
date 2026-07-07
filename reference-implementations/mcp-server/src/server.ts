/**
 * Sovrn Agent Protocol — MCP Server Reference Implementation
 * MCP server wiring: 3 tools + 2 public-surface resources.
 *
 * This module (plus transports/) is the ONLY place the MCP SDK server API is
 * imported — the engine, providers, tools, and auth are SDK-agnostic, so an
 * SDK major-version migration is confined here.
 *
 * Surface (design §2.2, locked):
 *   tools:     request_credential (thin handoff), verify_presentation
 *              (Procedure A), validate_delegation_chain (Procedure B)
 *   resources: credential metadata (RFC 6570 template), zone federation map
 * The five sovrn:// memory-board families are NOT exposed here — they are the
 * memory-board's exposure, a separate repo (design §2).
 *
 * License: Apache-2.0.
 */

import { McpServer, ResourceTemplate } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { ServerConfig } from './config.js';
import { productionContext } from './providers/production.js';
import { checkUcanGate } from './auth/ucan-gate.js';
import type { ToolContext } from './tools/context.js';
import { requestCredentialTool } from './tools/request-credential.js';
import { verifyPresentationTool } from './tools/verify-presentation.js';
import { validateDelegationChainTool } from './tools/validate-delegation-chain.js';
import { listCredentialTypes, readCredentialMetadata } from './resources/credential-metadata.js';
import { loadZoneMap } from './resources/zone-federation-map.js';

export function buildServer(config: ServerConfig): McpServer {
  const { providers, resolveIssuerJwk } = productionContext({
    sovrnRegistryUrl: config.sovrnRegistryUrl,
    trustedIssuers: config.trustedIssuers,
    staticDidDocuments: config.staticDidDocuments,
    epochOverlapSeconds: config.epochOverlapSeconds,
  });

  const ctx: ToolContext = {
    providers,
    gate: (toolName, capabilityToken) =>
      checkUcanGate(toolName, capabilityToken, {
        serverDid: config.serverDid,
        mode: config.ucanGateMode,
        resolveIssuerJwk,
      }),
  };

  const server = new McpServer({
    name: 'sovrn-agent-protocol-reference',
    version: '0.1.0',
  });

  for (const tool of [requestCredentialTool, verifyPresentationTool, validateDelegationChainTool] as const) {
    server.registerTool(
      tool.name,
      { title: tool.title, description: tool.description, inputSchema: tool.inputShape },
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (async (args: any) => tool.handler(args, ctx)) as never,
    );
  }

  server.registerResource(
    'credential-metadata',
    new ResourceTemplate('sovrn-agent-protocol://credential-metadata/{credentialType}', {
      list: async () => ({
        resources: listCredentialTypes().map((t) => ({
          uri: `sovrn-agent-protocol://credential-metadata/${t}`,
          name: `credential-metadata: ${t}`,
          mimeType: 'application/json',
        })),
      }),
    }),
    {
      title: 'Agent-discoverable credential metadata',
      description: 'Public metadata for Sovrn agent-protocol credential discovery: schema URLs, context URLs, envelope formats. Public surface only.',
      mimeType: 'application/json',
    },
    async (uri, variables) => ({
      contents: [
        {
          uri: uri.href,
          mimeType: 'application/json',
          text: JSON.stringify(readCredentialMetadata(String(variables.credentialType)), null, 2),
        },
      ],
    }),
  );

  server.registerResource(
    'zone-federation-map',
    'sovrn-agent-protocol://zone-federation-map',
    {
      title: 'Zone federation map',
      description: 'The public list of zones and their public attributes. No Federation trust logic, no PII, no agent state.',
      mimeType: 'application/json',
    },
    async (uri) => ({
      contents: [
        {
          uri: uri.href,
          mimeType: 'application/json',
          text: JSON.stringify(loadZoneMap(config.zoneMapPath), null, 2),
        },
      ],
    }),
  );

  return server;
}
