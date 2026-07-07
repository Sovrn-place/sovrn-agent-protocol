/**
 * Sovrn Agent Protocol — MCP Server Reference Implementation
 * stdio transport (local: Claude Desktop, Claude Code, Cursor, MCP-native
 * frameworks).
 *
 * OAuth is N/A here BY DESIGN (design §3): the client launched this process;
 * client and server share the local process trust boundary, and OAuth's
 * authorization-server round-trip has no natural home. stdio is NOT
 * unauthenticated in the ways that matter: the per-tool-call UCAN capability
 * gate is transport-independent and carries here in full.
 *
 * stdout is the protocol channel — all diagnostics go to stderr.
 *
 * License: Apache-2.0.
 */

import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import type { ServerConfig } from '../config.js';
import { buildServer } from '../server.js';

export async function runStdio(config: ServerConfig): Promise<void> {
  const server = buildServer(config);
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('[sovrn-mcp-reference] stdio transport connected (UCAN gate: %s)', config.ucanGateMode);
}
