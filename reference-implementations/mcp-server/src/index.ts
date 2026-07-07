/**
 * Sovrn Agent Protocol — MCP Server Reference Implementation
 * CLI entrypoint.
 *
 *   tsx src/index.ts --transport stdio
 *   tsx src/index.ts --transport http --port 3900
 *
 * Configuration via SOVRN_MCP_* environment variables (see config.ts).
 * Diagnostics go to stderr (stdout is the stdio protocol channel).
 *
 * License: Apache-2.0.
 */

import { loadConfig } from './config.js';
import { runStdio } from './transports/stdio.js';
import { runHttp } from './transports/http.js';

async function main(): Promise<void> {
  const config = loadConfig();
  if (config.ucanGateMode === 'optional') {
    console.error('[sovrn-mcp-reference] WARNING: UCAN gate is in OPTIONAL mode — local evaluation only, never production (SECURITY.md)');
  }
  if (config.transport === 'stdio') {
    await runStdio(config);
  } else {
    await runHttp(config);
  }
}

main().catch((err) => {
  console.error('[sovrn-mcp-reference] fatal:', err);
  process.exit(1);
});
