# HTTP Usage Walkthrough

The streamable HTTP transport requires OAuth 2.1 (RFC 8707 audience-bound bearer tokens) **and** a per-tool-call UCAN capability. This walkthrough exercises the full path with curl.

## 1. Start the server

```bash
SOVRN_MCP_JWKS_URL=https://auth.zone-a.example/jwks \
SOVRN_MCP_OAUTH_ISSUER=https://auth.zone-a.example \
SOVRN_MCP_AUDIENCE=http://127.0.0.1:3900/mcp \
SOVRN_MCP_SERVER_DID=did:sovrn:agent:reference-server \
SOVRN_MCP_TRUSTED_ISSUERS=did:sovrn:zone:zone-a \
npm run start:http
```

The server binds `127.0.0.1:3900`. Without a JWKS URL every request 401s — that is the intended fail-closed default.

## 2. Discover the authorization server (RFC 9728)

```bash
curl -s http://127.0.0.1:3900/.well-known/oauth-protected-resource
# -> { "resource": "http://127.0.0.1:3900/mcp", "authorization_servers": ["https://auth.zone-a.example"], ... }
```

Obtain an access token from that authorization server with `resource=http://127.0.0.1:3900/mcp` (RFC 8707) so the token's `aud` binds to this server.

## 3. Call a tool

The UCAN capability travels as the `capabilityToken` tool argument: a UCAN 0.10 compact JWT issued to `aud = did:sovrn:agent:reference-server` with attenuation `{ "with": "sovrn:mcp:server", "can": "mcp/verify_presentation" }`.

```bash
curl -s http://127.0.0.1:3900/mcp \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{
    "jsonrpc": "2.0", "id": 1, "method": "tools/call",
    "params": {
      "name": "verify_presentation",
      "arguments": {
        "credential": { "...": "a SovrnAgentCredential JSON object or a compact SD-JWT-VC string" },
        "capabilityToken": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsInVjdiI6IjAuMTAuMCJ9...."
      }
    }
  }'
```

The response carries the verdict, the cited rule on rejection, and the full step trace.

## 4. What refuses, and why

| Request | Result |
|---|---|
| No `Authorization` header | 401 + `WWW-Authenticate` pointing at the RFC 9728 metadata |
| Token minted for another server (`aud` mismatch) | 401 — RFC 8707 audience binding |
| Valid token, no `capabilityToken` | Tool-level refusal: the conjunction — an OAuth session alone is not sufficient |
| Capability whose terminal `aud` is another server's DID | Tool-level refusal — anti-replay pin |
| Capability for a different tool's ability | Tool-level refusal — attenuation is per-ability |

## Local demo without external infrastructure

For an end-to-end local demo (no live authorization server, no registry), use the stdio transport with a static DID store ([claude-desktop-config.json](./claude-desktop-config.json)) — OAuth is N/A on stdio by design, and the UCAN gate still enforces. MCP Inspector works the same way:

```bash
npx @modelcontextprotocol/inspector npx tsx src/index.ts --transport stdio
```
