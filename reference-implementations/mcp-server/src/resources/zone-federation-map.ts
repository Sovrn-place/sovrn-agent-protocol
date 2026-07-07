/**
 * Sovrn Agent Protocol — MCP Server Reference Implementation
 * MCP resource: zone federation map (PUBLIC SURFACE ONLY).
 *
 * The public list of zones and their PUBLIC attributes. No Federation trust
 * computation, no zone routing logic, no cross-zone trust weights — those are
 * proprietary (master §3) and never appear in this reference implementation.
 * Ships with fictional sample zones (zone-a, zone-b); a deployment overrides
 * the map via config (--zone-map / SOVRN_MCP_ZONE_MAP).
 *
 * License: Apache-2.0.
 */

import * as fs from 'node:fs';

export interface ZoneMapEntry {
  zoneId: string;
  name: string;
  did: string;
  status: string;
  serviceEndpoints: { type: string; endpoint: string }[];
}

export const SAMPLE_ZONE_MAP: ZoneMapEntry[] = [
  {
    zoneId: 'zone-a',
    name: 'Zone A (sample)',
    did: 'did:sovrn:zone:zone-a',
    status: 'sample',
    serviceEndpoints: [
      { type: 'sovrn-mcp/1.0', endpoint: 'https://mcp.zone-a.example' },
      { type: 'OID4VCI', endpoint: 'https://zone-a.example/oid4vci' },
    ],
  },
  {
    zoneId: 'zone-b',
    name: 'Zone B (sample)',
    did: 'did:sovrn:zone:zone-b',
    status: 'sample',
    serviceEndpoints: [
      { type: 'sovrn-mcp/1.0', endpoint: 'https://mcp.zone-b.example' },
      { type: 'OID4VCI', endpoint: 'https://zone-b.example/oid4vci' },
    ],
  },
];

export function loadZoneMap(zoneMapPath?: string): ZoneMapEntry[] {
  if (!zoneMapPath) return SAMPLE_ZONE_MAP;
  return JSON.parse(fs.readFileSync(zoneMapPath, 'utf8')) as ZoneMapEntry[];
}
