/**
 * Sovrn Agent Protocol — MCP Server Reference Implementation
 * Credential status — BitstringStatusList (Layer 1 §9.1).
 *
 * The BITSTRING DECODER is real (base64url + gzip + bit index, per the W3C
 * Bitstring Status List spec). The status-list SOURCE is injectable: a static
 * config source ships as the v0.1.0 default; live HTTPS fetch of the status
 * list credential is a documented integrator extension (design §11 —
 * "oracle-injectable for conformance; real live fetch documented as
 * integrator config").
 *
 * License: Apache-2.0.
 */

import { gunzipSync } from 'node:zlib';

/**
 * Decode a BitstringStatusList encodedList and read one bit (statusListIndex).
 * Throws on a non-integer/negative index (adversarial M5 — a negative index
 * must not silently read as ACTIVE) or an out-of-range index. gunzip failure
 * on a non-gzip list also throws; callers treat any throw as a hard fail
 * (adversarial M4), never as a silent CLEAR.
 */
export function readStatusBit(encodedList: string, index: number): boolean {
  if (!Number.isInteger(index) || index < 0) {
    throw new Error(`statusListIndex must be a non-negative integer, got ${index}`);
  }
  const compressed = Buffer.from(encodedList, 'base64url');
  const bitstring = gunzipSync(compressed);
  const byteIndex = Math.floor(index / 8);
  if (byteIndex >= bitstring.length) {
    throw new Error(`statusListIndex ${index} is outside the bitstring (${bitstring.length} bytes)`);
  }
  // Spec order: the most significant bit of byte 0 is index 0.
  const bit = 7 - (index % 8);
  return (bitstring[byteIndex] & (1 << bit)) !== 0;
}

export interface CredentialStatusSource {
  /** Returns 'REVOKED' when the credential's status bit is set (or the id is listed). */
  credentialStatus(credential: unknown): Promise<'ACTIVE' | 'REVOKED'>;
}

interface CredentialStatusEntry {
  id?: string;
  type?: string;
  statusListIndex?: string | number;
  statusListCredential?: string;
}

function statusEntries(credential: unknown): CredentialStatusEntry[] {
  const status = (credential as { credentialStatus?: unknown } | null | undefined)?.credentialStatus;
  if (!status) return [];
  return Array.isArray(status) ? (status as CredentialStatusEntry[]) : [status as CredentialStatusEntry];
}

/**
 * Static status source: a config-supplied revoked-id set plus optional inline
 * status lists keyed by statusListCredential URL.
 */
export class StaticStatusSource implements CredentialStatusSource {
  private readonly revokedIds: Set<string>;
  private readonly statusLists: Map<string, string>;

  constructor(revokedCredentialIds: string[] = [], statusLists: Record<string, string> = {}) {
    this.revokedIds = new Set(revokedCredentialIds);
    this.statusLists = new Map(Object.entries(statusLists));
  }

  async credentialStatus(credential: unknown): Promise<'ACTIVE' | 'REVOKED'> {
    const id = (credential as { id?: unknown } | null | undefined)?.id;
    if (typeof id === 'string' && this.revokedIds.has(id)) return 'REVOKED';

    for (const entry of statusEntries(credential)) {
      const listUrl = entry.statusListCredential;
      const index = entry.statusListIndex;
      if (listUrl && this.statusLists.has(listUrl) && index !== undefined) {
        const encodedList = this.statusLists.get(listUrl)!;
        // A malformed index or an undecodable (non-gzip / corrupt) status list
        // must fail CLOSED — the verifier cannot confirm the credential is
        // active, so it treats it as revoked rather than throwing (adversarial
        // M4) or silently granting (adversarial M5).
        let revoked: boolean;
        try {
          revoked = readStatusBit(encodedList, Number(index));
        } catch {
          return 'REVOKED';
        }
        if (revoked) return 'REVOKED';
      }
    }
    return 'ACTIVE';
  }
}
