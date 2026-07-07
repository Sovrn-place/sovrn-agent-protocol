/**
 * Sovrn Agent Protocol — MCP Server Reference Implementation
 * MCP resource: agent-discoverable credential metadata (PUBLIC SURFACE ONLY).
 *
 * Public metadata for credential discovery — schema URLs, context URLs,
 * envelope formats, layer, status. Everything here is already public in the
 * protocol publication (schemas/ + contexts/). No Federation trust logic, no
 * PII, no agent state (design §6). The reputation-record entry describes the
 * PUBLISHED SCHEMA SHAPE only: dimensions and tier are implementation-defined
 * opaque values, and Layer 3 tooling is out of reference-impl scope at v0.1.0.
 *
 * License: Apache-2.0.
 */

export interface CredentialMetadataEntry {
  credentialType: string;
  vcType: string;
  layer: number;
  schemaUrl: string;
  contextUrl: string;
  envelopes: string[];
  status: 'DRAFT';
  notes?: string;
}

const NS = 'https://schema.sovrn.place';

export const CREDENTIAL_METADATA: Record<string, CredentialMetadataEntry> = {
  'agent-credential': {
    credentialType: 'agent-credential',
    vcType: 'SovrnAgentCredential',
    layer: 1,
    schemaUrl: `${NS}/agent/v1/agent-credential.json`,
    contextUrl: `${NS}/agent/v1`,
    envelopes: ['W3C VC 2.0 + Data Integrity (multi-proof co-signing)', 'SD-JWT-VC (selective disclosure)'],
    status: 'DRAFT',
  },
  'agent-record': {
    credentialType: 'agent-record',
    vcType: 'SovrnAgentRecord',
    layer: 0,
    schemaUrl: `${NS}/agent/v1/agent-record.json`,
    contextUrl: `${NS}/agent/v1`,
    envelopes: ['application-level composite (identity + credentials + reputation + delegations)'],
    status: 'DRAFT',
  },
  'delegation-token': {
    credentialType: 'delegation-token',
    vcType: 'UCANDelegation',
    layer: 2,
    schemaUrl: `${NS}/agent/v1/delegation-token.json`,
    contextUrl: `${NS}/agent/v1`,
    envelopes: ['UCAN 0.10 JWT (accepted input)', 'UCAN 1.0-rc.1 DAG-CBOR (normative wire; verification extension point at v0.1.0)'],
    status: 'DRAFT',
  },
  'reputation-record': {
    credentialType: 'reputation-record',
    vcType: 'SovrnReputationRecord',
    layer: 3,
    schemaUrl: `${NS}/reputation/v1/reputation-record.json`,
    contextUrl: `${NS}/reputation/v1`,
    envelopes: ['W3C VC 2.0'],
    status: 'DRAFT',
    notes:
      'Published schema shape only. Dimension names, count, weighting, tier names, and thresholds are implementation-defined opaque values. Layer 3 reputation tooling is out of reference-implementation scope for v0.1.0.',
  },
};

export function listCredentialTypes(): string[] {
  return Object.keys(CREDENTIAL_METADATA);
}

export function readCredentialMetadata(credentialType: string): CredentialMetadataEntry | { error: string; available: string[] } {
  // Own-property check so inherited keys ("__proto__", "constructor",
  // "toString") return a clean miss instead of an Object.prototype member
  // (adversarial L2). No prototype pollution risk, but a reference impl should
  // never return anything but a registered entry or the miss shape.
  if (Object.prototype.hasOwnProperty.call(CREDENTIAL_METADATA, credentialType)) {
    return CREDENTIAL_METADATA[credentialType];
  }
  return { error: `unknown credential type: ${credentialType}`, available: listCredentialTypes() };
}
