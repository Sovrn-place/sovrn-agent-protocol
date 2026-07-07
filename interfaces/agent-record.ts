/**
 * SovrnAgentRecord — Composite agent identity record
 * Generated from: schemas/agents/agent-record.v1.json
 * Version: 0.1.0
 * License: Apache-2.0
 *
 * This is an application-level aggregation, not a W3C VC.
 * Individual credentials and reputation records within are VCs.
 */

import type { SovrnAgentCredential, AgentType } from './agent-credential'
import type { SovrnReputationRecord } from './reputation-record'

/** Service endpoint for agent discovery */
export interface ServiceEndpoint {
  protocol: 'MCP' | 'A2A' | 'OID4VP' | 'OID4VCI' | 'REST' | 'WebSocket'
  endpoint: string
  version?: string
}

/** Agent identity block */
export interface AgentIdentity {
  agentType: AgentType
  principalDID: string
  principalSiName?: string
  publicKey: string
  framework?: string
  version?: string
  registeredAt: string
  erc8004TokenId?: string
  serviceEndpoints?: ServiceEndpoint[]
}

/** Delegation summary (reference to full UCAN token) */
export interface DelegationSummary {
  delegator: string
  capabilities: {
    resource: string
    action: string
    constraints?: Record<string, unknown>
  }[]
  expiration: string
  /** Hash of the full UCAN JWT */
  tokenHash: string
  /** Delegation chain depth (0 = direct from principal) */
  chainDepth?: number
}

/** Complete agent record */
export interface SovrnAgentRecord {
  agentDID: string
  identity: AgentIdentity
  credentials: SovrnAgentCredential[]
  reputation?: SovrnReputationRecord
  delegations?: DelegationSummary[]
}
