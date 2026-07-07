/**
 * SovrnAgentCredential — W3C VC 2.0 type for agent identity and capabilities
 * Generated from: schemas/agents/agent-credential.v1.json
 * Version: 0.1.0
 * License: Apache-2.0
 */

/** How the credential was issued. Determines trust level. */
export type IssuanceMethod =
  | 'SELF_ATTESTED'       // Agent issued to itself. Identity only, not trust.
  | 'COMMUNITY_ATTESTED'  // Co-signed by N other agents or community members.
  | 'ZONE_ISSUED'         // Issued by a zone authority with jurisdictional binding.
  | 'ORACLE_ISSUED'       // Issued by a verification or reputation oracle.

/** Agent operational mode. Optional per Layer 1 D1 — not a trust signal. */
export type AgentType = 'AUTONOMOUS' | 'SUPERVISED' | 'DELEGATED'

/** Principal class (Layer 1 D2). Default NATURAL. */
export type PrincipalType = 'NATURAL' | 'LEGAL'

/** Agent capability with jurisdictional scope */
export interface AgentCapability {
  /** Capability action identifier */
  action: string
  /** Zone federation IDs where this capability is valid. '*' for all zones. */
  jurisdictions?: string[]
  /** Action-specific constraints (max values, approval thresholds, etc.) */
  constraints?: Record<string, unknown>
}

/** Agent verification status */
export interface VerificationStatus {
  /** Whether the principal has completed identity verification */
  principalKYC?: boolean
  /** Principal's KYC tier level */
  principalKYCTier?: number
  /** Whether the agent code has been audited */
  agentCodeAudit?: boolean
  /** Agent behavior assessment result (implementation-defined) */
  agentBehaviorStatus?: string
}

/** Evidence entry in a credential */
export interface CredentialEvidence {
  id?: string
  /** Evidence type (e.g., UCANDelegation, KYCAttestation) */
  type: string
  [key: string]: unknown
}

/** W3C BitstringStatusListEntry */
export interface CredentialStatus {
  id?: string
  type?: string
  statusPurpose?: 'revocation' | 'suspension'
  statusListIndex?: string
  statusListCredential?: string
}

/** SovrnAgentCredential — the primary credential an agent holds */
export interface SovrnAgentCredential {
  '@context': string[]
  id: string
  type: string[]
  issuer: {
    id: string
    name?: string
  }
  validFrom: string
  validUntil?: string
  credentialSubject: {
    id: string
    /** Optional per Layer 1 D1 — categorical metadata, not a trust signal */
    agentType?: AgentType
    principalDID: string
    /** Principal class (Layer 1 D2). Default NATURAL when absent. */
    principalType?: PrincipalType
    principalSiName?: string
    issuanceMethod: IssuanceMethod
    capabilities?: AgentCapability[]
    verificationStatus?: VerificationStatus
    /** Cryptographic hash with algorithm prefix (sha256:, sha3-256:, shake256:) */
    credentialHash?: string
  }
  credentialStatus?: CredentialStatus
  evidence?: CredentialEvidence[]
  /** Array of proofs (multi-proof co-signing, Layer 1 D3): index 0 issuer, 1+ co-signers */
  proof?: Record<string, unknown>[]
}
