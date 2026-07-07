/**
 * Sovrn Agent Protocol — TypeScript interfaces
 * Version: 0.1.0
 * License: Apache-2.0
 */

export type {
  SovrnAgentCredential,
  AgentType,
  PrincipalType,
  IssuanceMethod,
  AgentCapability,
  VerificationStatus,
  CredentialEvidence,
  CredentialStatus,
} from './agent-credential'

export type {
  SovrnReputationRecord,
  DimensionScore,
  ZoneScore,
} from './reputation-record'

export type {
  SovrnDelegationToken,
  UCANHeader,
  UCANPayload,
  UCANAttenuation,
  SovrnDelegationFacts,
} from './delegation-token'

export type {
  SovrnAgentRecord,
  AgentIdentity,
  ServiceEndpoint,
  DelegationSummary,
} from './agent-record'
