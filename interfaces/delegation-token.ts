/**
 * SovrnDelegationToken — UCAN 1.0 profile for human-to-agent delegation
 * Generated from: schemas/agents/delegation-token.v1.json
 * Version: 0.1.0
 * License: Apache-2.0
 */

/** UCAN capability attenuation entry */
export interface UCANAttenuation {
  /** Resource URI (e.g., sovrn:zone:zone-a, sovrn:wallet:principal) */
  with: string
  /** Action in namespace/ability format (e.g., residency/apply) */
  can: string
  /** Action-specific constraints */
  constraints?: Record<string, unknown>
}

/** Sovrn-specific facts in the delegation token */
export interface SovrnDelegationFacts {
  /** Delegation type identifier */
  sovrnDelegationType?: string
  /** Opaque principal identity level */
  principalIdentityLevel?: string
  /** Principal's .si name */
  principalSiName?: string
  /** Human-readable delegation purpose */
  delegationPurpose?: string
  [key: string]: unknown
}

/** UCAN JWT header */
export interface UCANHeader {
  alg: string
  typ: 'JWT'
  ucv: string
}

/** UCAN JWT payload */
export interface UCANPayload {
  /** Issuer DID (human principal or delegating agent) */
  iss: string
  /** Audience DID (agent receiving delegation) */
  aud: string
  /** Subject DID (principal on whose behalf agent acts) */
  sub?: string
  /** Not before (Unix timestamp) */
  nbf?: number
  /** Expiration (Unix timestamp) */
  exp: number
  /** Attenuation array. Child must be subset of parent. */
  att: UCANAttenuation[]
  /** Sovrn-specific delegation facts */
  fct?: SovrnDelegationFacts
  /** Proof chain. Parent UCAN hashes. Empty for root delegation. */
  prf: string[]
}

/** Complete UCAN delegation token */
export interface SovrnDelegationToken {
  header: UCANHeader
  payload: UCANPayload
}
