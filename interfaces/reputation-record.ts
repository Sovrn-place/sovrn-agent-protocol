/**
 * SovrnReputationRecord — W3C VC 2.0 type for agent reputation
 * Generated from: schemas/reputation/reputation-record.v1.json
 * Version: 0.1.0
 * License: Apache-2.0
 */

/** Single reputation dimension score */
export interface DimensionScore {
  /** Implementation-defined dimension name */
  name: string
  /** Dimension score. Range is implementation-defined. */
  score: number
  /** Number of data points contributing to this score */
  sampleSize?: number
  /** Last time this dimension was updated */
  lastUpdated?: string
}

/** Per-zone reputation breakdown */
export interface ZoneScore {
  /** Zone federation identifier */
  zone: string
  /** Zone-scoped reputation score */
  score: number
  /** Number of completed actions in this zone */
  actionsCompleted: number
  /** When the agent first became active in this zone */
  activeFrom?: string
}

/** SovrnReputationRecord — time-bound reputation VC */
export interface SovrnReputationRecord {
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
    /** Aggregate reputation score. Range is implementation-defined. */
    compositeScore: number
    /** Reputation tier label. Implementation-defined. */
    tier: string
    /** Reputation dimension breakdown. Names, count, weighting implementation-defined. */
    dimensions?: DimensionScore[]
    /** Per-zone reputation breakdown */
    zoneScores?: ZoneScore[]
    /** Compliance or operational flags. Values implementation-defined. */
    flags?: string[]
    /** Monotonically increasing epoch counter. Duration implementation-defined. */
    epochNumber: number
    /** Opaque algorithm identifier */
    computationMethod?: string
    /** Hash of input data for auditability */
    computationHash?: string
    /** Hash of credential content for integrity */
    credentialHash?: string
  }
  proof?: Record<string, unknown>
}
