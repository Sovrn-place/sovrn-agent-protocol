/**
 * Sovrn Agent Protocol — MCP Server Reference Implementation
 * Production CheckProviders — the real wiring behind the engine.
 *
 * v0.1.0 FLOOR (real): DID resolution (did:sovrn primary / did:web
 * accepted-input, hard-fail no fallback), Data Integrity eddsa-jcs-2022
 * verification per proof[] entry, SD-JWT-VC envelope verification, UCAN 0.10
 * JWT signature verification per link, time bounds, chain invariant, resource
 * matching, bitstring status decoding.
 *
 * INJECTABLE (design §11): the status-list source, the UCAN blocklist, and
 * the B8 cross-protocol root-principal oracle. Absent a B8 oracle the
 * provider returns VERIFIED — integrators gating real invocations MUST inject
 * a real root-principal source (documented in docs/extension-points.md).
 *
 * License: Apache-2.0.
 */

import type { CheckProviders } from '../engine/types.js';
import {
  getLinkPayload,
  resourceMatches,
  timeBoundsStatus,
  chainInvariantStatus,
} from '../engine/checks.js';
import { resolveDidDocument, selectVerificationMethod, type DidDocument, type DidResolverOptions } from '../did/resolve.js';
import { ed25519FromMultibase } from '../crypto/keys.js';
import { verifyEddsaJcs2022, type DataIntegrityProof } from '../crypto/data-integrity.js';
import { verifySdJwtVc } from '../crypto/sd-jwt.js';
import { verifyUcanJwtSignature, ucanTokenId, StaticBlocklist, type UcanBlocklist } from '../crypto/ucan.js';
import { StaticStatusSource, type CredentialStatusSource } from './status.js';

export interface ProductionProviderConfig {
  /** did:sovrn registry endpoint (Layer 0). Required to resolve did:sovrn. */
  sovrnRegistryUrl?: string;
  /**
   * Static DID-document trust store (did -> document), checked BEFORE network
   * resolution. For local evaluation, tests, and air-gapped demos. Still
   * hard-fail: a DID absent from the store falls through to (and only to) its
   * own method's network resolution — never another method.
   */
  staticDidDocuments?: Record<string, DidDocument>;
  /** Issuer trusted list for the A6 normative check (zone-authority DIDs). */
  trustedIssuers?: string[];
  /** Static credential-status source inputs (see StaticStatusSource). */
  revokedCredentialIds?: string[];
  statusLists?: Record<string, string>;
  /** Or a fully custom status source (e.g. a live BitstringStatusList fetcher). */
  statusSource?: CredentialStatusSource;
  /** UCAN-native blocklist (token ids per ucanTokenId). */
  revokedDelegationTokenIds?: string[];
  blocklist?: UcanBlocklist;
  /** Revoked embedded evidence[] link ids (the cross-layer walk arm). */
  revokedEvidenceLinkIds?: string[];
  /** Authority key generations: authority DID -> current generation (L1 D8). */
  authorityKeyGenerations?: Record<string, number>;
  /** B8 cross-protocol root-principal oracle (INJECT for real gating). */
  rootPrincipalOracle?: (chain: unknown[], credential: unknown) => Promise<'VERIFIED' | 'NOT_VERIFIED'>;
  /** Reputation epoch overlap window in seconds (L3 §6 / master §9.6). */
  epochOverlapSeconds?: number;
  /** Verifier trust profile: minimum issuance method (master §9.1 guidance). */
  minIssuanceMethod?: 'SELF_ATTESTED' | 'COMMUNITY_ATTESTED' | 'ZONE_ISSUED';
  /** Clock (seconds since epoch); injectable for tests. */
  clock?: () => number;
  /** DID resolver options passthrough (fetchFn, allowInsecureLocalhost). */
  didResolver?: Omit<DidResolverOptions, 'sovrnRegistryUrl'>;
}

const ISSUANCE_RANK: Record<string, number> = { SELF_ATTESTED: 0, COMMUNITY_ATTESTED: 1, ZONE_ISSUED: 2 };

function issuerId(credential: unknown): string | undefined {
  const issuer = (credential as { issuer?: unknown } | null | undefined)?.issuer;
  if (typeof issuer === 'string') return issuer;
  const id = (issuer as { id?: unknown } | null | undefined)?.id;
  return typeof id === 'string' ? id : undefined;
}

function subjectField(credential: unknown, field: string): unknown {
  const subject = (credential as { credentialSubject?: Record<string, unknown> } | null | undefined)?.credentialSubject;
  return subject?.[field];
}

function vmToJwk(doc: DidDocument, methodId?: string): Record<string, unknown> {
  const method = selectVerificationMethod(doc, methodId);
  if (method.publicKeyJwk) return method.publicKeyJwk;
  if (method.publicKeyMultibase) {
    const raw = ed25519FromMultibase(method.publicKeyMultibase);
    return { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(raw).toString('base64url') };
  }
  throw new Error(`verification method ${method.id} carries no supported key material`);
}

export interface ProductionContext {
  providers: CheckProviders;
  /** DID-document-backed issuer key resolver (shared with the UCAN gate). */
  resolveIssuerJwk: (iss: string, kid?: string) => Promise<Record<string, unknown>>;
}

export function productionProviders(config: ProductionProviderConfig = {}): CheckProviders {
  return productionContext(config).providers;
}

export function productionContext(config: ProductionProviderConfig = {}): ProductionContext {
  const clock = config.clock ?? ((): number => Math.floor(Date.now() / 1000));
  const resolverOpts: DidResolverOptions = { ...config.didResolver, sovrnRegistryUrl: config.sovrnRegistryUrl };
  const statusSource =
    config.statusSource ?? new StaticStatusSource(config.revokedCredentialIds ?? [], config.statusLists ?? {});
  const blocklist = config.blocklist ?? new StaticBlocklist(config.revokedDelegationTokenIds ?? []);
  const revokedEvidence = new Set(config.revokedEvidenceLinkIds ?? []);
  const didCache = new Map<string, DidDocument>();

  async function resolveDoc(did: string): Promise<DidDocument> {
    const cached = didCache.get(did);
    if (cached) return cached;
    const staticDoc = config.staticDidDocuments?.[did];
    if (staticDoc) {
      didCache.set(did, staticDoc);
      return staticDoc;
    }
    const doc = await resolveDidDocument(did, resolverOpts);
    didCache.set(did, doc);
    return doc;
  }

  async function resolveIssuerJwk(iss: string, kid?: string): Promise<Record<string, unknown>> {
    return vmToJwk(await resolveDoc(iss), kid);
  }

  const providers: CheckProviders = {
    async resolveDid(did) {
      if (did === undefined) return 'UNRESOLVABLE';
      try {
        await resolveDoc(did);
        return 'RESOLVED';
      } catch {
        return 'UNRESOLVABLE';
      }
    },

    async verifyCredentialProof(proof, credential) {
      // Envelope path: no embedded proof[] — the credential must itself be a
      // compact SD-JWT-VC whose JWS envelope carries the integrity.
      if (proof === undefined) {
        if (typeof credential !== 'string') return 'INVALID';
        const result = await verifySdJwtVc(credential, resolveIssuerJwk);
        return result.valid ? 'VALID' : 'INVALID';
      }
      const p = proof as DataIntegrityProof;
      const vmId = p.verificationMethod;
      const controller = typeof vmId === 'string' ? vmId.split('#')[0] : undefined;
      if (!controller) return 'INVALID';
      try {
        const jwk = vmToJwk(await resolveDoc(controller), vmId);
        return verifyEddsaJcs2022(credential as Record<string, unknown>, p, jwk) ? 'VALID' : 'INVALID';
      } catch {
        return 'INVALID';
      }
    },

    async verifyDelegationSignature(link) {
      return verifyUcanJwtSignature(link, resolveIssuerJwk);
    },

    async credentialStatus(credential) {
      return statusSource.credentialStatus(credential);
    },

    async authorityKeyGeneration(credential) {
      const authority = issuerId(credential);
      const generations = config.authorityKeyGenerations ?? {};
      if (!authority || !(authority in generations)) return 'CURRENT';
      const embedded = subjectField(credential, 'authorityKeyGeneration') ?? (credential as Record<string, unknown>)?.authorityKeyGeneration;
      if (typeof embedded !== 'number') return 'CURRENT';
      return embedded < generations[authority] ? 'STALE' : 'CURRENT';
    },

    async crossLayerWalk(credential) {
      const evidence = subjectField(credential, 'evidence') ?? (credential as { evidence?: unknown } | null | undefined)?.evidence;
      if (!Array.isArray(evidence)) return 'CLEAR';
      for (const link of evidence) {
        let id: string;
        if (typeof (link as { id?: unknown })?.id === 'string') {
          id = (link as { id: string }).id;
        } else {
          // ucanTokenId hashes the link's canonical form; a hostile
          // deeply-nested evidence entry can make canonicalization throw
          // (adversarial H2). Fail closed: an un-identifiable evidence link
          // is treated as revoked, never as a crash and never silently CLEAR.
          try {
            id = ucanTokenId(link);
          } catch {
            return 'REVOKED_LINK';
          }
        }
        if (revokedEvidence.has(id)) return 'REVOKED_LINK';
      }
      return 'CLEAR';
    },

    async linkTimeBounds(link) {
      return timeBoundsStatus(getLinkPayload(link), clock());
    },

    async chainInvariant(chain, invokerDid) {
      return chainInvariantStatus(chain, invokerDid).status;
    },

    async resourceMatch(attWith, targetResource) {
      return resourceMatches(attWith, targetResource) ? 'MATCH' : 'MISMATCH';
    },

    async delegationRevocation(link) {
      return (await blocklist.isRevoked(ucanTokenId(link))) ? 'REVOKED' : 'CLEAR';
    },

    async rootPrincipalStatus(chain, credential) {
      if (config.rootPrincipalOracle) return config.rootPrincipalOracle(chain, credential);
      // Impl-defined at v0.1.0 (resolution algorithm §5). Without an injected
      // oracle the reference verifier does not block on B8 — integrators
      // gating real invocations MUST inject one. Loudly documented.
      return 'VERIFIED';
    },

    async resolveMode(credential) {
      const trusted = (config.trustedIssuers ?? []).includes(issuerId(credential) ?? '');
      const zoneIssued = subjectField(credential, 'issuanceMethod') === 'ZONE_ISSUED';
      // §9.2 seam (3-signal rule): the issuer-trusted-list check is NORMATIVE;
      // seam recognition is guidance. GOV requires both signals; a ZONE_ISSUED
      // claim from an issuer absent from the trusted list is the ambiguous seam.
      return { mode: trusted && zoneIssued ? 'GOV' : 'PLAY', seamAmbiguous: zoneIssued && !trusted };
    },

    async reputationEpoch(reputationVC) {
      // The reputation VC is OPAQUE (Layer 3 out of scope): only the envelope
      // validity window is read — never tier, dimensions, or scores.
      const validUntil = (reputationVC as { validUntil?: unknown } | null | undefined)?.validUntil;
      if (typeof validUntil !== 'string') return null;
      const boundary = Math.floor(Date.parse(validUntil) / 1000);
      if (Number.isNaN(boundary)) return null;
      const now = clock();
      return {
        pastValidUntil: now > boundary,
        insideOverlapWindow: now <= boundary + (config.epochOverlapSeconds ?? 0),
      };
    },

    async trustProfileThreshold(credential) {
      if (!config.minIssuanceMethod) return 'MET';
      const method = subjectField(credential, 'issuanceMethod');
      const rank = typeof method === 'string' ? ISSUANCE_RANK[method] : undefined;
      if (rank === undefined) return 'UNMET';
      return rank >= ISSUANCE_RANK[config.minIssuanceMethod] ? 'MET' : 'UNMET';
    },
  };

  return { providers, resolveIssuerJwk };
}
