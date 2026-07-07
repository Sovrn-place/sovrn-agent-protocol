/**
 * Sovrn Agent Protocol — MCP Server Reference Implementation
 * Layer 0 DID resolution (design-of-record: Layer 0 §4).
 *
 * `did:sovrn:` is PRIMARY NORMATIVE (resolved against a configurable registry
 * endpoint); `did:web` is ACCEPTED-INPUT (RFC-style HTTPS resolution). The
 * asymmetry is deliberate and the failure mode is HARD-FAIL with NO
 * cross-method fallback — a resolution failure never silently downgrades to
 * another method (closes the downgrade attack, Layer 0 JC1).
 *
 * License: Apache-2.0.
 */

export interface DidVerificationMethod {
  id: string;
  type?: string;
  controller?: string;
  publicKeyJwk?: Record<string, unknown>;
  publicKeyMultibase?: string;
}

export interface DidDocument {
  id: string;
  verificationMethod?: DidVerificationMethod[];
  assertionMethod?: (string | DidVerificationMethod)[];
  service?: { id?: string; type?: string; serviceEndpoint?: unknown }[];
}

export class DidResolutionError extends Error {
  constructor(
    message: string,
    readonly did: string,
  ) {
    super(message);
    this.name = 'DidResolutionError';
  }
}

export interface DidResolverOptions {
  /**
   * Resolution endpoint for `did:sovrn:` (e.g. a zone registry). The resolver
   * GETs `${sovrnRegistryUrl}/${encodeURIComponent(did)}` and expects a DID
   * document as application/json. REQUIRED to resolve did:sovrn (no default:
   * a reference verifier must be pointed at a registry explicitly).
   */
  sovrnRegistryUrl?: string;
  /** Injectable fetch (tests point this at a local ephemeral server). */
  fetchFn?: typeof fetch;
  /** Allow http:// for did:web on localhost (tests only; production is https-only). */
  allowInsecureLocalhost?: boolean;
  /** Resolution request timeout in ms (default 10s). */
  timeoutMs?: number;
  /** Maximum DID-document body size in bytes (default 256 KiB). */
  maxBytes?: number;
}

const DEFAULT_RESOLVE_TIMEOUT_MS = 10_000;
const DEFAULT_RESOLVE_MAX_BYTES = 262_144; // 256 KiB — a DID document is small

const SOVRN_DID = /^did:sovrn:(agent|citizen|zone):[^:]+$/;
const WEB_DID = /^did:web:.+$/;

// A did:web host segment: hostname (optionally with a %3A-encoded port). No
// path separators, no traversal. Validated to block SSRF / path-traversal via
// attacker-decoded segments (adversarial M2).
const DID_WEB_HOST = /^[a-zA-Z0-9.\-]+(?:%3[aA][0-9]+)?$/;
// A did:web path segment after decoding: no empty, no "." / "..", no slashes.
const DID_WEB_SEGMENT = /^[a-zA-Z0-9._\-~]+$/;

/** did:web → HTTPS URL per the did:web method spec. */
export function didWebToUrl(did: string, allowInsecureLocalhost = false): string {
  const method = did.slice('did:web:'.length);
  const rawParts = method.split(':');
  const rawHost = rawParts[0];
  if (!rawHost || !DID_WEB_HOST.test(rawHost)) {
    throw new DidResolutionError(`did:web host is empty or malformed: ${did}`, did);
  }
  // The host's %3A port is decoded; nothing else in the host is percent-decoded.
  const host = rawHost.replace(/%3[aA]/, ':');
  // Path segments are percent-decoded then re-validated so a %2F ("/") or ".."
  // cannot smuggle a path separator or traversal into the URL.
  const pathSegments = rawParts.slice(1).map((p) => {
    const decoded = decodeURIComponent(p);
    if (!DID_WEB_SEGMENT.test(decoded) || decoded === '.' || decoded === '..') {
      throw new DidResolutionError(`did:web path segment is empty, traversal, or contains a separator: ${did}`, did);
    }
    return decoded;
  });
  const hostForScheme = host.split(':')[0];
  const scheme =
    allowInsecureLocalhost && (hostForScheme === 'localhost' || hostForScheme === '127.0.0.1') ? 'http' : 'https';
  if (pathSegments.length === 0) return `${scheme}://${host}/.well-known/did.json`;
  return `${scheme}://${host}/${pathSegments.join('/')}/did.json`;
}

/**
 * Resolve a DID document. Hard-fail on: unsupported method, network error,
 * non-200, malformed document, or document id mismatch. NEVER falls back
 * across methods.
 */
export async function resolveDidDocument(did: string, opts: DidResolverOptions = {}): Promise<DidDocument> {
  const fetchFn = opts.fetchFn ?? fetch;

  let url: string;
  if (SOVRN_DID.test(did)) {
    if (!opts.sovrnRegistryUrl) {
      throw new DidResolutionError('did:sovrn resolution requires a configured registry endpoint (no fallback)', did);
    }
    url = `${opts.sovrnRegistryUrl.replace(/\/+$/, '')}/${encodeURIComponent(did)}`;
  } else if (WEB_DID.test(did)) {
    url = didWebToUrl(did, opts.allowInsecureLocalhost === true);
  } else {
    throw new DidResolutionError(`unsupported DID method (accepted: did:sovrn primary, did:web accepted-input): ${did}`, did);
  }

  let response: Response;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), opts.timeoutMs ?? DEFAULT_RESOLVE_TIMEOUT_MS);
  try {
    response = await fetchFn(url, {
      headers: { accept: 'application/json' },
      // Do NOT follow redirects: a redirect can pivot the verifier to an
      // arbitrary URL (SSRF). Manual mode surfaces the 3xx so we reject it.
      redirect: 'manual',
      signal: controller.signal,
    });
  } catch (err) {
    throw new DidResolutionError(`DID document fetch failed: ${(err as Error).message}`, did);
  } finally {
    clearTimeout(timeout);
  }
  if (response.status >= 300 && response.status < 400) {
    throw new DidResolutionError(`DID document fetch returned a redirect (${response.status}); redirects are not followed`, did);
  }
  if (!response.ok) {
    throw new DidResolutionError(`DID document fetch returned ${response.status}`, did);
  }

  // Read with a hard byte cap so an oversized/slow-drip body cannot exhaust
  // memory (adversarial M3). We stream and abort past the limit rather than
  // buffering response.json() unbounded.
  let text: string;
  try {
    text = await readCappedText(response, opts.maxBytes ?? DEFAULT_RESOLVE_MAX_BYTES);
  } catch (err) {
    throw new DidResolutionError(`DID document read failed: ${(err as Error).message}`, did);
  }

  let doc: DidDocument;
  try {
    doc = JSON.parse(text) as DidDocument;
  } catch {
    throw new DidResolutionError('DID document is not valid JSON', did);
  }
  if (typeof doc?.id !== 'string' || doc.id !== did) {
    throw new DidResolutionError('DID document id does not match the resolved DID', did);
  }
  return doc;
}

/** Read a fetch Response body as text, aborting if it exceeds maxBytes. */
async function readCappedText(response: Response, maxBytes: number): Promise<string> {
  const body = response.body;
  if (!body) return response.text();
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value) {
      total += value.length;
      if (total > maxBytes) {
        await reader.cancel();
        throw new Error(`response body exceeds the ${maxBytes}-byte limit`);
      }
      chunks.push(value);
    }
  }
  return Buffer.concat(chunks.map((c) => Buffer.from(c))).toString('utf8');
}

/**
 * Select a verification method from a resolved document. When `methodId` is
 * given (e.g. a proof's verificationMethod), it must match exactly (fragment
 * or full id); otherwise the first assertion-capable method is returned.
 */
export function selectVerificationMethod(doc: DidDocument, methodId?: string): DidVerificationMethod {
  const methods = doc.verificationMethod ?? [];
  if (methodId) {
    const found = methods.find((m) => m.id === methodId || m.id === `${doc.id}${methodId.startsWith('#') ? methodId : ''}`);
    if (!found) throw new DidResolutionError(`verification method not found: ${methodId}`, doc.id);
    return found;
  }
  if (methods.length === 0) throw new DidResolutionError('DID document has no verification methods', doc.id);
  return methods[0];
}
