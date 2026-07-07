/**
 * Sovrn Agent Protocol — MCP Server Reference Implementation
 * Canonical JSON serialization (JCS-style sorted-key form).
 *
 * Track-1 precedent: a deterministic sorted-key serializer is the protocol's
 * documented canonicalization for single-verifier deployments; full RFC 8785
 * number canonicalization is a Track-2 interop item. This serializer is
 * self-consistent for sign/verify within this implementation and for the
 * protocol's string/integer-valued documents; the RFC 8785 delta is documented
 * in docs/extension-points.md.
 *
 * License: Apache-2.0.
 */

/**
 * Maximum nesting depth. Recursion beyond this throws a bounded, catchable
 * error instead of overflowing the stack on a hostile deeply-nested document
 * (adversarial H2). No legitimate agent-protocol document nests this deep.
 */
export const MAX_CANONICAL_DEPTH = 256;

export function canonicalJson(value: unknown, depth = 0): string {
  if (depth > MAX_CANONICAL_DEPTH) {
    throw new Error(`canonicalJson: maximum nesting depth ${MAX_CANONICAL_DEPTH} exceeded`);
  }
  if (value === null || typeof value === 'number' || typeof value === 'boolean') {
    return JSON.stringify(value);
  }
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map((v) => canonicalJson(v === undefined ? null : v, depth + 1)).join(',')}]`;
  }
  if (typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, v]) => v !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v, depth + 1)}`).join(',')}}`;
  }
  throw new Error(`canonicalJson: unsupported value type ${typeof value}`);
}
