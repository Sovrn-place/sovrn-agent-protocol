#!/usr/bin/env node
/**
 * Public-safe opacity check for the Sovrn Agent Protocol publication.
 *
 * This is the PUBLIC CI gate. It contains NO private vocabulary — it enforces
 * STRUCTURAL PATTERN CLASSES only. The authoritative gate (a runtime denylist
 * built from Sovrn's proprietary reputation module) is private and does not
 * live in this repository.
 *
 * Pattern classes (any hit fails the build):
 *   1. A reputation `tier` field whose value is an enum-shaped token
 *      (UPPER_SNAKE) rather than an opaque token. Published tiers MUST be
 *      opaque (e.g. "opaque-tier-token-a"), never the private ladder names.
 *   2. A `kycProvider` / KYC `provider` field naming a concrete vendor rather
 *      than an opaque identifier. Published provider references MUST be opaque
 *      (e.g. "opaque-provider-id").
 *   3. An `assuranceLevel` field appearing anywhere in a schema or example.
 *      Assurance level is a Gov Mode (proprietary, Layer 4) concept and MUST
 *      NOT surface in the open Play Mode artifacts.
 *
 * Scope: every .json / .jsonld under schemas/, examples/, contexts/, and the
 * conformance corpus under tests/fixtures/. Docs (.md) are prose and are not
 * pattern-scanned here (the private gate covers prose).
 *
 * License: Apache-2.0.
 */

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, extname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(fileURLToPath(import.meta.url), '..', '..');

const SCAN_DIRS = ['schemas', 'examples', 'contexts', 'tests/fixtures'];
const SCAN_EXTS = new Set(['.json', '.jsonld']);

function walk(dir) {
  let out = [];
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const e of entries) {
    const full = join(dir, e.name);
    if (e.isDirectory()) {
      if (e.name === 'node_modules' || e.name === '.git') continue;
      out = out.concat(walk(full));
    } else if (SCAN_EXTS.has(extname(e.name))) {
      out.push(full);
    }
  }
  return out;
}

// --- pattern classes (structural; no private vocabulary) ---
const CHECKS = [
  {
    id: 'tier-enum-shaped',
    // "tier": "SOMETHING_UPPER" — an enum-shaped tier value is a leak; opaque
    // tokens (lowercase, hyphenated) pass. Require >= 3 chars to avoid matching
    // single-letter placeholders.
    re: /"tier"\s*:\s*"([A-Z][A-Z_]{2,})"/g,
    msg: 'reputation "tier" carries an enum-shaped (UPPER_SNAKE) value; published tiers must be opaque tokens',
  },
  {
    id: 'named-kyc-provider',
    // A kycProvider / provider value in INSTANCE DATA that is NOT an opaque
    // identifier. Opaque = contains "opaque", a bare placeholder, or a
    // namespace-prefixed CURIE/IRI (e.g. "sovrn:provider" in a JSON-LD context
    // term mapping — a vocabulary definition, not a vendor name). Anything else
    // (a real vendor name) fails. Skipped on .jsonld files entirely: contexts
    // define terms, they do not carry instance values.
    re: /"(?:kycProvider|provider)"\s*:\s*"([^"]+)"/g,
    msg: 'a KYC provider field names a concrete value; published provider references must be opaque identifiers',
    skipJsonLd: true,
    allow: (v) => /opaque/i.test(v) || v === 'example-provider' || /^[a-z][a-z0-9]*:/i.test(v),
  },
  {
    id: 'assurance-level-present',
    re: /"assuranceLevel"\s*:/g,
    msg: 'assuranceLevel is a Gov Mode (proprietary) field and must not appear in open Play Mode artifacts',
  },
];

const files = SCAN_DIRS.flatMap((d) => walk(join(ROOT, d)));
let hits = 0;

for (const file of files) {
  if (statSync(file).isDirectory()) continue;
  const content = readFileSync(file, 'utf8');
  const rel = relative(ROOT, file).split('\\').join('/');
  const isJsonLd = extname(file) === '.jsonld';
  for (const check of CHECKS) {
    if (check.skipJsonLd && isJsonLd) continue;
    check.re.lastIndex = 0;
    let m;
    while ((m = check.re.exec(content)) !== null) {
      const captured = m[1];
      if (check.allow && captured !== undefined && check.allow(captured)) continue;
      console.error(`LEAK [${check.id}] ${rel}: ${check.msg}${captured !== undefined ? ` (value: ${JSON.stringify(captured)})` : ''}`);
      hits++;
    }
  }
}

console.log(`opacity-check: scanned ${files.length} files across ${SCAN_DIRS.join(', ')}`);
if (hits > 0) {
  console.error(`opacity-check: ${hits} pattern-class violation(s) — publication blocker`);
  process.exit(1);
}
console.log('opacity-check: clean (pattern classes only; the authoritative denylist gate is private)');
