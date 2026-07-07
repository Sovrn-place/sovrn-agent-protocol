/**
 * Sovrn Agent Protocol — MCP Server Reference Implementation
 * Conformance runner — drives the reference engine through the frozen Step 7
 * fixture suite (40 bundles) and gates on the acceptance bar (design §9):
 *
 *   - 100% of the MUST set (positives → ACCEPT/PERMIT; negatives →
 *     REJECT/DENY) with EXACT citedRule (JC-F3).
 *   - The graded set surfaces the named graded signal without hard-blocking.
 *   - DIFFERENTIAL check: every engine verdict is also compared against the
 *     frozen MockVerifier's verdict for the same bundle. The mock is a free
 *     second oracle — any misread of the harness's ordering or field-presence
 *     semantics fails loudly here.
 *
 * Run from the package root:  npm run conformance   (tsx conformance/run.ts)
 * Exits non-zero on any failure. Fixtures are NEVER modified.
 *
 * Path note: in the protocol repo this file lives at
 * reference-implementations/mcp-server/conformance/ and the fixture suite at
 * tests/fixtures/agent-protocol/ (repo root) — three levels up. All filesystem
 * paths go through fileURLToPath + path.join (the local dev path contains a
 * space; never string-concatenate file URLs).
 *
 * License: Apache-2.0.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { strict as assert } from 'node:assert';

import { procedureA } from '../src/engine/procedure-a.js';
import { procedureB } from '../src/engine/procedure-b.js';
import type { Verdict } from '../src/engine/types.js';
import { providersFromOracle } from './fixture-adapter.js';

import { MANIFEST } from '../../../tests/fixtures/agent-protocol/manifest.js';
import { MockVerifier } from '../../../tests/fixtures/agent-protocol/mock-verifier.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = path.resolve(HERE, '..', '..', '..', 'tests', 'fixtures', 'agent-protocol');
const BUNDLES_DIR = path.join(FIXTURES_DIR, 'bundles');

interface Failure {
  bundle: string;
  expected: Verdict;
  engine: Verdict;
  mock: Verdict;
  reason: string;
}

function loadBundle(rel: string): any {
  return JSON.parse(fs.readFileSync(path.join(BUNDLES_DIR, ...rel.split('/')), 'utf8'));
}

async function main(): Promise<void> {
  const mock = new MockVerifier();
  let passed = 0;
  const failures: Failure[] = [];

  for (const spec of MANIFEST) {
    const bundle = loadBundle(spec.bundle);
    const providers = providersFromOracle(bundle._oracle);

    let engineVerdict: Verdict;
    let mockVerdict: Verdict;
    if (spec.procedure === 'A') {
      const input = { credential: bundle.credential, reputationVC: bundle.reputationVC };
      engineVerdict = (await procedureA(input, providers)).verdict;
      mockVerdict = mock.procedureA({ ...input, _oracle: bundle._oracle }) as Verdict;
    } else {
      const input = {
        credential: bundle.credential,
        delegationChain: bundle.delegationChain,
        targetResource: bundle.targetResource,
      };
      engineVerdict = (await procedureB(input, providers)).verdict;
      mockVerdict = mock.procedureB({ ...input, _oracle: bundle._oracle }) as Verdict;
    }

    try {
      assert.deepStrictEqual(engineVerdict, spec.expected);
    } catch {
      failures.push({ bundle: spec.bundle, expected: spec.expected as Verdict, engine: engineVerdict, mock: mockVerdict, reason: 'engine != manifest expected (JC-F3)' });
      continue;
    }
    try {
      assert.deepStrictEqual(engineVerdict, mockVerdict);
    } catch {
      failures.push({ bundle: spec.bundle, expected: spec.expected as Verdict, engine: engineVerdict, mock: mockVerdict, reason: 'engine != mock (differential check)' });
      continue;
    }
    passed++;
  }

  const total = MANIFEST.length;
  console.log(`\nSovrn agent-protocol conformance — reference MCP-server engine`);
  console.log(`fixtures: ${total}   passed: ${passed}   failed: ${failures.length}`);

  if (failures.length > 0) {
    for (const f of failures) {
      console.error(`\nFAIL ${f.bundle} — ${f.reason}`);
      console.error(`  expected: ${JSON.stringify(f.expected)}`);
      console.error(`  engine:   ${JSON.stringify(f.engine)}`);
      console.error(`  mock:     ${JSON.stringify(f.mock)}`);
    }
    process.exit(1);
  }
  console.log('MUST set: 100% with exact citedRule. Differential vs MockVerifier: identical.\n');
}

main().catch((err) => {
  console.error('conformance runner crashed:', err);
  process.exit(1);
});
