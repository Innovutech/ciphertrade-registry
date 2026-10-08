import fs from 'node:fs/promises';
import { writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import assert from 'node:assert/strict';
import { catalogDigest } from './publicationLifecycle.ts';
import { previousReviewSources, releaseReviewContext } from '../scripts/publication-review.mjs';

const oldRevision = 'a'.repeat(40), newRevision = 'b'.repeat(40);
const file = 'blockchains/ethereum/assets/0xToken/logo.png';
const url = (revision: string) => `https://raw.githubusercontent.com/trustwallet/assets/${revision}/${file}`;
const rows = [{ kind: 'token', scope: '1:token', payload: { source: 'trustwallet', revision: oldRevision, symbol: 'T', decimals: 6, logoUrl: url(oldRevision) } }];
const previous = { sequence: 123, contentDigest: catalogDigest(rows as never), records: rows.map(row => ({ statement: { kind: row.kind, scope: row.scope }, payload: row.payload })) };

test('legacy signing provenance is accepted only when the complete catalog matches the verified baseline', async t => {
  const temp = await fs.mkdtemp(path.join(os.tmpdir(), 'registry-review-context-'));
  t.after(() => fs.rm(temp, { recursive: true, force: true }));
  // The helper's relative work paths stay inside this test's temporary workspace.
  const sources = [{ name: 'registry', revision: newRevision }];
  const originalDirectory = process.cwd();
  process.chdir(temp);
  try {
    const run = (_command: string, args: string[]) => {
      if (args.includes('list')) return JSON.stringify([{ databaseId: 1 }, { databaseId: 2 }]);
      const directory = args[args.indexOf('--dir') + 1]!;
      const records = args.includes('1') ? [{ ...rows[0], payload: { ...rows[0]!.payload, decimals: 18 } }] : rows;
      writeFileSync(path.join(directory, 'prepared.json'), JSON.stringify({ schema: 1, sources, records }));
      return '';
    };
    const recovered = await previousReviewSources(previous, { sources: [] }, run);
    assert.deepEqual(recovered.sources, sources);
    const release = await releaseReviewContext(previous, (_command: string, args: string[]) => {
      if (args.includes('view')) return JSON.stringify({ publishedAt: '2026-10-08T01:34:19Z', assets: [{ name: 'review-provenance.json' }] });
      const directory = args[args.indexOf('--dir') + 1]!;
      writeFileSync(path.join(directory, 'review-provenance.json'), JSON.stringify({ schema: 1, sequence: 123, contentDigest: 'wrong', sources }));
      return '';
    });
    assert.deepEqual(release.sources, []);
    assert.equal(release.publishedAt, '2026-10-08T01:34:19Z');
  } finally { process.chdir(originalDirectory); }
});

test('missing legacy context recovers only unambiguous signed sources and does not stop review', async () => {
  const result = await previousReviewSources(previous, { sources: [] }, () => { throw new Error('Unavailable'); });
  assert.deepEqual(result.sources, [{ name: 'trustWallet', revision: oldRevision }]);
  assert.ok(result.notes.length);
  const release = await releaseReviewContext(previous, () => { throw new Error('Unavailable'); });
  assert.deepEqual(release.sources, []);
});
