import test from 'node:test';
import assert from 'node:assert/strict';
import { publicationReport } from './publicationReport.ts';
import type { PreparedPublication } from './publisher.ts';
import type { SignedRecord } from './protocol.ts';

test('review reports semantic changes and removals without treating proof renewal as metadata edits', () => {
  const payload = { symbol: 'TEST', decimals: 6, source: 'ciphertrade', revision: 'old', logoSha256: 'same', logoUrl: 'old' };
  const records = [{ statement: { kind: 'token', scope: '1:token' }, payload }, { statement: { kind: 'classification', scope: '1:removed' }, payload: {} }] as SignedRecord[];
  const prepared = { schema: 1, sequence: 2, issuedAt: 1, expiresAt: 2, sources: [], records: [
    { kind: 'token', scope: '1:token', payload: { ...payload, revision: 'new', logoUrl: 'new' } },
  ] } as PreparedPublication;
  assert.deepEqual(publicationReport(prepared, { records }).changed, []);
  assert.deepEqual(publicationReport(prepared, { records }).removed, ['classification:1:removed']);
  (prepared.records[0]!.payload as typeof payload).decimals = 18;
  assert.deepEqual(publicationReport(prepared, { records }).changed, ['token:1:token']);
});
