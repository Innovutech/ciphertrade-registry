import test from 'node:test';
import assert from 'node:assert/strict';
import { publicationReport, renderPublicationReview } from './publicationReport.ts';
import { preparedDigest } from './publisher.ts';
import type { PreparedPublication } from './publisher.ts';
import type { SignedRecord } from './protocol.ts';

test('review reports semantic changes and removals without treating proof renewal as metadata edits', () => {
  const payload = { symbol: 'TEST', decimals: 6, source: 'ciphertrade', revision: 'old', logoUrl: 'old' };
  const records = [{ statement: { kind: 'token', scope: '1:token' }, payload }, { statement: { kind: 'classification', scope: '1:removed' }, payload: {} }] as SignedRecord[];
  const prepared = { schema: 1, sequence: 2, issuedAt: 1, expiresAt: 2, sources: [], records: [
    { kind: 'token', scope: '1:token', payload: { ...payload, revision: 'new' } },
  ] } as PreparedPublication;
  assert.deepEqual(publicationReport(prepared, { records }).changed, []);
  assert.deepEqual(publicationReport(prepared, { records }).removed, ['classification:1:removed']);
  (prepared.records[0]!.payload as typeof payload).logoUrl = 'new';
  assert.deepEqual(publicationReport(prepared, { records }).changed, ['token:1:token']);
  (prepared.records[0]!.payload as typeof payload).decimals = 18;
  assert.deepEqual(publicationReport(prepared, { records }).changed, ['token:1:token']);
});

const oldRevision = 'a'.repeat(40), newRevision = 'b'.repeat(40);
const logoUrl = (revision: string) => `https://raw.githubusercontent.com/trustwallet/assets/${revision}/blockchains/ethereum/assets/0xToken/logo.png`;
const snapshot = (records: PreparedPublication['records']): PreparedPublication => ({
  schema: 1, sequence: 2, issuedAt: 1, expiresAt: 2, sources: [{ name: 'trustWallet', revision: newRevision }], records,
});
const prior = (records: PreparedPublication['records']) => ({ records: records.map(row => ({ statement: { kind: row.kind, scope: row.scope }, payload: row.payload })) as SignedRecord[] });
const token = (revision: string, decimals = 6) => ({ kind: 'token' as const, scope: '1:token', payload: {
  symbol: 'T', decimals, revision, logoUrl: logoUrl(revision),
} });

test('exact pinned logo URL edits stay in the approval change list and readable report', () => {
  const prepared = snapshot([token(newRevision)]);
  const original = structuredClone(prepared), digest = preparedDigest(prepared);
  const report = publicationReport(prepared, prior([token(oldRevision)]));
  assert.deepEqual(report.changed, ['token:1:token']);
  assert.equal(report.summary.logoUrlsChanged, 1);
  assert.equal(report.summary.tokenDetailsChanged, 0);
  assert.equal(report.changes[0]!.category, 'logo-url');
  assert.deepEqual(report.changes[0]!.fields, [{ path: '/logoUrl', before: logoUrl(oldRevision), after: logoUrl(newRevision) }]);
  assert.deepEqual(prepared, original);
  assert.equal(preparedDigest(prepared), digest);
  const md = renderPublicationReview(report, digest);
  assert.ok(md.includes(logoUrl(oldRevision)));
  assert.ok(md.includes(logoUrl(newRevision)));
  assert.match(md, /Exact logo URLs changed; approval required \| 1/);
});

test('URL edits preserve the full value even beyond the general summary value limit', () => {
  const oldUrl = `https://example.org/${'a'.repeat(800)}/logo.png`, newUrl = `https://example.org/${'b'.repeat(800)}/logo.png`;
  const before = { ...token(oldRevision), payload: { ...token(oldRevision).payload, logoUrl: oldUrl } };
  const after = { ...token(newRevision), payload: { ...token(newRevision).payload, logoUrl: newUrl } };
  const report = publicationReport(snapshot([after]), prior([before]));
  const md = renderPublicationReview(report, '0x' + '2'.repeat(64), true);
  assert.equal(report.summary.logoUrlsChanged, 1);
  assert.ok(md.includes(oldUrl));
  assert.ok(md.includes(newUrl));
});

test('token and URL edits are both reported with exact before and after values', () => {
  const report = publicationReport(snapshot([token(newRevision, 18)]), prior([token(oldRevision)]));
  assert.equal(report.summary.tokenDetailsChanged, 1);
  assert.equal(report.summary.logoUrlsChanged, 1);
  assert.equal(report.changes[0]!.category, 'content');
  assert.deepEqual(report.changes[0]!.fields[0], { path: '/decimals', before: 6, after: 18 });
});

test('schema-only edits group shared descriptor documents and preserve each affected scope', () => {
  const oldPayload = { $schema: 'https://example.org/v2.json', metadata: { owner: 'Protocol', contractName: 'Router' }, display: { intent: 'Swap' } };
  const newPayload = { ...oldPayload, $schema: '../../specs/v2.json' };
  const rows = (payload: unknown) => ['1:router:swap', '10:router:swap', '1:router:deposit'].map(scope => ({ kind: 'descriptor' as const, scope, payload }));
  const report = publicationReport(snapshot(rows(newPayload)), prior(rows(oldPayload)));
  assert.equal(report.changed.length, 3);
  assert.equal(report.documents.length, 1);
  assert.equal(report.documents[0]!.records.length, 3);
  assert.equal(report.summary.descriptorSchemaDocuments, 1);
  assert.equal(report.summary.descriptorSchemaRecords, 3);
  assert.deepEqual(report.documents[0]!.fields, [{ path: '/$schema', before: oldPayload.$schema, after: newPayload.$schema }]);
  const changed = { ...newPayload, display: { intent: 'Approve' } };
  const meaningful = publicationReport(snapshot(rows(changed)), prior(rows(oldPayload)));
  assert.equal(meaningful.summary.descriptorSchemaRecords, 0);
  assert.equal(meaningful.summary.otherChangedRecords, 3);
  assert.ok(meaningful.documents[0]!.fields.some(field => field.path === '/display/intent'));
});

test('field diffs distinguish missing from null, include array reordering, additions and removals', () => {
  const old = [{ kind: 'networks' as const, scope: 'chains', payload: { nullable: null, order: [1, 2], 'a/b~c': 'before' } },
    { kind: 'classification' as const, scope: 'removed', payload: { verified: true } }];
  const next = [{ kind: 'networks' as const, scope: 'chains', payload: { inserted: null, order: [2, 1], 'a/b~c': 'after' } },
    { kind: 'classification' as const, scope: 'added', payload: { verified: false } }];
  const report = publicationReport(snapshot(next), prior(old));
  assert.deepEqual(report.additions, [{ id: 'classification:added', after: { verified: false } }]);
  assert.deepEqual(report.removals, [{ id: 'classification:removed', before: { verified: true } }]);
  assert.deepEqual(report.changes[0]!.fields, [
    { path: '/a~1b~0c', before: 'before', after: 'after' }, { path: '/inserted', after: null },
    { path: '/nullable', before: null }, { path: '/order', before: [1, 2], after: [2, 1] },
  ]);
});

test('review includes the exact baseline, source compare links and escaped before/after values', () => {
  const row = { kind: 'token' as const, scope: '1:<script>|[link]', payload: { symbol: '<img>|[click](https://evil.example)', decimals: 6 } };
  const report = publicationReport(snapshot([row]), prior([{ ...row, payload: { ...row.payload, decimals: 18 } }]), {
    repository: 'Innovutech/ciphertrade-registry', baseline: { sequence: 123, contentDigest: '0x' + '1'.repeat(64), publishedAt: '2026-10-08T01:34:19Z' },
    previousSources: [{ name: 'trustWallet', revision: oldRevision }],
  });
  const md = renderPublicationReview(report, '0x' + '2'.repeat(64), true);
  assert.match(md, /Snapshot awaiting approval/);
  assert.match(md, /releases\/tag\/metadata-123/);
  assert.ok(md.includes(`https://github.com/trustwallet/assets/compare/${oldRevision}...${newRevision}`));
  assert.match(md, /\/decimals \| 18 \| 6/);
  assert.doesNotMatch(md, /<script>|\[link\]/);
  assert.match(md, /review\.md/);
});

test('compact summary bounds details while JSON and the readable report retain every change', () => {
  const rows = Array.from({ length: 25 }, (_, index) => ({ ...token(newRevision, 18), scope: `1:${index}` }));
  const old = rows.map(row => ({ ...row, payload: { ...row.payload, decimals: 6 } }));
  const report = publicationReport(snapshot(rows), prior(old));
  assert.equal(report.changes.length, 25);
  assert.match(renderPublicationReview(report, '0x' + '2'.repeat(64), true), /Showing 20 of 25 entries/);
  assert.match(renderPublicationReview(report, '0x' + '2'.repeat(64)), /token:1:24/);
});
