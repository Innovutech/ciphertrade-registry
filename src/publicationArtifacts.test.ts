import test from 'node:test';
import assert from 'node:assert/strict';
import { ethers } from 'ethers';
import { artifactJson, encodePrepared, decodePrepared, encodeSignedPart, decodeSignedPart } from './publicationArtifacts.ts';
import { metadataDigest } from './protocol.ts';
import { preparedDigest, type PreparedPublication } from './publisher.ts';
import { publicationReport } from './publicationReport.ts';

const payload = { metadata: { description: 'x'.repeat(175 * 1024) } };
const candidate = (count = 1): PreparedPublication => ({ schema: 1, sequence: 1, issuedAt: 1, expiresAt: 2,
  sources: [{ name: 'registry', revision: 'a'.repeat(40) }], baseDigest: null,
  records: Array.from({ length: count }, (_, n) => ({ kind: 'descriptor', scope: `scope-${n}`, payload })) });

test('thousands of near-limit descriptor scopes serialize once and preserve the exact approval digest', () => {
  const original = candidate(4000);
  const encoded = artifactJson(encodePrepared(original));
  assert.ok(Buffer.byteLength(encoded) < 1024 * 1024);
  const decoded = decodePrepared(JSON.parse(encoded));
  assert.equal(decoded.records.length, 4000);
  assert.equal(decoded.records[0]!.payload, decoded.records[3999]!.payload);
  assert.equal(preparedDigest(decoded), preparedDigest(original));
  const documentDigest = metadataDigest(payload);
  const expected = ethers.sha256(ethers.toUtf8Bytes(JSON.stringify({ schema: 1, sequence: 1, issuedAt: 1, expiresAt: 2,
    sources: original.sources, records: original.records.map(row => ({ kind: row.kind, scope: row.scope, digest: documentDigest })), baseDigest: null })));
  assert.equal(preparedDigest(decoded), expected);
});

test('legacy inline artifacts remain readable and missing, tampered, mixed or unused references fail', () => {
  const original = candidate();
  assert.deepEqual(decodePrepared(JSON.parse(JSON.stringify(original))), original);
  const good = encodePrepared(original);
  const ref = Object.keys(good.documents)[0]!;
  const corrupt = () => JSON.parse(JSON.stringify(good));
  let bad = corrupt(); delete bad.documents[ref]; assert.throws(() => decodePrepared(bad));
  bad = corrupt(); bad.documents[ref].metadata.description = 'tampered'; assert.throws(() => decodePrepared(bad), /digest mismatch/);
  bad = corrupt(); bad.records[0].payload = payload; assert.throws(() => decodePrepared(bad));
  bad = corrupt(); bad.records[0].kind = 'token'; assert.throws(() => decodePrepared(bad));
  bad = corrupt(); bad.documents['0x' + '0'.repeat(64)] = {}; assert.throws(() => decodePrepared(bad), /Unused/);
});

test('signed role artifacts preserve every statement and signature while enforcing document references', () => {
  const row = { payload, statement: { kind: 'descriptor', scope: 'scope', digest: metadataDigest(payload) }, signature: 'opaque-signature' };
  const part = { schema: 1, trust: {}, records: [row] } as any;
  const encoded = encodeSignedPart(part);
  assert.deepEqual(decodeSignedPart(JSON.parse(artifactJson(encoded))), part);
  assert.deepEqual(decodeSignedPart(part), part);
  const bad = JSON.parse(artifactJson(encoded));
  bad.records[0].statement.digest = '0x' + '0'.repeat(64);
  assert.throws(() => decodeSignedPart(bad), /Invalid artifact reference/);
});

test('review reports retain every new descriptor scope without duplicating its document', () => {
  const report = publicationReport(candidate(4000));
  assert.equal(report.added.length, 4000);
  assert.equal(Object.keys(report.descriptorPayloads).length, 1);
  assert.ok(Buffer.byteLength(JSON.stringify(report)) < 1024 * 1024);
  for (const row of report.additions) assert.deepEqual(report.descriptorPayloads[row.afterRef!], payload);
  assert.equal(report.capacity.uniqueDescriptorDocuments, 1);
  assert.ok(report.notes.some(note => note.includes('Descriptor capacity')));
});
