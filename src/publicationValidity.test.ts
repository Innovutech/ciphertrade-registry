import test from 'node:test';
import assert from 'node:assert/strict';
import { ethers } from 'ethers';
import { MetadataVerifier, metadataDigest, type TrustPayload } from './protocol.ts';
import { emptyConfigurationFixture } from './configurationFixtures.ts';
import { catalogDigest, finalizePublication, verifyPrevious } from './publicationLifecycle.ts';
import { artifactJson, encodePrepared, decodePrepared, encodeSignedPart, decodeSignedPart } from './publicationArtifacts.ts';
import { compactPublication, preparedDigest, signPublication, signTrust, type PreparedPublication } from './publisher.ts';
import { PUBLICATION_LIFETIME, assertRecordPublication, recordExpiry } from './publicationValidity.ts';

const DAY = 86400000, now = Date.now();
const root = new ethers.SigningKey('0x' + '11'.repeat(32));
const tokens = new ethers.SigningKey('0x' + '22'.repeat(32));
const configuration = new ethers.SigningKey('0x' + '33'.repeat(32));
const descriptors = new ethers.SigningKey('0x' + '44'.repeat(32));
const roots = [{ id: 'root', publicKey: root.compressedPublicKey }];
const signingKeys = { tokens: tokens.privateKey, configuration: configuration.privateKey, descriptors: descriptors.privateKey };
const address = '0x' + '55'.repeat(20), scope = `1:${address}`;
function policy(): TrustPayload {
  return { schema: 2, sequence: 1, issuedAt: now - 1000, expiresAt: null,
    keys: [
      { id: 'tokens', publicKey: tokens.compressedPublicKey, kinds: ['token', 'asset'], notBefore: now - 2000, expiresAt: null },
      { id: 'configuration', publicKey: configuration.compressedPublicKey, kinds: ['networks', 'domains', 'classification'], notBefore: now - 2000, expiresAt: null },
      { id: 'descriptors', publicKey: descriptors.compressedPublicKey, kinds: ['descriptor'], notBefore: now - 2000, expiresAt: null },
    ], revokedDigests: [], minimumSequences: { token: 1, asset: 1, descriptor: 1, networks: 1, domains: 1, classification: 1 } };
}
const trust = (p = policy()) => signTrust(p, 'root', root.privateKey);
function prepared(): PreparedPublication {
  return { schema: 1, sequence: now, issuedAt: now, expiresAt: now + PUBLICATION_LIFETIME, sources: [], baseDigest: null,
    records: [
      ...emptyConfigurationFixture(),
      { kind: 'token', scope, payload: { chainId: 1, address, symbol: 'T', decimals: 6, spam: true } },
      { kind: 'asset', scope, payload: { chainId: 1, address, logoUrl: 'https://example.com/logo.png' } },
      { kind: 'classification', scope, payload: { chainId: 1, address, default: true, verified: true, verification: 'official' } },
      { kind: 'descriptor', scope: `${scope}:0x12345678`, payload: { display: { formats: {} } } },
      { kind: 'domains', scope: 'dapp:example.com', payload: { host: 'example.com', name: 'Example', description: null,
        canonicalUrl: 'https://example.com/', logoUrl: null, enabled: true, verified: true, source: 'ciphertrade', revision: 'a'.repeat(40),
        domainAliases: [], searchAliases: [] } },
    ] };
}

test('mixed validity survives isolated role signing, artifacts and the unchanged release schema', t => {
  const original = prepared(), signedTrust = trust();
  const p = decodePrepared(JSON.parse(artifactJson(encodePrepared(original))));
  assert.equal(preparedDigest(p), preparedDigest(original));
  const parts = [signPublication(p, preparedDigest(p), signedTrust, roots, { tokens: tokens.privateKey }, ['token', 'asset']),
    signPublication(p, preparedDigest(p), signedTrust, roots, { configuration: configuration.privateKey }, ['networks', 'domains', 'classification']),
    signPublication(p, preparedDigest(p), signedTrust, roots, { descriptors: descriptors.privateKey }, ['descriptor'])];
  const records = parts.flatMap(part => decodeSignedPart(JSON.parse(artifactJson(encodeSignedPart(part)))).records);
  const verifier = new MetadataVerifier(roots);
  verifier.acceptTrust(signedTrust, now);
  for (const row of records) {
    assertRecordPublication(row.statement, p, signedTrust.payload);
    assert.equal(row.statement.expiresAt, now + (row.statement.kind === 'domains' ? 7 : 30) * DAY);
    assert.deepEqual(Object.keys(row.statement).sort(), ['schema', 'kind', 'scope', 'keyId', 'sequence', 'issuedAt', 'expiresAt', 'digest'].sort());
    verifier.verifyRecord(row, row.statement.kind, row.statement.scope, row.statement.expiresAt - 1);
    assert.throws(() => verifier.verifyRecord(row, row.statement.kind, row.statement.scope, row.statement.expiresAt), /validity/);
  }
  const release = JSON.parse(JSON.stringify(compactPublication({ schema: 1, trust: signedTrust, records })));
  assert.deepEqual(Object.keys(release).sort(), ['schema', 'trust', 'documents', 'records'].sort());
  const prior = verifyPrevious(release, roots, now + 31 * DAY);
  assert.equal(prior.contentDigest, catalogDigest(p.records));
  assert.deepEqual(prior.records.find(row => row.statement.kind === 'descriptor')!.payload, { display: { formats: {} } });
  const future = now + 31 * DAY;
  t.mock.method(Date, 'now', () => future);
  const renewed = finalizePublication({ mode: 'renewal', previous: prior, roots, trust: signedTrust, now: future });
  const fresh = signPublication(renewed, preparedDigest(renewed), signedTrust, roots, signingKeys);
  for (const row of fresh.records) assert.equal(row.statement.expiresAt, future + (row.statement.kind === 'domains' ? 7 : 30) * DAY);
  assert.equal(verifyPrevious(compactPublication(fresh), roots, future).contentDigest, prior.contentDigest);
});

test('finite authority caps are per record and use the actual selected key', () => {
  const p = prepared(), authority = policy();
  authority.keys[0]!.expiresAt = now + 2 * DAY;
  authority.keys[2]!.expiresAt = now + 9 * DAY;
  authority.keys.push({ ...authority.keys[0]!, id: 'unused-longer-token-key', expiresAt: null });
  const signedTrust = trust(authority);
  const finalized = finalizePublication({ mode: 'changes', previous: null, reviewed: p, approvedDigest: preparedDigest(p), trust: signedTrust, roots, now });
  assert.equal(finalized.expiresAt, now + 30 * DAY);
  const signed = signPublication(finalized, preparedDigest(finalized), signedTrust, roots, signingKeys);
  for (const row of signed.records) {
    const days = row.statement.kind === 'token' || row.statement.kind === 'asset' ? 2 : row.statement.kind === 'descriptor' ? 9 : row.statement.kind === 'domains' ? 7 : 30;
    assert.equal(row.statement.expiresAt, now + days * DAY);
    assertRecordPublication(row.statement, finalized, authority);
  }
  for (const schema of [1, 2] as const) {
    const finite = { ...authority, schema, expiresAt: now + 5 * DAY,
      keys: authority.keys.map(key => ({ ...key, expiresAt: key.expiresAt ?? now + 60 * DAY })) };
    const result = signPublication(p, preparedDigest(p), trust(finite), roots, signingKeys);
    for (const row of result.records) assert.equal(row.statement.expiresAt, now + (['token', 'asset'].includes(row.statement.kind) ? 2 : 5) * DAY);
  }
});

test('short legacy approval windows remain binding and longer requests cannot exceed issuer policy', () => {
  for (const days of [1, 7, 90]) {
    const p = { ...prepared(), expiresAt: now + days * DAY };
    const digest = ethers.sha256(ethers.toUtf8Bytes(JSON.stringify({ schema: p.schema, sequence: p.sequence, issuedAt: p.issuedAt, expiresAt: p.expiresAt,
      sources: p.sources, records: p.records.map(row => ({ kind: row.kind, scope: row.scope, digest: metadataDigest(row.payload) })), baseDigest: null })));
    assert.equal(preparedDigest(p), digest);
    const result = signPublication(p, digest, trust(), roots, signingKeys);
    for (const row of result.records) assert.equal(row.statement.expiresAt, now + Math.min(days, row.statement.kind === 'domains' ? 7 : 30) * DAY);
    assert.throws(() => signPublication({ ...p, expiresAt: p.expiresAt + 1 }, digest, trust(), roots, signingKeys), /approved digest/);
  }
});

test('signing skips inactive configured delegates without extending another role', () => {
  const p = prepared(), authority = policy();
  const inactive = new ethers.SigningKey('0x' + '66'.repeat(32));
  for (const window of [{ notBefore: now - 2000, expiresAt: now }, { notBefore: now + DAY, expiresAt: null }]) {
    const old = { ...authority.keys[0]!, id: 'inactive', publicKey: inactive.compressedPublicKey, ...window };
    const withInactive = trust({ ...authority, keys: [old, ...authority.keys] });
    const result = signPublication(p, preparedDigest(p), withInactive, roots, { inactive: inactive.privateKey, ...signingKeys });
    assert.equal(result.records.find(row => row.statement.kind === 'token')!.statement.keyId, 'tokens');
    assert.throws(() => signPublication(p, preparedDigest(p), withInactive, roots, { inactive: inactive.privateKey }, ['token']), /Missing scoped/);
  }
});

test('assembly rejects shortened, extended, mismatched and unauthorized record windows', () => {
  const p = prepared(), authority = policy();
  const row = signPublication(p, preparedDigest(p), trust(authority), roots, signingKeys).records.find(row => row.statement.kind === 'domains')!;
  for (const change of [{ expiresAt: row.statement.expiresAt - 1 }, { expiresAt: now + 30 * DAY },
    { issuedAt: now - 1 }, { sequence: now + 1 }, { keyId: 'tokens' }]) {
    assert.throws(() => assertRecordPublication({ ...row.statement, ...change }, p, authority), /validity|authorized/);
  }
  for (const window of [{ issuedAt: 0, expiresAt: now }, { issuedAt: now, expiresAt: now }, { issuedAt: now, expiresAt: NaN }]) {
    assert.throws(() => recordExpiry(window, 'domains', 'configuration', authority), /validity/);
  }
});

test('expired finite prior trust can be revalidated only under renewed current authorization', () => {
  const authority = policy();
  authority.expiresAt = now + DAY;
  const p = prepared(), oldTrust = trust(authority);
  const prior = verifyPrevious(compactPublication(signPublication(p, preparedDigest(p), oldTrust, roots, signingKeys)), roots, now + 2 * DAY);
  const current = trust({ ...policy(), sequence: 2 });
  const renewed = finalizePublication({ mode: 'renewal', previous: prior, roots, trust: current, now: now + 2 * DAY });
  assert.equal(renewed.expiresAt, now + 32 * DAY);
  assert.equal(catalogDigest(renewed.records), prior.contentDigest);
  assert.throws(() => finalizePublication({ mode: 'renewal', previous: prior, roots, trust: oldTrust, now: now + 2 * DAY }), /validity/);
});
