import test from 'node:test';
import assert from 'node:assert/strict';
import { ethers } from 'ethers';
import { metadataDigest, signatureDigest, type MetadataKind, type TrustPayload } from './protocol.ts';
import { signTrust, signPublication, preparedDigest, compactPublication, type PreparedPublication } from './publisher.ts';
import { verifyPrevious, finalizePublication, catalogDigest } from './publicationLifecycle.ts';
import { emptyConfigurationFixture } from './configurationFixtures.ts';

const root = new ethers.SigningKey('0x' + '11'.repeat(32));
const key = new ethers.SigningKey('0x' + '22'.repeat(32));
const configurationKey = new ethers.SigningKey('0x' + '44'.repeat(32));
const roots = [{ id: 'root', publicKey: root.compressedPublicKey }];
const now = Date.now();
const payload = { chainId: 1, address: '0x' + '33'.repeat(20), symbol: 'T', decimals: 6 };
const policy: TrustPayload = { schema: 2, sequence: 1, issuedAt: now - 1000, expiresAt: null,
  keys: [{ id: 'token', publicKey: key.compressedPublicKey, kinds: ['token'], notBefore: now - 2000, expiresAt: null },
    { id: 'configuration', publicKey: configurationKey.compressedPublicKey, kinds: ['networks', 'domains', 'classification'], notBefore: now - 2000, expiresAt: null }], revokedDigests: [],
  minimumSequences: { token: 1, asset: 1, descriptor: 1, networks: 1, domains: 1, classification: 1 } };
const trust = (p = policy) => signTrust(p, 'root', root.privateKey);
const prepared: PreparedPublication = { schema: 1, sequence: 2, issuedAt: now, expiresAt: now + 60000,
  sources: [{ name: 'fixture', revision: 'a'.repeat(40) }], records: [{ kind: 'token', scope: `1:${payload.address}`, payload }, ...emptyConfigurationFixture()] };
const publication = () => signPublication(prepared, preparedDigest(prepared), trust(), roots, { token: key.privateKey, configuration: configurationKey.privateKey });
const previous = () => verifyPrevious(publication(), roots, now);

function legacyPublication() {
  const sign = (kind: MetadataKind, scope: string, payload: unknown) => {
    const statement = { schema: 1 as const, kind, scope, keyId: 'configuration', sequence: 2,
      issuedAt: now, expiresAt: now + 60000, digest: metadataDigest(payload) };
    return { payload, statement, signature: configurationKey.sign(signatureDigest('record', statement)).compactSerialized };
  };
  return { ...publication(), records: [publication().records[0]!,
    sign('networks', 'chains', { '1': { name: 'Ethereum', nativeSymbol: 'ETH', rpcUrl: 'https://rpc.example.com', supportsSwap: true } }),
    sign('domains', 'domains', { origins: [] }),
  ] };
}

test('old signed configuration authenticates change-review history but cannot become active or renew', () => {
  const old = verifyPrevious(legacyPublication(), roots, now);
  assert.equal(old.sequence, 2);
  assert.throws(() => finalizePublication({ mode: 'renewal', previous: old, roots, trust: trust(), now }), /Incomplete|metadata format/);
  const reviewed = { ...prepared, baseDigest: old.contentDigest };
  const next = finalizePublication({ mode: 'changes', previous: old, reviewed, approvedDigest: preparedDigest(reviewed), roots, trust: trust(), now });
  const published = signPublication(next, preparedDigest(next), trust(), roots, { token: key.privateKey, configuration: configurationKey.privateKey });
  assert.ok(verifyPrevious(published, roots, now).sequence > old.sequence);
});

test('historical config still rejects modified payloads, forged proofs, wrong roles and mixed schemas', () => {
  const old = legacyPublication();
  for (const mutate of [
    (p: ReturnType<typeof legacyPublication>) => { p.records[1]!.payload = { '1': { name: 'Forged', nativeSymbol: 'ETH', rpcUrl: 'https://attacker.example.com' } }; },
    (p: ReturnType<typeof legacyPublication>) => { p.records[1]!.signature = root.sign(signatureDigest('record', p.records[1]!.statement)).compactSerialized; },
    (p: ReturnType<typeof legacyPublication>) => { p.records[1]!.statement.keyId = 'token'; p.records[1]!.signature = key.sign(signatureDigest('record', p.records[1]!.statement)).compactSerialized; },
  ]) {
    const p = structuredClone(old);
    mutate(p);
    assert.throws(() => verifyPrevious(p, roots, now), /digest|signature|not authorized/i);
  }
  const mixed = structuredClone(old);
  const payload = { '1': { name: 'Mixed', nativeSymbol: 'ETH', rpcUrl: 'https://rpc.example.com', swapRoutes: [] } };
  mixed.records[1]!.payload = payload;
  mixed.records[1]!.statement.digest = metadataDigest(payload);
  mixed.records[1]!.signature = configurationKey.sign(signatureDigest('record', mixed.records[1]!.statement)).compactSerialized;
  assert.throws(() => verifyPrevious(mixed, roots, now), /metadata format/);
});

test('automatic renewal preserves every approved payload and works after record expiry', () => {
  const prior = previous();
  const future = now + 86400000;
  const renewed = finalizePublication({ mode: 'renewal', previous: prior, roots, trust: trust(), now: future });
  assert.deepEqual(renewed.records, prepared.records);
  assert.equal(renewed.sequence, future);
  assert.equal(renewed.expiresAt, future + 7 * 86400000);
  assert.equal(catalogDigest(renewed.records), prior.contentDigest);
});
test('unattended renewal cannot import an unsigned candidate or bootstrap without approval', () => {
  assert.throws(() => finalizePublication({ mode: 'renewal', previous: null, roots, trust: trust(), now }), /previous/);
  assert.throws(() => finalizePublication({ mode: 'renewal', previous: previous(), roots, trust: trust(), now, reviewed: prepared }), /only/);
  const tampered = structuredClone(publication());
  tampered.records[0]!.payload = { ...payload, decimals: 18 };
  assert.throws(() => verifyPrevious(tampered, roots), /digest/);
  const duplicate = publication();
  duplicate.records.push(duplicate.records[0]!);
  assert.throws(() => verifyPrevious(duplicate, roots), /Duplicate/);
});
test('revoked payloads, removed/changed keys and raised floors cannot silently renew', () => {
  for (const change of [{ revokedDigests: [metadataDigest(payload)] }, { keys: [] },
    { keys: [{ ...policy.keys[0]!, publicKey: root.compressedPublicKey }] },
    { minimumSequences: { ...policy.minimumSequences, token: 3 } }]) {
    assert.throws(() => finalizePublication({ mode: 'renewal', previous: previous(), roots, now, trust: trust({ ...policy, ...change, sequence: 2 }) }), /no longer authorized/);
  }
});
test('pending approved changes survive intervening identical renewals, but not different catalog changes', () => {
  const prior = previous();
  const reviewed = structuredClone(prepared);
  reviewed.baseDigest = prior.contentDigest;
  reviewed.records[0]!.payload = { ...payload, symbol: 'APPROVED' };
  const options = { mode: 'changes' as const, reviewed, approvedDigest: preparedDigest(reviewed), previous: { ...prior, sequence: now + 1 }, roots, trust: trust(), now };
  assert.equal(finalizePublication(options).sequence, now + 2);
  assert.deepEqual(finalizePublication(options).records, reviewed.records);
  assert.throws(() => finalizePublication({ ...options, previous: { ...prior, contentDigest: 'different' } }), /superseded/);
  reviewed.records[0]!.payload = { ...payload, symbol: 'NOT-APPROVED' };
  assert.throws(() => finalizePublication(options), /snapshot changed/);
});
test('record version allocation, legacy authorization deadline and compact history remain valid', () => {
  const compact = compactPublication(publication());
  assert.equal(verifyPrevious(compact, roots).contentDigest, previous().contentDigest);
  const finite = { ...policy, sequence: 2, schema: 1 as const, expiresAt: now + 10000,
    keys: policy.keys.map(key => ({ ...key, expiresAt: now + 10000 })) };
  const result = finalizePublication({ mode: 'renewal', previous: previous(), roots, trust: trust(finite), now });
  assert.equal(result.expiresAt, finite.expiresAt);
  assert.throws(() => finalizePublication({ mode: 'renewal', previous: previous(), roots, trust: trust(finite), now: now + 10001 }), /validity/);
});

test('a pre-migration approved publication cannot renew or publish without complete configuration', () => {
  const legacy = publication();
  legacy.records = legacy.records.filter(row => row.statement.kind === 'token');
  const old = verifyPrevious(legacy, roots, now);
  assert.throws(() => finalizePublication({ mode: 'renewal', previous: old, roots, trust: trust(), now }), /Incomplete/);
  const incomplete = { ...prepared, records: prepared.records.filter(row => row.kind === 'token') };
  assert.throws(() => signPublication(incomplete, preparedDigest(incomplete), trust(), roots, { token: key.privateKey }), /Incomplete/);
  assert.throws(() => compactPublication(legacy), /Incomplete/);
});
