import test from 'node:test';
import assert from 'node:assert/strict';
import { ethers } from 'ethers';
import { metadataDigest, type TrustPayload } from './protocol.ts';
import { signTrust, signPublication, preparedDigest, compactPublication, type PreparedPublication } from './publisher.ts';
import { verifyPrevious, finalizePublication, catalogDigest } from './publicationLifecycle.ts';

const root = new ethers.SigningKey('0x' + '11'.repeat(32));
const key = new ethers.SigningKey('0x' + '22'.repeat(32));
const roots = [{ id: 'root', publicKey: root.compressedPublicKey }];
const now = Date.now();
const payload = { chainId: 1, address: '0x' + '33'.repeat(20), symbol: 'T', decimals: 6 };
const policy: TrustPayload = { schema: 2, sequence: 1, issuedAt: now - 1000, expiresAt: null,
  keys: [{ id: 'token', publicKey: key.compressedPublicKey, kinds: ['token'], notBefore: now - 2000, expiresAt: null }], revokedDigests: [],
  minimumSequences: { token: 1, asset: 1, descriptor: 1, networks: 1, domains: 1, classification: 1 } };
const trust = (p = policy) => signTrust(p, 'root', root.privateKey);
const prepared: PreparedPublication = { schema: 1, sequence: 2, issuedAt: now, expiresAt: now + 60000,
  sources: [{ name: 'fixture', revision: 'a'.repeat(40) }], records: [{ kind: 'token', scope: `1:${payload.address}`, payload }] };
const publication = () => signPublication(prepared, preparedDigest(prepared), trust(), roots, { token: key.privateKey });
const previous = () => verifyPrevious(publication(), roots, now);

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
    keys: [{ ...policy.keys[0]!, expiresAt: now + 10000 }] };
  const result = finalizePublication({ mode: 'renewal', previous: previous(), roots, trust: trust(finite), now });
  assert.equal(result.expiresAt, finite.expiresAt);
  assert.throws(() => finalizePublication({ mode: 'renewal', previous: previous(), roots, trust: trust(finite), now: now + 10001 }), /validity/);
});
