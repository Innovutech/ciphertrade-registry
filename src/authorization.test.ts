import test from 'node:test';
import assert from 'node:assert/strict';
import { ethers } from 'ethers';
import { MetadataVerifier, metadataDigest, signatureDigest, type TrustPayload } from './protocol.ts';
import { signTrust } from './publisher.ts';

const root = new ethers.SigningKey('0x' + '11'.repeat(32));
const signer = new ethers.SigningKey('0x' + '22'.repeat(32));
const roots = [{ id: 'root', publicKey: root.compressedPublicKey }];
const now = Date.now();
const policy = (): TrustPayload => ({ schema: 2, sequence: 1, issuedAt: now - 1000, expiresAt: null,
  keys: [{ id: 'tokens', publicKey: signer.compressedPublicKey, kinds: ['token'], notBefore: now - 2000, expiresAt: null }],
  revokedDigests: [], minimumSequences: { token: 1, asset: 1, descriptor: 1, networks: 1, domains: 1, classification: 1 } });
const trust = (payload: TrustPayload) => signTrust(payload, 'root', root.privateKey);
const body = { chainId: 1, address: '0x' + '33'.repeat(20), symbol: 'T', decimals: 6 };
function record(issuedAt = now, expiresAt = issuedAt + 10000) {
  const statement = { schema: 1 as const, kind: 'token' as const, scope: `1:${body.address}`, keyId: 'tokens', sequence: 1, issuedAt, expiresAt, digest: metadataDigest(body) };
  return { statement, signature: signer.sign(signatureDigest('record', statement)).compactSerialized };
}
test('explicit non-expiring policy and delegate work years later; records still expire', () => {
  const future = now + 5 * 365 * 86400000;
  const verifier = new MetadataVerifier(roots);
  verifier.acceptTrust(trust(policy()), future);
  const evidence = record(future);
  verifier.verify(body, evidence, 'token', evidence.statement.scope, future);
  assert.throws(() => verifier.verify(body, evidence, 'token', evidence.statement.scope, future + 10001), /validity/);
});
test('schema 1 remains finite and schema 2 cannot infer missing or malformed expiry', () => {
  const original = policy();
  for (const payload of [{ ...original, schema: 1 }, { ...original, schema: 3 }, { ...original, expiresAt: 0 }, { ...original, expiresAt: 'never' },
    { ...original, expiresAt: undefined }, { ...original, keys: [{ ...original.keys[0], expiresAt: undefined }] }, { ...original, issuedAt: now + 120000 }]) {
    assert.throws(() => new MetadataVerifier(roots).acceptTrust(trust(payload as TrustPayload), now));
  }
  const finite = { ...original, schema: 1 as const, expiresAt: now + 10000, keys: [{ ...original.keys[0]!, expiresAt: now + 10000 }] };
  new MetadataVerifier(roots).acceptTrust(trust(finite), now);
  assert.throws(() => new MetadataVerifier(roots).acceptTrust(trust(finite), now + 10001), /validity/);
});
test('revocation, key removal and policy rollback remain enforced without expiry', () => {
  const verifier = new MetadataVerifier(roots);
  verifier.acceptTrust(trust(policy()), now);
  const evidence = record();
  verifier.verify(body, evidence, 'token', evidence.statement.scope, now);
  verifier.acceptTrust(trust({ ...policy(), sequence: 2, revokedDigests: [metadataDigest(body)] }), now);
  assert.throws(() => verifier.verify(body, evidence, 'token', evidence.statement.scope, now), /revoked/);
  assert.throws(() => verifier.acceptTrust(trust(policy()), now), /rollback/);
  verifier.acceptTrust(trust({ ...policy(), sequence: 3, keys: [] }), now);
  assert.throws(() => verifier.verify(body, evidence, 'token', evidence.statement.scope, now), /authorized/);
});
test('finite delegates under non-expiring policy retain their own validity restrictions', () => {
  const p = policy();
  p.keys[0]!.expiresAt = now + 5000;
  const verifier = new MetadataVerifier(roots);
  verifier.acceptTrust(trust(p), now);
  const evidence = record();
  assert.throws(() => verifier.verify(body, evidence, 'token', evidence.statement.scope, now), /authorized/);
});
