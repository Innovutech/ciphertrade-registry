import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { ethers } from 'ethers';
import { MetadataVerifier, metadataDigest, tokenScope, signatureDigest, validatePublicNetworkPayload, type TrustPayload, type SignedRecord } from './protocol.ts';
import { importTokenSources, preparedDigest, signPublication, signTrust, type PreparedPublication } from './publisher.ts';

const now = Date.now();
const root = new ethers.SigningKey('0x' + '11'.repeat(32));
const signer = new ethers.SigningKey('0x' + '22'.repeat(32));
const roots = [{ id: 'test-root', publicKey: root.compressedPublicKey }];
const trustPayload: TrustPayload = { schema: 1, sequence: 1, issuedAt: now - 1000, expiresAt: now + 86400000,
  keys: [{ id: 'test-tokens', publicKey: signer.compressedPublicKey, kinds: ['token'], notBefore: now - 2000, expiresAt: now + 86400000 }],
  revokedDigests: [], minimumSequences: { token: 1, asset: 1, descriptor: 1, networks: 1, domains: 1, classification: 1 },
};
const trust = () => signTrust(structuredClone(trustPayload), roots[0].id, root.privateKey);
const payload = { chainId: 1, address: '0x' + '33'.repeat(20), symbol: 'EXAMPLE', decimals: 6, source: 'trustwallet', revision: 'a'.repeat(40) };
const candidate = { kind: 'token' as const, scope: tokenScope(1, payload.address), payload };
const prepared = (): PreparedPublication => ({ schema: 1, sequence: 1, issuedAt: now, expiresAt: now + 3600000,
  sources: [{ name: 'fixture', revision: 'a'.repeat(40) }], records: [candidate] });
const signed = () => signPublication(prepared(), preparedDigest(prepared()), trust(), roots, { 'test-tokens': signer.privateKey }).records[0]!;
const verify = (verifier: MetadataVerifier, row: SignedRecord, kind = row.statement.kind, scope = row.statement.scope, time = now) => verifier.verify(row.payload, { statement: row.statement, signature: row.signature }, kind, scope, time);

test('public network policy rejects private configuration before the signer can publish it', () => {
  const row = { name: 'Ethereum', nativeSymbol: 'ETH', rpcUrl: 'https://ethereum.example' };
  validatePublicNetworkPayload({ '1': row });
  for (const extra of [{ rpcUrlFallback: ['https://private.example'] }, { explorerApiKey: 'private' }, { rpcUrl: 'https://172.16.1.1' },
    { rpcUrl: 'https://user:secret@example.com' }, { rpcUrl: 'https://[::1]' }, { privacy: { supportsPrivacy: false, secret: 'private' } }]) {
    assert.throws(() => validatePublicNetworkPayload({ '1': { ...row, ...extra } }));
  }
});

test('signed per-token publication needs no whole-catalog client download', () => {
  const verifier = new MetadataVerifier(roots);
  verifier.acceptTrust(trust(), now);
  const result = verify(verifier, signed());
  assert.deepEqual(result.payload, payload);
  assert.ok(Object.isFrozen(result.payload));
  assert.equal(Object.hasOwn(result.payload as object, 'verified'), false);
});

test('approval digest binds payload, source revisions, scope and publication times', () => {
  for (const change of [
    (p: PreparedPublication) => { p.sequence++; },
    (p: PreparedPublication) => { p.sources[0]!.revision = 'b'.repeat(40); },
    (p: PreparedPublication) => { p.records[0] = { ...candidate, scope: tokenScope(10, payload.address) }; },
    (p: PreparedPublication) => { p.records[0] = { ...candidate, payload: { ...payload, decimals: 18 } }; },
  ]) {
    const p = structuredClone(prepared());
    change(p);
    assert.throws(() => signPublication(p, preparedDigest(prepared()), trust(), roots, { 'test-tokens': signer.privateKey }), /approved digest/);
  }
});

test('wrong roots, unknown delegates and cross-role use fail closed', () => {
  assert.throws(() => new MetadataVerifier([]).acceptTrust(trust(), now), /root/);
  const verifier = new MetadataVerifier(roots);
  verifier.acceptTrust(trust(), now);
  assert.throws(() => verify(verifier, signed(), 'networks', 'chains'), /scope/);
  const p = prepared();
  p.records[0] = { kind: 'descriptor', scope: 'test', payload: {} };
  assert.throws(() => signPublication(p, preparedDigest(p), trust(), roots, { 'test-tokens': signer.privateKey }), /Missing scoped/);
});

test('wrong chain/address, changed units and invalid signatures are rejected', () => {
  const verifier = new MetadataVerifier(roots);
  verifier.acceptTrust(trust(), now);
  assert.throws(() => verify(verifier, signed(), 'token', tokenScope(10, payload.address)), /scope/);
  assert.throws(() => verify(verifier, signed(), 'token', tokenScope(1, '0x' + '44'.repeat(20))), /scope/);
  const changed = structuredClone(signed());
  changed.payload = { ...payload, decimals: 18 };
  assert.throws(() => verify(verifier, changed), /digest/);
  const forged = structuredClone(signed());
  forged.signature = root.sign(signatureDigest('record', forged.statement)).compactSerialized;
  assert.throws(() => verify(verifier, forged), /signature/);
});

test('memoized signatures still enforce expiry and root revocation', () => {
  const verifier = new MetadataVerifier(roots);
  verifier.acceptTrust(trust(), now);
  const row = signed();
  verify(verifier, row);
  assert.throws(() => verify(verifier, row, 'token', row.statement.scope, now + 3600001), /validity/);
  const next = { ...trustPayload, sequence: 2, revokedDigests: [metadataDigest(payload)] };
  verifier.acceptTrust(signTrust(next, roots[0].id, root.privateKey), now);
  assert.throws(() => verify(verifier, row), /revoked/);
});

test('trust checkpoint rejects rollback and same-version substitution', () => {
  const verifier = new MetadataVerifier(roots);
  verifier.acceptTrust(signTrust({ ...trustPayload, sequence: 2 }, roots[0].id, root.privateKey), now);
  const restored = new MetadataVerifier(roots, verifier.trustCheckpoint);
  assert.throws(() => restored.acceptTrust(trust(), now), /rollback/);
  assert.throws(() => restored.acceptTrust(signTrust({ ...trustPayload, sequence: 2, revokedDigests: [metadataDigest(payload)] }, roots[0].id, root.privateKey), now), /equivocation/);
});

test('scoped key rotation invalidates records signed with removed keys', () => {
  const verifier = new MetadataVerifier(roots);
  verifier.acceptTrust(trust(), now);
  verify(verifier, signed());
  verifier.acceptTrust(signTrust({ ...trustPayload, sequence: 2, keys: [] }, roots[0].id, root.privateKey), now);
  assert.throws(() => verify(verifier, signed()), /authorized/);
});

test('malformed and unsupported publication formats cannot gain trust', () => {
  const verifier = new MetadataVerifier(roots);
  for (const payload of [
    { ...trustPayload, schema: 2 }, { ...trustPayload, issuedAt: String(now) },
    { ...trustPayload, keys: [...trustPayload.keys, ...trustPayload.keys] },
  ]) {
    const signature = root.sign(signatureDigest('trust', payload)).compactSerialized;
    assert.throws(() => verifier.acceptTrust({ rootId: roots[0].id, payload, signature }, now));
  }
  assert.throws(() => metadataDigest(JSON.parse('{"__proto__":{}}')), /Unsafe/);
});

test('Trust Wallet importer covers non-curated assets without awarding verification', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'cipher-metadata-test-'));
  try {
    const asset = path.join(directory, 'tw/blockchains/ethereum/assets', payload.address);
    await fs.mkdir(asset, { recursive: true });
    await fs.mkdir(path.join(directory, 'curated'));
    await fs.writeFile(path.join(asset, 'info.json'), JSON.stringify({ id: payload.address, name: 'Example', symbol: 'EXAMPLE', decimals: 6, status: 'active', verified: true }));
    const options = { curatedDirectory: path.join(directory, 'curated'), trustWalletDirectory: path.join(directory, 'tw'), chains: { '1': { twChainId: 'ethereum' } }, revisions: { curated: 'b'.repeat(40), trustWallet: 'a'.repeat(40) } };
    const rows = await importTokenSources(options);
    assert.equal(rows.length, 1);
    assert.equal(rows[0]!.scope, candidate.scope);
    assert.equal(rows[0]!.kind, 'token');
    assert.equal(Object.hasOwn(rows[0]!.payload as object, 'verified'), false);
    await fs.writeFile(path.join(directory, 'curated/default_tokens.1.json'), JSON.stringify([{ tokenAddress: payload.address, tokenSymbol: 'CURATED', decimals: 6 }]));
    const merged = await importTokenSources(options);
    assert.equal((merged.find(row => row.kind === 'token')!.payload as { symbol: string }).symbol, 'CURATED');
    assert.equal(merged.filter(row => row.kind === 'classification').length, 1);
  } finally { await fs.rm(directory, { recursive: true, force: true }); }
});
