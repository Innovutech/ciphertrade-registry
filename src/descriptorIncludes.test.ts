import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { resolveDescriptorIncludes, mergeDescriptor } from './descriptorIncludes.ts';
import { compactPublication, signTrust } from './publisher.ts';
import { ethers } from 'ethers';
import { KINDS, metadataDigest, signatureDigest, type MetadataKind, type SignedRecord } from './protocol.ts';

test('include field merges preserve ordering, inherited params and explicit overrides', () => {
  assert.deepEqual(mergeDescriptor({ fields: [{ path: 'amount', params: { decimals: 6, base: 'USD' } }, { path: 'to' }] },
    { fields: [{ path: 'amount', params: { decimals: 18 } }, { path: 'from' }] }),
  { fields: [{ path: 'amount', params: { decimals: 18, base: 'USD' } }, { path: 'to' }, { path: 'from' }] });
});

test('includes are local, bounded, cycle checked and fully resolved before signing', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'cipher-includes-'));
  try {
    await fs.mkdir(path.join(root, 'registry'));
    const file = path.join(root, 'registry/child.json');
    await fs.writeFile(path.join(root, 'base.json'), JSON.stringify({ metadata: { owner: 'Base' }, display: { formats: { 'deposit()': { intent: 'Wrap', fields: [] } } } }));
    await fs.writeFile(file, JSON.stringify({ includes: '../base.json', metadata: { owner: 'Child' } }));
    const resolved = await resolveDescriptorIncludes(root, file);
    assert.equal((resolved.metadata as { owner: string }).owner, 'Child');
    assert.ok(resolved.display);
    assert.equal(resolved.includes, undefined);
    for (const includes of ['child.json', '../../outside.json', 'https://example.com/base.json']) {
      await fs.writeFile(file, JSON.stringify({ includes }));
      await assert.rejects(resolveDescriptorIncludes(root, file));
    }
  } finally { await fs.rm(root, { recursive: true, force: true }); }
});

test('artifact compaction references identical descriptor bodies without changing signed statements', () => {
  const body = { test: true };
  const statement = { schema: 1 as const, kind: 'descriptor' as const, scope: '1:contract:selector', digest: 'digest', keyId: 'test', sequence: 1, issuedAt: 1, expiresAt: 2 };
  const key = new ethers.SigningKey('0x' + '11'.repeat(32));
  const now = Date.now();
  const trust = signTrust({ schema: 2, sequence: 1, issuedAt: now - 1000, expiresAt: null,
    keys: [{ id: 'test', publicKey: key.compressedPublicKey, kinds: [...KINDS], notBefore: now - 1000, expiresAt: null }],
    revokedDigests: [], minimumSequences: Object.fromEntries(KINDS.map(kind => [kind, 1])) as Record<MetadataKind, number>,
  }, 'root', key.privateKey);
  const config = (kind: MetadataKind, scope: string, payload: unknown): SignedRecord => {
    const statement = { schema: 1 as const, kind, scope, digest: metadataDigest(payload), keyId: 'test', sequence: 1, issuedAt: now - 500, expiresAt: now + 3600000 };
    return { payload, statement, signature: key.sign(signatureDigest('record', statement)).compactSerialized };
  };
  const configs = [
    config('networks', 'chains', { '1': { name: 'Ethereum', nativeSymbol: 'ETH', rpcUrl: 'https://rpc.example.com', swapRoutes: [], appContracts: { chatGCAddress: null, memoGcAddress: null, cipherDataGcAddress: null } } }),
    config('domains', 'domains', { patterns: [] }),
    config('networks', 'coti-bridge-routes', { version: 1, routes: [] }),
    config('networks', 'tokens:1', { chainId: 1, defaults: [], verified: [], tokens: [] }),
    config('networks', 'privacy-bridges:1', { chainId: 1, bridges: [] }),
    config('networks', 'token-families:1', { chainId: 1, version: 1, families: [] }),
    config('networks', 'trusted-nfts:1', { chainId: 1, nfts: [] }),
  ];
  const compact = compactPublication({ schema: 1, trust, records: [
    { statement, signature: 'signature', payload: body }, { statement: { ...statement, scope: '2:contract:selector' }, signature: 'signature2', payload: body },
    ...configs,
  ] });
  assert.equal(Object.keys(compact.documents).length, 1);
  assert.deepEqual(compact.records[0].statement, statement);
  assert.equal(Object.hasOwn(compact.records[0], 'payload'), false);
});
