import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ethers } from 'ethers';
import {
  KINDS, MAX_HEADER_BYTES, NETWORK_CHAIN_SCOPES, MetadataVerifier, canonicalMetadata, decodeMetadataHeader,
  encodeMetadataHeader, metadataDigest, networkConfigScope, signatureDigest, validateConfigurationPublication,
  validateCotiBridgeRoutesPayload, validateDomainPayload, validateNetworkConfigurationPayload,
  validatePrivacyBridgesPayload, validatePublicNetworkPayload, validateTokenCatalogPayload,
  validateTokenFamiliesPayload, validateTrustedNftsPayload, type CotiBridgeRoute, type DomainPayload,
  type Evidence, type MetadataKind, type NetworkChainScope, type PublicNetwork, type PublicNetworkPayload,
  type SignedRecord, type TokenCatalogPayload, type TokenFamily, type TrustPayload,
} from './protocol.ts';
import { importConfigurationSources, readCuratedTokenCatalog } from './configuration.ts';
import { configurationFallbacks } from './fallbacks.ts';
import {
  assertConfigurationHeaderBudget, compactPublication, importTokenSources, preparedDigest, signPublication, signTrust,
  type Candidate, type PreparedPublication,
} from './publisher.ts';
import { catalogDigest, finalizePublication, verifyPrevious } from './publicationLifecycle.ts';
import { publicationReport } from './publicationReport.ts';

const now = Date.now();
const root = new ethers.SigningKey('0x' + '11'.repeat(32));
const configurationKey = new ethers.SigningKey('0x' + '22'.repeat(32));
const tokenKey = new ethers.SigningKey('0x' + '33'.repeat(32));
const descriptorKey = new ethers.SigningKey('0x' + '44'.repeat(32));
const roots = [{ id: 'fixture-root', publicKey: root.compressedPublicKey }];
const policy = (): TrustPayload => ({ schema: 2, sequence: 1, issuedAt: now - 1000, expiresAt: null,
  keys: [
    { id: 'metadata-configuration', publicKey: configurationKey.compressedPublicKey, kinds: ['networks', 'domains', 'classification'], notBefore: now - 2000, expiresAt: null },
    { id: 'metadata-tokens', publicKey: tokenKey.compressedPublicKey, kinds: ['token', 'asset'], notBefore: now - 2000, expiresAt: null },
    { id: 'metadata-descriptors', publicKey: descriptorKey.compressedPublicKey, kinds: ['descriptor'], notBefore: now - 2000, expiresAt: null },
  ], revokedDigests: [], minimumSequences: { token: 1, asset: 1, descriptor: 1, networks: 1, domains: 1, classification: 1 },
});
const trust = (payload = policy()) => signTrust(payload, roots[0]!.id, root.privateKey);
const keys = { 'metadata-configuration': configurationKey.privateKey, 'metadata-tokens': tokenKey.privateKey, 'metadata-descriptors': descriptorKey.privateKey };
const address = (index: number) => '0x' + index.toString(16).padStart(40, '0');
const emptyTokens = (chainId = 1): TokenCatalogPayload => ({ chainId, defaults: [], verified: [], tokens: [] });
const network = (): PublicNetwork => ({ name: 'Fixture', nativeSymbol: 'ETH', rpcUrl: 'https://rpc.example.com', swapRoutes: [],
  appContracts: { chatGCAddress: null, cipherDataGcAddress: null, memoGcAddress: null } });
const route = (): CotiBridgeRoute => ({ sourceChainId: 2632500, destinationChainId: 1, sourceTokenSymbol: 'COTI', destinationTokenSymbol: 'COTI',
  sourceTokenAddress: ethers.ZeroAddress, destinationTokenAddress: address(1), bridgeRecipientAddress: address(2),
  requiresQuotaCheck: true, quotaTokenAddress: ethers.ZeroAddress, quotaApiBaseUrl: 'https://bridge.example.com/quota', statusApiBaseUrl: 'https://bridge.example.com/status', decimals: 18 });
const family = (): TokenFamily => ({ familyId: 'fixture-family', protocol: 'cipherdex', assetKind: 'liquidity-position', privacyMode: 'public',
  detector: 'cipherdex-protocol-lp-v1', parentFactoryAddress: address(1), issuedTokenFactoryAddress: address(2), issuerMode: 'parent', protocolVersion: 1, privacyModeCode: 0,
  presentation: { groupLabel: 'Positions', badgeLabel: 'Position' }, actions: { swap: 'blocked', crossChain: 'blocked', privacyPortal: 'blocked', chatTip: 'blocked', transfer: 'confirm' } });
const prepared = (records: Candidate[]): PreparedPublication => ({ schema: 1, sequence: now, issuedAt: now, expiresAt: now + 3600000, sources: [{ name: 'fixture', revision: 'a'.repeat(40) }], records });
const catalog = fileURLToPath(new URL('../catalog/', import.meta.url));
const readCatalog = async (name: string): Promise<unknown> => JSON.parse(await fs.readFile(path.join(catalog, name), 'utf8'));
const imports = async () => importConfigurationSources({ curatedDirectory: catalog, networks: await readCatalog('public-chains.json'), domains: await readCatalog('domains.json') });
const evidence = (row: SignedRecord): Evidence => ({ statement: row.statement, signature: row.signature });
function signedRecord(kind: MetadataKind, scope: string, payload: unknown, sequence = now): SignedRecord {
  const statement = { schema: 1 as const, kind, scope, keyId: 'metadata-configuration', sequence, issuedAt: now, expiresAt: now + 3600000, digest: metadataDigest(payload) };
  return { payload, statement, signature: configurationKey.sign(signatureDigest('record', statement)).compactSerialized };
}
function verifier(policyPayload = policy()): MetadataVerifier {
  const result = new MetadataVerifier(roots);
  result.acceptTrust(trust(policyPayload), now);
  return result;
}
async function temporary(work: (directory: string) => Promise<void>): Promise<void> {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'cipher-configuration-test-'));
  try { await work(directory); }
  finally {
    assert.equal(path.dirname(directory), os.tmpdir());
    assert.ok(path.basename(directory).startsWith('cipher-configuration-test-'));
    await fs.rm(directory, { recursive: true, force: true });
  }
}

test('configuration scopes use only the existing networks kind and exact chain identity', () => {
  assert.deepEqual(KINDS, ['token', 'asset', 'descriptor', 'networks', 'domains', 'classification']);
  const payloads = [emptyTokens(), { chainId: 1, bridges: [] }, { version: 1, chainId: 1, families: [] }, { chainId: 1, nfts: [] }];
  for (const [index, section] of NETWORK_CHAIN_SCOPES.entries()) {
    assert.equal(networkConfigScope(section, 1), `${section}:1`);
    validateNetworkConfigurationPayload(`${section}:1`, payloads[index]);
    assert.throws(() => validateNetworkConfigurationPayload(`${section}:10`, payloads[index]), /identity/);
  }
  for (const scope of ['arbitrary', 'tokens', 'tokens:01', 'tokens:0', 'tokens:-1', 'tokens:1:extra', 'tokens:1e3', 'tokens:9007199254740992', 'privacy_bridges:1', 'coti-bridge-routes:1']) {
    assert.throws(() => validateNetworkConfigurationPayload(scope, emptyTokens()));
  }
  assert.throws(() => networkConfigScope('arbitrary' as NetworkChainScope, 1), /scope/);
  assert.throws(() => networkConfigScope('tokens', 0), /integer/);
});

test('public networks have closed deployment/route schemas and public HTTPS/WSS endpoints', () => {
  validatePublicNetworkPayload({ '1': network() });
  for (const rpcUrl of ['http://rpc.example.com', 'https:rpc.example.com', 'https://user:password@rpc.example.com',
    'https://localhost', 'https://localhost.', 'https://rpc.internal', 'https://127.1', 'https://0x7f000001',
    'https://10.1.1.1', 'https://172.16.1.1', 'https://192.168.1.1', 'https://169.254.169.254', 'https://100.64.0.1',
    'https://[::1]', 'https://[::ffff:127.0.0.1]', 'https://[fd00::1]', 'https://[fe80::1]',
    'https://rpc.example.com/?api_key=credential', 'https://rpc.example.com/#fragment', 'https://bad_host.example']) {
    assert.throws(() => validatePublicNetworkPayload({ '1': { ...network(), rpcUrl } }));
  }
  for (const extra of [{ rpcUrlFallback: [] }, { providerApiKey: 'test' }, { swapRoutes: ['unknown'] }, { swapRoutes: ['uniswap', 'uniswap'] },
    { supportsSwap: true }, { appContracts: { ...network().appContracts, memoGcAddress: ethers.ZeroAddress } },
    { appContracts: { ...network().appContracts, spender: address(1) } }, { appContracts: {} },
    { explorerTxUrl: 'http://scan.example.com/tx/{hash}' }, { explorerTxUrl: 'https://scan.example.com/tx/{address}' },
    { blockscoutUrl: 'https://127.0.0.1' }, { chainLogoUrl: 'https://user:password@images.example.com/logo.png' }, { rpcWsUrl: 'ws://rpc.example.com' },
    { privacy: { supportsPrivacy: true, privateKey: 'test' } }]) {
    assert.throws(() => validatePublicNetworkPayload({ '1': { ...network(), ...extra } }));
  }
  validatePublicNetworkPayload({ '1': { ...network(), swapRoutes: ['uniswap'], supportsSwap: true, rpcWsUrl: 'wss://rpc.example.com', explorerTxUrl: 'https://scan.example.com/tx/{hash}' } });
});

test('curated catalogs retain nulls, unknown decimals and market references without normalization', async () => {
  const raw = { tokenAddress: address(1), chainId: 1, private: null, tokenSymbol: null, name: null, logoUrl: null, cgCoinId: null, decimals: null,
    marketDataReference: { chainId: 2632500, tokenAddress: 'native', priceMultiplier: '1.25' }, verification: 'community' };
  const payload = { ...emptyTokens(), verified: [raw], tokens: [{ tokenAddress: address(2), tokenSymbol: 'UNKNOWN' }] };
  const before = JSON.stringify(payload);
  validateTokenCatalogPayload(payload, 1);
  assert.equal(JSON.stringify(payload), before);
  const row = signedRecord('networks', 'tokens:1', payload);
  const accepted = verifier().verify(payload, evidence(row), 'networks', 'tokens:1', now);
  assert.deepEqual(accepted.payload, payload);
  assert.equal(accepted.payload.verified[0]!.decimals, null);
  assert.equal(Object.hasOwn(accepted.payload.tokens[0]!, 'decimals'), false);
  await temporary(async directory => {
    await fs.writeFile(path.join(directory, 'verified_tokens.1.json'), JSON.stringify([raw]));
    assert.deepEqual((await readCuratedTokenCatalog(directory, 1)).verified, [raw]);
    const records = await importTokenSources({ curatedDirectory: directory, chains: { '1': {} }, revisions: { curated: 'a'.repeat(40) } });
    assert.equal(records.some(record => record.kind === 'token'), false);
    assert.equal(records.filter(record => record.kind === 'classification').length, 1);
  });
});

test('curated token fields, decimals, duplicates and references reject malformed authority', () => {
  const raw = { tokenAddress: address(1), tokenSymbol: 'TOKEN' };
  for (const extra of [{ chainId: 10 }, { private: 'false' }, { default: true }, { verified: true }, { tokenSymbol: 1 },
    { tokenSymbol: 'X'.repeat(65) }, { decimals: -1 }, { decimals: 256 }, { decimals: 6.5 }, { decimals: '6' },
    { verification: null }, { marketDataReference: { tokenAddress: 'native', rpcUrl: 'https://rpc.example.com' } },
    { marketDataReference: { tokenAddress: 'native', chainId: 0 } }, { marketDataReference: { tokenAddress: 'invalid' } },
    { marketDataReference: { tokenAddress: 'native', priceMultiplier: '0' } }, { marketDataReference: { tokenAddress: 'native', priceMultiplier: 1.25 } }]) {
    assert.throws(() => validateTokenCatalogPayload({ ...emptyTokens(), tokens: [{ ...raw, ...extra }] }));
  }
  assert.throws(() => validateTokenCatalogPayload({ ...emptyTokens(), tokens: [raw, raw] }), /Duplicate/);
  assert.throws(() => validateTokenCatalogPayload({ ...emptyTokens(), defaults: [{ ...raw, verification: 'unverified' }] }), /classification/);
  assert.throws(() => validateTokenCatalogPayload({ ...emptyTokens(), defaults: [raw], verified: [raw] }), /Conflicting/);
  assert.throws(() => validateTokenCatalogPayload({ ...emptyTokens(), tokens: Array(2049).fill(raw) }), /limit/);
  assert.throws(() => validateTokenCatalogPayload({ ...emptyTokens(), spender: address(1) }), /format/);
});

test('privacy bridge catalogs validate recipients, native/PoD identities and duplicates', () => {
  const bridge = { bridgeAddress: address(1), bridgeType: 'native', publicTokenAddress: null, privateTokenAddress: address(2), default: true, verified: true, sortOrder: 1 };
  validatePrivacyBridgesPayload({ chainId: 1, bridges: [bridge] }, 1);
  validatePrivacyBridgesPayload({ chainId: 1, bridges: [{ ...bridge, bridgeType: 'pod-native', publicTokenAddress: address(3), factoryAddress: address(4) }] }, 1);
  for (const extra of [{ bridgeAddress: ethers.ZeroAddress }, { bridgeType: 'arbitrary' }, { bridgeType: 'erc20' },
    { publicTokenAddress: address(3) }, { privateTokenAddress: 'invalid' }, { factoryAddress: address(4) },
    { verified: false }, { verified: 'true' }, { spender: address(4) }, { sortOrder: 1.5 },
    { bridgeType: 'pod-erc20', publicTokenAddress: address(3) }]) {
    assert.throws(() => validatePrivacyBridgesPayload({ chainId: 1, bridges: [{ ...bridge, ...extra }] }));
  }
  assert.throws(() => validatePrivacyBridgesPayload({ chainId: 1, bridges: [bridge, bridge] }), /Duplicate/);
  assert.throws(() => validatePrivacyBridgesPayload({ chainId: 10, bridges: [] }, 1), /identity/);
});

test('token family policy closes detector, actions and deployment schemas', () => {
  validateTokenFamiliesPayload({ version: 2, chainId: 1, families: [family()] }, 1);
  for (const extra of [{ protocol: 'other' }, { detector: 'unverified' }, { assetKind: 'token' }, { protocolVersion: 0 },
    { privacyModeCode: 1 }, { issuerMode: 'other' }, { issuedTokenFactoryAddress: ethers.ZeroAddress },
    { actions: { ...family().actions, transfer: 'ignore' } }, { actions: { ...family().actions, sign: 'allowed' } },
    { presentation: { ...family().presentation, badgeUrl: 'https://images.example.com/badge.png' } }, { spender: address(4) }]) {
    assert.throws(() => validateTokenFamiliesPayload({ version: 2, chainId: 1, families: [{ ...family(), ...extra }] }));
  }
  assert.throws(() => validateTokenFamiliesPayload({ version: 2, chainId: 1, families: [family(), family()] }), /Duplicate/);
  assert.throws(() => validateTokenFamiliesPayload({ version: 2, chainId: 1, families: [family(), { ...family(), familyId: 'another-family' }] }), /Duplicate/);
  assert.throws(() => validateTokenFamiliesPayload({ version: 2, chainId: 1, families: [] }, 10), /identity/);
});

test('trusted NFT catalogs identify bounded canonical uint256 token ids and contracts', () => {
  validateTrustedNftsPayload({ chainId: 1, nfts: [{ contractAddress: address(1), tokenId: '0' }, { contractAddress: address(1), tokenId: ethers.MaxUint256.toString() }] });
  for (const tokenId of ['', '01', '-1', '0x1', '1.1', 1, (ethers.MaxUint256 + 1n).toString()]) {
    assert.throws(() => validateTrustedNftsPayload({ chainId: 1, nfts: [{ contractAddress: address(1), tokenId }] }));
  }
  const nft = { contractAddress: address(1), tokenId: '1' };
  assert.throws(() => validateTrustedNftsPayload({ chainId: 1, nfts: [nft, nft] }), /Duplicate/);
  assert.throws(() => validateTrustedNftsPayload({ chainId: 1, nfts: [{ ...nft, verified: true }] }), /format/);
  assert.throws(() => validateTrustedNftsPayload({ chainId: 1, nfts: [{ ...nft, contractAddress: ethers.ZeroAddress }] }), /address/);
  assert.throws(() => validateTrustedNftsPayload({ chainId: 1, nfts: [] }, 10), /identity/);
});

test('COTI route catalog preserves disabled historical entries and checks route/quota identity', () => {
  const payload = { version: 2, routes: [{ ...route(), enabled: false }] };
  validateCotiBridgeRoutesPayload(payload);
  assert.equal(payload.routes[0]!.enabled, false);
  for (const extra of [{ destinationChainId: 2632500 }, { sourceChainId: 10, destinationChainId: 1 }, { bridgeRecipientAddress: ethers.ZeroAddress },
    { bridgeRecipientAddress: 'invalid' }, { enabled: 'false' }, { quotaTokenAddress: address(4) }, { statusApiBaseUrl: 'http://bridge.example.com/status' },
    { quotaApiBaseUrl: 'https://10.0.0.1/quota' }, { requiresQuotaCheck: false }, { spender: address(3) }, { decimals: null }]) {
    assert.throws(() => validateCotiBridgeRoutesPayload({ version: 2, routes: [{ ...route(), ...extra }] }));
  }
  validateCotiBridgeRoutesPayload({ version: 2, routes: [{ ...route(), requiresQuotaCheck: false, quotaTokenAddress: null, quotaApiBaseUrl: null }] });
  assert.throws(() => validateCotiBridgeRoutesPayload({ version: 2, routes: [route(), route()] }), /Duplicate/);
});

test('domain publication uses exact and wildcard-plus-apex host patterns, never origins', () => {
  const payload = { patterns: ['example.com', '*.ciphertrade.org'] };
  validateDomainPayload(payload);
  assert.deepEqual(payload.patterns, ['example.com', '*.ciphertrade.org']);
  validateDomainPayload({ patterns: [] });
  for (const pattern of ['https://example.com', 'example.com/path', 'example.com:443', '*example.com', '*.*.example.com',
    'example.*', 'Example.com', '*.localhost', '*.rpc.internal', '127.0.0.1', 'example.com.', '-bad.example.com', 'example.com\n']) {
    assert.throws(() => validateDomainPayload({ patterns: [pattern] }));
  }
  assert.throws(() => validateDomainPayload({ origins: [] }), /format/);
  assert.throws(() => validateDomainPayload({ patterns: ['*.example.com', '*.example.com'] }), /Duplicate/);
  assert.throws(() => validateDomainPayload({ patterns: [], origins: [] }), /format/);
});

test('every signed network gets all four scopes, including authoritative empty records', async () => {
  const records = await imports();
  const chains = records.find(row => row.scope === 'chains')!.payload as PublicNetworkPayload;
  assert.equal(records.length, Object.keys(chains).length * 4 + 3);
  assert.equal(records.length, 51);
  validateConfigurationPublication(records);
  for (const chainId of Object.keys(chains).map(Number)) for (const section of NETWORK_CHAIN_SCOPES) {
    const row = records.find(row => row.scope === networkConfigScope(section, chainId));
    assert.ok(row);
    validateNetworkConfigurationPayload(row.scope, row.payload);
  }
  assert.deepEqual(records.find(row => row.scope === 'tokens:43113')!.payload, {
    ...emptyTokens(43113), defaults: JSON.parse(await fs.readFile(new URL('../catalog/default_tokens.43113.json', import.meta.url), 'utf8')),
  });
  assert.deepEqual(records.find(row => row.scope === 'trusted-nfts:1')!.payload, { chainId: 1, nfts: [] });
  const coti = records.find(row => row.scope === 'coti-bridge-routes')!.payload as { routes: CotiBridgeRoute[] };
  assert.equal(coti.routes.filter(row => row.enabled === false).length, 2);
  assert.deepEqual(chains['2632500']!.swapRoutes, ['carbon', 'cipherdex', 'wrapped-native']);
  assert.equal(chains['2632500']!.appContracts.memoGcAddress, '0x817e3Fd031E3f964c2AEe6B3999365a979C8BB85');
  assert.equal((records.find(row => row.scope === 'tokens:2632500')!.payload as TokenCatalogPayload).defaults.some(row => row.tokenSymbol === 'p.gCOTI'), true);
});

test('missing, duplicate, unsupported-chain or unapproved extra configuration is incomplete', async () => {
  const records = await imports();
  for (const scope of ['chains', 'domains', 'coti-bridge-routes', 'tokens:1', 'privacy-bridges:1', 'token-families:1', 'trusted-nfts:1']) {
    assert.throws(() => validateConfigurationPublication(records.filter(row => row.scope !== scope)), /Incomplete/);
  }
  assert.throws(() => validateConfigurationPublication([...records, records[0]!]), /Duplicate/);
  assert.throws(() => validateConfigurationPublication([...records, { kind: 'networks', scope: 'tokens:2', payload: emptyTokens(2) }]), /unsupported/);
  const changed = records.map(row => row.scope === 'coti-bridge-routes' ? { ...row, payload: { version: 2, routes: [{ ...route(), destinationChainId: 2 }] } } : row);
  assert.throws(() => validateConfigurationPublication(changed), /unsupported chain/);
  const p = prepared(records.filter(row => row.scope !== 'trusted-nfts:1'));
  assert.throws(() => signPublication(p, preparedDigest(p), trust(), roots, keys), /Incomplete/);
});

test('malformed curated source files fail preparation rather than becoming empty fallbacks', async () => {
  await temporary(async directory => {
    const options = { curatedDirectory: directory, networks: { '1': network() }, domains: { patterns: [] } };
    const rows = await importConfigurationSources(options);
    assert.deepEqual(rows.find(row => row.scope === 'tokens:1')!.payload, emptyTokens());
    await fs.writeFile(path.join(directory, 'tokens.1.json'), '{invalid');
    await assert.rejects(importConfigurationSources(options), SyntaxError);
    await fs.writeFile(path.join(directory, 'tokens.1.json'), JSON.stringify([{ tokenAddress: address(1), spender: address(2) }]));
    await assert.rejects(importConfigurationSources(options), /format/);
    await fs.writeFile(path.join(directory, 'tokens.1.json'), '[]');
    await fs.writeFile(path.join(directory, 'token_families.1.json'), JSON.stringify({ version: 1, chainId: 10, families: [] }));
    await assert.rejects(importConfigurationSources(options), /identity/);
  });
});

test('classification removals also remove bundled and signed curated-list authority', async () => {
  await temporary(async directory => {
    await fs.writeFile(path.join(directory, 'default_tokens.1.json'), JSON.stringify([{ tokenAddress: address(1), tokenSymbol: 'REMOVED', decimals: 6 }]));
    await fs.writeFile(path.join(directory, 'classification-overrides.json'), JSON.stringify([{ chainId: 1, address: address(1), default: false, verified: false, verification: 'unverified' }]));
    const config = await importConfigurationSources({ curatedDirectory: directory, networks: { '1': network() }, domains: { patterns: [] } });
    assert.deepEqual(config.find(row => row.scope === 'tokens:1')!.payload, emptyTokens());
    assert.deepEqual(configurationFallbacks(config).get('default_tokens.1.json'), []);
    const tokens = await importTokenSources({ curatedDirectory: directory, chains: { '1': {} }, revisions: { curated: 'a'.repeat(40) } });
    assert.equal((tokens.find(row => row.kind === 'classification')!.payload as { verified: boolean }).verified, false);
    await fs.writeFile(path.join(directory, 'classification-overrides.json'), JSON.stringify([{ chainId: 10, address: address(1), default: false, verified: false, verification: 'unverified' }]));
    await assert.rejects(importConfigurationSources({ curatedDirectory: directory, networks: { '1': network() }, domains: { patterns: [] } }), /supported chains/);
  });
});

test('configuration tampering, missing evidence, wrong scope and wrong-role signing fail closed', () => {
  const body = { '1': { ...network(), appContracts: { ...network().appContracts, memoGcAddress: address(1) } } };
  const row = signedRecord('networks', 'chains', body);
  const v = verifier();
  v.verify(body, evidence(row), 'networks', 'chains', now);
  assert.throws(() => v.verify({ '1': { ...body['1'], appContracts: { ...body['1'].appContracts, memoGcAddress: address(2) } } }, evidence(row), 'networks', 'chains', now), /digest/);
  const bridge = signedRecord('networks', 'coti-bridge-routes', { version: 2, routes: [route()] });
  assert.throws(() => v.verify({ version: 2, routes: [{ ...route(), bridgeRecipientAddress: address(3) }] }, evidence(bridge), 'networks', 'coti-bridge-routes', now), /digest/);
  for (const proof of [null, {}, { statement: row.statement }, { signature: row.signature }]) {
    assert.throws(() => v.verify(body, proof as Evidence, 'networks', 'chains', now));
  }
  assert.throws(() => v.verify(body, evidence(row), 'networks', 'tokens:1', now), /scope/);
  const statement = { ...row.statement, keyId: 'metadata-tokens' };
  assert.throws(() => v.verify(body, { statement, signature: tokenKey.sign(signatureDigest('record', statement)).compactSerialized }, 'networks', 'chains', now), /authorized/);
});

test('expired, revoked, rolled-back or same-version-replaced config cannot regain authority', () => {
  const first = signedRecord('networks', 'tokens:1', { ...emptyTokens(), defaults: [{ tokenAddress: address(1), decimals: 6 }] }, now);
  const removed = signedRecord('networks', 'tokens:1', emptyTokens(), now + 1);
  const v = verifier();
  v.verify(first.payload, evidence(first), 'networks', 'tokens:1', now);
  v.verify(removed.payload, evidence(removed), 'networks', 'tokens:1', now);
  assert.throws(() => v.verify(first.payload, evidence(first), 'networks', 'tokens:1', now), /rollback/);
  const replacement = signedRecord('networks', 'tokens:1', { ...emptyTokens(), defaults: [{ tokenAddress: address(2) }] }, now + 1);
  assert.throws(() => v.verify(replacement.payload, evidence(replacement), 'networks', 'tokens:1', now), /equivocation/);
  assert.throws(() => v.verify(removed.payload, evidence(removed), 'networks', 'tokens:1', now + 3600001), /validity/);
  v.acceptTrust(trust({ ...policy(), sequence: 2, revokedDigests: [metadataDigest(removed.payload)] }), now);
  assert.throws(() => v.verify(removed.payload, evidence(removed), 'networks', 'tokens:1', now), /revoked/);
});

test('large static arrays use implicit body evidence rather than header payloads or whole-publication downloads', () => {
  const payload = { ...emptyTokens(), tokens: Array.from({ length: 256 }, (_, i) => ({ tokenAddress: address(i + 1), tokenSymbol: `T${i}`, decimals: null, cgCoinId: null })) };
  const row = signedRecord('networks', 'tokens:1', payload);
  assert.ok(encodeMetadataHeader(row).length > MAX_HEADER_BYTES);
  const header = encodeMetadataHeader([evidence(row)]);
  assert.ok(header.length + encodeMetadataHeader(trust()).length < MAX_HEADER_BYTES);
  const proof = (decodeMetadataHeader(header) as Evidence[])[0]!;
  assert.equal(Object.hasOwn(proof, 'payload'), false);
  assert.deepEqual(verifier().verify(payload, proof, 'networks', 'tokens:1', now).payload, payload);
  const families = { version: 2, chainId: 1, families: Array.from({ length: 24 }, (_, i) => ({ ...family(), familyId: `family-${i}`, issuedTokenFactoryAddress: address(i + 2) })) };
  const familyRecord = signedRecord('networks', 'token-families:1', families);
  assert.ok(encodeMetadataHeader(familyRecord).length > MAX_HEADER_BYTES);
  assert.deepEqual(verifier().verify(families, evidence(familyRecord), 'networks', 'token-families:1', now).payload, families);
});

test('/chains fits the real domain catalog and a 62-pattern catalog beside implicit network proof and three role roots', async () => {
  const records = await imports();
  const p = prepared(records);
  const publication = signPublication(p, preparedDigest(p), trust(), roots, keys);
  const chains = publication.records.find(row => row.statement.scope === 'chains')!;
  const domains = publication.records.find(row => row.statement.kind === 'domains')!;
  const actual = domains.payload as DomainPayload;
  assert.equal(actual.patterns.length, 61);
  assert.equal(ethers.toUtf8Bytes(canonicalMetadata(actual)).length, 1053);
  const expanded = { patterns: [...actual.patterns, 'bitstamp.net'] };
  assert.equal(expanded.patterns.length, 62);
  validateDomainPayload(expanded);
  const extra = signedRecord('domains', 'domains', expanded);
  for (const domain of [domains, extra]) {
    const header = encodeMetadataHeader([evidence(chains), domain]);
    assert.ok(header.length + encodeMetadataHeader(publication.trust).length <= MAX_HEADER_BYTES);
    const returned = decodeMetadataHeader(header) as (Evidence | SignedRecord)[];
    assert.equal(returned.length, 2);
    assert.equal(Object.hasOwn(returned[0]!, 'payload'), false);
    assert.equal(Object.hasOwn(returned[1]!, 'payload'), true);
    const v = verifier();
    v.verify(chains.payload, returned[0]!, 'networks', 'chains', now);
    v.verify(domain.payload, evidence(returned[1]!), 'domains', 'domains', now);
  }
  assertConfigurationHeaderBudget(publication.records, publication.trust);
});

test('configuration publication fails before headers would silently strip the domains record', async () => {
  const records = await imports();
  const p = prepared(records);
  const signed = signPublication(p, preparedDigest(p), trust(), roots, keys);
  const chain = signed.records.find(row => row.statement.scope === 'chains')!;
  const domain = signed.records.find(row => row.statement.kind === 'domains')!;
  let crowded: ReturnType<typeof trust> | null = null;
  for (let count = 0; count < 50; count++) {
    const candidate = trust({ ...policy(), revokedDigests: Array.from({ length: count }, (_, i) => metadataDigest({ fixture: i })) });
    const bytes = encodeMetadataHeader(candidate).length;
    if (bytes <= MAX_HEADER_BYTES - 1024 && bytes + encodeMetadataHeader([evidence(chain), domain]).length > MAX_HEADER_BYTES) { crowded = candidate; break; }
  }
  assert.ok(crowded);
  assert.throws(() => signPublication(p, preparedDigest(p), crowded, roots, keys), /response-header budget/);
});

test('all new scopes sign, compact, report and renew unchanged through the configuration role', async () => {
  const p = prepared(await imports());
  const signed = signPublication(p, preparedDigest(p), trust(), roots, keys, ['networks', 'domains', 'classification']);
  assert.equal(signed.records.length, p.records.length);
  assert.ok(signed.records.every(row => row.statement.keyId === 'metadata-configuration'));
  const compact = compactPublication(signed);
  assert.deepEqual(compact.documents, Object.create(null));
  assert.deepEqual(compact.records, signed.records);
  const previous = verifyPrevious(compact, roots, now);
  const renewed = finalizePublication({ mode: 'renewal', previous, roots, trust: trust(), now: now + 86400000 });
  assert.deepEqual(renewed.records, p.records);
  assert.equal(catalogDigest(renewed.records), previous.contentDigest);
  assert.deepEqual(publicationReport(renewed, previous).changed, []);
  assert.deepEqual(publicationReport(renewed, previous).removed, []);
  const removed = structuredClone(p);
  removed.records = removed.records.map(row => row.scope === 'tokens:2632500' ? { ...row, payload: emptyTokens(2632500) } : row);
  assert.deepEqual(publicationReport(removed, previous).changed, ['networks:tokens:2632500']);
  assert.deepEqual(publicationReport(removed, previous).removed, []);
  const incomplete = { ...previous, records: previous.records.filter(row => row.statement.scope !== 'tokens:1') };
  assert.throws(() => finalizePublication({ mode: 'renewal', previous: incomplete, roots, trust: trust(), now: now + 86400000 }), /Incomplete/);
});

test('release fallbacks are generated exclusively from complete publisher configuration', async () => {
  const records = await imports();
  const files = configurationFallbacks(records);
  const publicChains = records.find(row => row.scope === 'chains')!.payload as PublicNetworkPayload;
  const chains = files.get('chains.json') as (PublicNetwork & { chainId: number })[];
  assert.equal(chains[0]!.chainId, 2632500);
  for (const { chainId, ...row } of chains) assert.deepEqual(row, publicChains[String(chainId)]);
  assert.ok(chains.every(row => !Object.hasOwn(row, 'rpcUrlFallback') && !Object.hasOwn(row, 'explorerApiKey')));
  assert.deepEqual(files.get('verified_domains.json'), (records.find(row => row.kind === 'domains')!.payload as DomainPayload).patterns);
  assert.deepEqual(files.get('verified_tokens.1.json'), []);
  assert.deepEqual(files.get('privacy_bridges.1.json'), []);
  assert.deepEqual(files.get('trusted_nfts.1.json'), []);
  assert.deepEqual(files.get('token_families.1.json'), { version: 1, chainId: 1, families: [] });
  assert.deepEqual(files.get('tokens.2632500.json'), (records.find(row => row.scope === 'tokens:2632500')!.payload as TokenCatalogPayload).tokens);
  const memo = files.get('bundledMemoConfig.2632500.json') as { memoGcAddress: string; chatFeeWei: null; memoFeeWei: null };
  assert.equal(memo.memoGcAddress, publicChains['2632500']!.appContracts.memoGcAddress);
  assert.equal(memo.chatFeeWei, null);
  assert.equal(memo.memoFeeWei, null);
  const removed = records.map(row => row.scope === 'chains' ? { ...row, payload: { ...publicChains,
    '2632500': { ...publicChains['2632500']!, appContracts: { chatGCAddress: null, cipherDataGcAddress: null, memoGcAddress: null } },
  } } : row);
  assert.equal((configurationFallbacks(removed).get('bundledMemoConfig.2632500.json') as { memoGcAddress: null }).memoGcAddress, null);
  assert.throws(() => configurationFallbacks(records.filter(row => row.scope !== 'tokens:1')), /Incomplete/);
});
