// Shared protocol source. scripts/sync-metadata-protocol.mjs checks the app copy.
import { ethers } from 'ethers';

export const METADATA_HEADER = 'Cipher-Metadata';
export const TRUST_HEADER = 'Cipher-Metadata-Trust';
export const MAX_HEADER_BYTES = 6144;
export const MAX_RECORD_BYTES = 192 * 1024;
export const KINDS = ['token', 'asset', 'descriptor', 'networks', 'domains', 'classification'] as const;
export type MetadataKind = typeof KINDS[number];
export type RootKey = { id: string; publicKey: string };
export type DelegatedKey = RootKey & { kinds: MetadataKind[]; notBefore: number; expiresAt: number | null };
export type TrustPayload = {
  schema: 1 | 2; sequence: number; issuedAt: number; expiresAt: number | null;
  keys: DelegatedKey[]; revokedDigests: string[];
  minimumSequences: Record<MetadataKind, number>;
};
export type SignedTrust = { rootId: string; payload: TrustPayload; signature: string };
export type Statement = {
  schema: 1; kind: MetadataKind; scope: string; keyId: string;
  sequence: number; issuedAt: number; expiresAt: number; digest: string;
};
export type Evidence = { statement: Statement; signature: string };
export type SignedRecord<T = unknown> = Evidence & { payload: T };
export type Checkpoint = { sequence: number; digest: string };
export type TokenIdentity = { chainId: number; address: string; symbol: string; decimals: number };
export type TokenPublication = TokenIdentity & {
  name?: string; logoUrl?: string;
  source: string; revision: string;
};
export const SWAP_ROUTES = ['carbon', 'cipherdex', 'wrapped-native', 'uniswap', 'kyber'] as const;
export type SwapRoute = typeof SWAP_ROUTES[number];
export const NETWORK_CHAIN_SCOPES = ['tokens', 'privacy-bridges', 'token-families', 'trusted-nfts'] as const;
export type NetworkChainScope = typeof NETWORK_CHAIN_SCOPES[number];
export type AppContracts = { chatGCAddress: string | null; cipherDataGcAddress: string | null; memoGcAddress: string | null };
export type PublicNetwork = {
  name: string; nativeSymbol: string; rpcUrl: string; swapRoutes: SwapRoute[]; appContracts: AppContracts;
  rpcWsUrl?: string | null; explorerTxUrl?: string | null; blockscoutUrl?: string | null;
  chainLogoUrl?: string | null; logoUrl?: string | null; priceOracle?: string | null;
  cgCoinId?: string | null; cgChainId?: string | null; cgTerminalChainId?: string | null; twChainId?: string | null;
  feeModel?: 'eip1559' | 'op-stack' | 'coti'; supportsPrivacy?: boolean; supportsSwap?: boolean; displayOrder?: number;
  privacy?: { supportsPrivacy: boolean; privacyRealm?: 'coti-mainnet' | 'coti-testnet' | 'pod-mainnet' | 'pod-testnet' | null;
    podInboxAddress?: string | null; podMotherAddress?: string | null } | null;
};
export type PublicNetworkPayload = Record<string, PublicNetwork>;
export type CuratedToken = {
  tokenAddress: string; chainId?: number; private?: boolean | null; tokenSymbol?: string | null;
  name?: string | null; tokenName?: string | null; logoUrl?: string | null; priceOracle?: string | null;
  cgCoinId?: string | null; decimals?: number | null; verification?: 'official' | 'community' | 'verified' | 'unverified';
  marketDataReference?: { chainId?: number; tokenAddress: string | 'native'; priceMultiplier?: string } | null;
};
export type TokenCatalogPayload = { chainId: number; defaults: CuratedToken[]; verified: CuratedToken[]; tokens: CuratedToken[] };
export type PrivacyBridge = {
  bridgeAddress: string; bridgeType: 'native' | 'erc20' | 'pod-native' | 'pod-erc20';
  publicTokenAddress: string | null; privateTokenAddress: string; factoryAddress?: string;
  default: boolean; verified: boolean; sortOrder: number;
};
export type PrivacyBridgesPayload = { chainId: number; bridges: PrivacyBridge[] };
export type TokenFamilyAction = 'allowed' | 'blocked' | 'confirm';
export type TokenFamily = {
  familyId: string; protocol: 'cipherdex'; assetKind: 'liquidity-position'; privacyMode: 'public' | 'private';
  detector: 'cipherdex-lp-v1' | 'cipherdex-protocol-lp-v1'; parentFactoryAddress: string; issuedTokenFactoryAddress: string;
  issuerMode: 'parent' | 'factory'; protocolVersion: number; privacyModeCode: number;
  presentation: { groupLabel: string; badgeLabel: string };
  actions: { swap: TokenFamilyAction; crossChain: TokenFamilyAction; privacyPortal: TokenFamilyAction; chatTip: TokenFamilyAction; transfer: TokenFamilyAction };
};
export type TokenFamiliesPayload = { version: number; chainId: number; families: TokenFamily[] };
export type TrustedNft = { contractAddress: string; tokenId: string };
export type TrustedNftsPayload = { chainId: number; nfts: TrustedNft[] };
export type CotiBridgeRoute = {
  sourceChainId: number; destinationChainId: number; sourceTokenSymbol: string; destinationTokenSymbol: string;
  sourceTokenAddress: string; destinationTokenAddress: string; bridgeRecipientAddress: string; enabled?: boolean;
  requiresQuotaCheck: boolean; quotaTokenAddress: string | null; quotaApiBaseUrl: string | null; statusApiBaseUrl: string; decimals: number;
};
export type CotiBridgeRoutesPayload = { version: number; routes: CotiBridgeRoute[] };
export type DomainPayload = { patterns: string[] };
export type NetworkConfigurationPayload = PublicNetworkPayload | TokenCatalogPayload | PrivacyBridgesPayload | TokenFamiliesPayload | TrustedNftsPayload | CotiBridgeRoutesPayload;

const DOMAIN = 'CipherTrade public metadata v1\n';
const DAY = 86400000;
const MAX_LIFETIME: Record<MetadataKind, number> = {
  token: 90 * DAY, asset: 90 * DAY, descriptor: 30 * DAY, networks: 30 * DAY, domains: 7 * DAY, classification: 30 * DAY,
};
const HASH = /^0x[0-9a-f]{64}$/;
const TEXT = /^[^\u0000-\u001f\u007f\u202a-\u202e\u2066-\u2069]+$/u;
const frozenValues = new WeakSet<object>();
const frozenDigests = new WeakMap<object, string>();

export function canonicalMetadata(value: unknown): string {
  let nodes = 0;
  const ancestors = new Set<object>();
  function visit(entry: unknown, depth: number): unknown {
    if (++nodes > 20000 || depth > 24) throw new Error('Metadata structure limit');
    if (entry === null || typeof entry === 'boolean') return entry;
    if (typeof entry === 'string') {
      if (entry.length > MAX_RECORD_BYTES) throw new Error('Metadata string limit');
      return entry;
    }
    if (typeof entry === 'number' && Number.isSafeInteger(entry)) return entry;
    if (!entry || typeof entry !== 'object' || ancestors.has(entry)) throw new Error('Invalid metadata JSON');
    if (!Array.isArray(entry) && ![Object.prototype, null].includes(Object.getPrototypeOf(entry))) throw new Error('Invalid metadata object');
    ancestors.add(entry);
    try {
      if (Array.isArray(entry)) return entry.map(child => visit(child, depth + 1));
      const result: Record<string, unknown> = Object.create(null);
      for (const key of Object.keys(entry).sort()) {
        if (['__proto__', 'prototype', 'constructor'].includes(key)) throw new Error('Unsafe metadata key');
        result[key] = visit((entry as Record<string, unknown>)[key], depth + 1);
      }
      return result;
    } finally { ancestors.delete(entry); }
  }
  const serialized = JSON.stringify(visit(value, 0));
  if (ethers.toUtf8Bytes(serialized).length > MAX_RECORD_BYTES) throw new Error('Metadata byte limit');
  return serialized;
}

export function metadataDigest(value: unknown): string {
  const frozen = value !== null && typeof value === 'object' && frozenValues.has(value);
  if (frozen) {
    const cached = frozenDigests.get(value as object);
    if (cached) return cached;
  }
  const digest = ethers.id(canonicalMetadata(value));
  if (frozen) frozenDigests.set(value as object, digest);
  return digest;
}
export function signatureDigest(type: 'trust' | 'record', value: unknown): string {
  return ethers.id(`${DOMAIN}${type}\n${canonicalMetadata(value)}`);
}
export function freezeMetadata<T>(value: T): T {
  if (value && typeof value === 'object') {
    for (const child of Object.values(value)) freezeMetadata(child);
    Object.freeze(value);
    frozenValues.add(value);
  }
  return value;
}
export function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value) || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) throw new Error('Expected metadata object');
  return value as Record<string, unknown>;
}
function exact(value: Record<string, unknown>, names: string[]): void {
  if (Object.keys(value).length !== names.length || names.some(name => !Object.hasOwn(value, name))) throw new Error('Unsupported metadata format');
}
function fields(value: Record<string, unknown>, required: string[], optional: string[] = []): void {
  const allowed = new Set([...required, ...optional]);
  if (required.some(name => !Object.hasOwn(value, name)) || Object.keys(value).some(name => !allowed.has(name))) throw new Error('Unsupported metadata format');
}
function text(value: unknown, max: number): asserts value is string {
  if (typeof value !== 'string' || !value.length || value.length > max || !TEXT.test(value)) throw new Error('Invalid metadata text');
}
function positive(value: unknown): asserts value is number {
  if (!Number.isSafeInteger(value) || Number(value) <= 0) throw new Error('Invalid metadata integer');
}
function integer(value: unknown, maximum: number): asserts value is number {
  if (!Number.isSafeInteger(value) || Number(value) < 0 || Number(value) > maximum) throw new Error('Invalid metadata integer');
}
function address(value: unknown, allowZero = false): asserts value is string {
  if (typeof value !== 'string' || !ethers.isAddress(value) || (!allowZero && value.toLowerCase() === ethers.ZeroAddress)) throw new Error('Invalid configuration address');
}
function list(value: unknown, maximum: number): asserts value is unknown[] {
  if (!Array.isArray(value) || value.length > maximum) throw new Error('Configuration collection limit');
}
function unique(seen: Set<string>, key: string): void {
  if (seen.has(key)) throw new Error('Duplicate configuration identity');
  seen.add(key);
}
function oneOf<T extends string>(value: unknown, values: readonly T[]): value is T {
  return typeof value === 'string' && values.includes(value as T);
}
function chainIdentity(row: Record<string, unknown>, chainId?: number): asserts row is Record<string, unknown> & { chainId: number } {
  positive(row.chainId);
  if (chainId !== undefined && row.chainId !== chainId) throw new Error('Configuration chain identity mismatch');
}
function publicUrl(value: unknown, protocol = 'https:'): void {
  text(value, 2048);
  const url = new URL(value);
  const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
  const parts = host.split('.').map(Number);
  const localV4 = /^\d+\.\d+\.\d+\.\d+$/.test(host) && (parts[0] === 0 || parts[0] === 10 || parts[0] === 127
    || (parts[0] === 100 && parts[1]! >= 64 && parts[1]! <= 127) || (parts[0] === 169 && parts[1] === 254)
    || (parts[0] === 172 && parts[1]! >= 16 && parts[1]! <= 31) || (parts[0] === 192 && (parts[1] === 168 || parts[1] === 0))
    || (parts[0] === 198 && (parts[1] === 18 || parts[1] === 19)) || parts[0]! >= 224);
  if (!value.startsWith(`${protocol}//`) || url.protocol !== protocol || url.username || url.password || url.hash || value.trim() !== value || /\s|\\/.test(value)
    || localV4 || !host.includes('.') && !host.includes(':') || /(^|\.)(localhost|local|internal|lan|home)$/.test(host)
    || !host.includes(':') && host.split('.').some(label => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))
    || (host.includes(':') && (!/^[23][0-9a-f]{3}:/.test(host) || /^2001:db8:/.test(host)))
    || [...url.searchParams.keys()].some(key => /^(?:api[-_]?key|key|token|access[-_]?token|auth|secret|password|authorization|signature)$/i.test(key))) throw new Error('Private or invalid endpoint cannot be published');
}
function checkTime(issuedAt: unknown, expiresAt: unknown, maxLifetime: number, now: number): void {
  positive(issuedAt); positive(expiresAt);
  if (expiresAt <= issuedAt || expiresAt - issuedAt > maxLifetime || issuedAt > now + 60000 || expiresAt <= now) throw new Error('Metadata outside validity period');
}
function checkTrustTime(payload: { schema: unknown; issuedAt: unknown; expiresAt: unknown }, now: number): void {
  if (payload.schema !== 1 && payload.schema !== 2) throw new Error('Unsupported trust schema');
  if (payload.schema === 2 && payload.expiresAt === null) {
    positive(payload.issuedAt);
    if (payload.issuedAt > now + 60000) throw new Error('Metadata outside validity period');
  } else checkTime(payload.issuedAt, payload.expiresAt, 90 * DAY, now);
}
function verifySignature(type: 'trust' | 'record', payload: unknown, signature: string, publicKey: string): void {
  if (!/^0x[0-9a-fA-F]{128}$/.test(signature)) throw new Error('Invalid metadata signature');
  const expected = ethers.SigningKey.computePublicKey(publicKey, true);
  const recovered = ethers.SigningKey.computePublicKey(ethers.SigningKey.recoverPublicKey(signatureDigest(type, payload), signature), true);
  if (recovered !== expected) throw new Error('Metadata signature mismatch');
}

export function tokenScope(chainId: number, address: string): string {
  positive(chainId);
  if (!ethers.isAddress(address)) throw new Error('Invalid token address');
  return `${chainId}:${address.toLowerCase()}`;
}
export function descriptorScope(chainId: number, address: string, selector: string): string {
  if (!/^0x[0-9a-f]{8}$/.test(selector)) throw new Error('Invalid selector');
  return `${tokenScope(chainId, address)}:${selector}`;
}
export function tokenIdentity(value: unknown): TokenIdentity {
  const row = object(value);
  positive(row.chainId);
  if (typeof row.address !== 'string' || row.address !== row.address.toLowerCase() || !ethers.isAddress(row.address)) throw new Error('Invalid token identity');
  text(row.symbol, 64);
  if (!Number.isInteger(row.decimals) || Number(row.decimals) < 0 || Number(row.decimals) > 255) throw new Error('Invalid token decimals');
  return { chainId: row.chainId, address: row.address, symbol: row.symbol, decimals: Number(row.decimals) };
}

export function validateMetadataPayload(kind: MetadataKind, scope: string, payload: unknown): void {
  const row = object(payload);
  if (!KINDS.includes(kind)) throw new Error('Unsupported publication kind');
  if (kind === 'networks') validateNetworkConfigurationPayload(scope, payload);
  if (kind === 'token' || kind === 'asset' || kind === 'classification') {
    positive(row.chainId);
    if (typeof row.address !== 'string' || tokenScope(row.chainId, row.address) !== scope) throw new Error('Payload identity mismatch');
    if (kind === 'token') tokenIdentity(payload);
    if (kind === 'classification') {
      if (typeof row.default !== 'boolean' || typeof row.verified !== 'boolean'
        || !['official', 'community', 'verified', 'unverified'].includes(String(row.verification))
        || row.verified !== (row.verification !== 'unverified') || (row.default && !row.verified)) throw new Error('Invalid classification');
    }
    if (row.logoUrl !== undefined) {
      text(row.logoUrl, 2048);
      const url = new URL(row.logoUrl);
      if (url.protocol !== 'https:' || url.username || url.password) throw new Error('Invalid logo URL');
    }
    if (kind === 'asset' && !row.logoUrl) throw new Error('Asset requires a logo URL');
  }
  if (kind === 'domains') {
    if (scope !== 'domains') throw new Error('Invalid domains scope');
    validateDomainPayload(payload);
  }
}

export function validatePublicNetworkPayload(input: unknown): asserts input is PublicNetworkPayload {
  const chains = object(input);
  const optional = ['explorerTxUrl', 'blockscoutUrl', 'rpcWsUrl', 'chainLogoUrl', 'logoUrl', 'priceOracle', 'cgCoinId', 'cgChainId', 'cgTerminalChainId', 'twChainId', 'feeModel', 'privacy', 'supportsPrivacy', 'supportsSwap', 'displayOrder'];
  if (Object.keys(chains).length > 256) throw new Error('Public chain catalog limit');
  for (const [id, value] of Object.entries(chains)) {
    if (!/^[1-9][0-9]*$/.test(id) || !Number.isSafeInteger(Number(id))) throw new Error('Invalid public chain id');
    const row = object(value);
    fields(row, ['name', 'nativeSymbol', 'rpcUrl', 'swapRoutes', 'appContracts'], optional);
    text(row.name, 128); text(row.nativeSymbol, 32); publicUrl(row.rpcUrl);
    if (row.rpcWsUrl != null) publicUrl(row.rpcWsUrl, 'wss:');
    for (const field of ['explorerTxUrl', 'blockscoutUrl', 'chainLogoUrl', 'logoUrl']) if (row[field] != null) publicUrl(row[field]);
    if (row.explorerTxUrl != null && (typeof row.explorerTxUrl !== 'string' || !row.explorerTxUrl.includes('{hash}') || /\{(?!hash\})/.test(row.explorerTxUrl))) throw new Error('Invalid explorer template');
    for (const field of ['priceOracle', 'cgCoinId', 'cgChainId', 'cgTerminalChainId', 'twChainId']) if (row[field] != null) text(row[field], 128);
    list(row.swapRoutes, SWAP_ROUTES.length);
    const routes = new Set<string>();
    for (const route of row.swapRoutes) {
      if (typeof route !== 'string' || !SWAP_ROUTES.includes(route as SwapRoute)) throw new Error('Invalid swap route');
      unique(routes, route);
    }
    const contracts = object(row.appContracts);
    exact(contracts, ['chatGCAddress', 'cipherDataGcAddress', 'memoGcAddress']);
    for (const value of Object.values(contracts)) if (value !== null) address(value);
    for (const field of ['supportsPrivacy', 'supportsSwap']) if (row[field] !== undefined && typeof row[field] !== 'boolean') throw new Error('Invalid chain flag');
    if (row.supportsSwap !== undefined && row.supportsSwap !== (routes.size > 0)) throw new Error('Swap route authorization mismatch');
    if (row.displayOrder !== undefined && !Number.isSafeInteger(row.displayOrder)) throw new Error('Invalid chain order');
    if (row.feeModel !== undefined && !oneOf(row.feeModel, ['eip1559', 'op-stack', 'coti'])) throw new Error('Invalid fee model');
    if (row.privacy != null) {
      const privacy = object(row.privacy);
      fields(privacy, ['supportsPrivacy'], ['privacyRealm', 'podInboxAddress', 'podMotherAddress']);
      if (typeof privacy.supportsPrivacy !== 'boolean') throw new Error('Nonpublic privacy configuration');
      if (privacy.privacyRealm != null && !oneOf(privacy.privacyRealm, ['coti-mainnet', 'coti-testnet', 'pod-mainnet', 'pod-testnet'])) throw new Error('Invalid privacy realm');
      for (const field of ['podInboxAddress', 'podMotherAddress']) if (privacy[field] != null) address(privacy[field]);
    }
  }
}

export function networkConfigScope(prefix: NetworkChainScope, chainId: number): string {
  if (!NETWORK_CHAIN_SCOPES.includes(prefix)) throw new Error('Invalid network scope');
  positive(chainId);
  return `${prefix}:${chainId}`;
}
export function validateTokenCatalogPayload(input: unknown, chainId?: number): asserts input is TokenCatalogPayload {
  const row = object(input);
  exact(row, ['chainId', 'defaults', 'verified', 'tokens']);
  chainIdentity(row, chainId);
  const classifications = new Map<string, string>();
  for (const name of ['defaults', 'verified', 'tokens']) {
    const entries = row[name];
    list(entries, 2048);
    const seen = new Set<string>();
    for (const entry of entries) {
      const token = object(entry);
      fields(token, ['tokenAddress'], ['chainId', 'private', 'tokenSymbol', 'name', 'tokenName', 'logoUrl', 'priceOracle', 'cgCoinId', 'decimals', 'verification', 'marketDataReference']);
      address(token.tokenAddress, true);
      unique(seen, token.tokenAddress.toLowerCase());
      if (Object.hasOwn(token, 'chainId') && token.chainId !== row.chainId) throw new Error('Configuration chain identity mismatch');
      if (token.private !== undefined && token.private !== null && typeof token.private !== 'boolean') throw new Error('Invalid token privacy flag');
      for (const key of ['tokenSymbol', 'name', 'tokenName', 'priceOracle', 'cgCoinId']) if (token[key] != null) text(token[key], key === 'tokenSymbol' ? 64 : 128);
      if (token.name != null && token.tokenName != null && token.name !== token.tokenName) throw new Error('Conflicting token names');
      if (token.logoUrl != null) publicUrl(token.logoUrl);
      if (token.decimals != null) integer(token.decimals, 255);
      if (token.verification !== undefined && !oneOf(token.verification, ['official', 'community', 'verified', 'unverified'])) throw new Error('Invalid curated classification');
      if (name !== 'tokens') {
        const verification = token.verification ?? (name === 'defaults' ? 'official' : 'community');
        if (verification === 'unverified') throw new Error('Invalid curated classification');
        const prior = classifications.get(token.tokenAddress.toLowerCase());
        if (prior && prior !== verification) throw new Error('Conflicting curated classifications');
        classifications.set(token.tokenAddress.toLowerCase(), String(verification));
      }
      if (token.marketDataReference != null) {
        const reference = object(token.marketDataReference);
        fields(reference, ['tokenAddress'], ['chainId', 'priceMultiplier']);
        if (reference.chainId !== undefined) positive(reference.chainId);
        if (reference.tokenAddress !== 'native') address(reference.tokenAddress, true);
        if (reference.priceMultiplier !== undefined) {
          text(reference.priceMultiplier, 128);
          if (!/^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$/.test(reference.priceMultiplier) || !Number.isFinite(Number(reference.priceMultiplier)) || Number(reference.priceMultiplier) <= 0) throw new Error('Invalid market multiplier');
        }
      }
    }
  }
}
export function validatePrivacyBridgesPayload(input: unknown, chainId?: number): asserts input is PrivacyBridgesPayload {
  const row = object(input);
  exact(row, ['chainId', 'bridges']); chainIdentity(row, chainId); list(row.bridges, 512);
  const bridges = new Set<string>(), tokens = new Set<string>();
  for (const entry of row.bridges) {
    const bridge = object(entry);
    fields(bridge, ['bridgeAddress', 'bridgeType', 'publicTokenAddress', 'privateTokenAddress', 'default', 'verified', 'sortOrder'], ['factoryAddress']);
    address(bridge.bridgeAddress); address(bridge.privateTokenAddress);
    unique(bridges, bridge.bridgeAddress.toLowerCase()); unique(tokens, bridge.privateTokenAddress.toLowerCase());
    if (!oneOf(bridge.bridgeType, ['native', 'erc20', 'pod-native', 'pod-erc20'])) throw new Error('Invalid privacy bridge type');
    if (bridge.bridgeType === 'native') {
      if (bridge.publicTokenAddress !== null) throw new Error('Invalid native privacy bridge');
    } else address(bridge.publicTokenAddress);
    if (String(bridge.bridgeType).startsWith('pod-')) address(bridge.factoryAddress);
    else if (bridge.factoryAddress !== undefined) throw new Error('Unsupported privacy bridge factory');
    if (typeof bridge.publicTokenAddress === 'string' && bridge.publicTokenAddress.toLowerCase() === bridge.privateTokenAddress.toLowerCase()
      || bridge.bridgeAddress.toLowerCase() === bridge.privateTokenAddress.toLowerCase()) throw new Error('Invalid privacy bridge identity');
    if (typeof bridge.default !== 'boolean' || typeof bridge.verified !== 'boolean' || bridge.default && !bridge.verified) throw new Error('Invalid privacy bridge classification');
    integer(bridge.sortOrder, Number.MAX_SAFE_INTEGER);
  }
}
export function validateTokenFamiliesPayload(input: unknown, chainId?: number): asserts input is TokenFamiliesPayload {
  const row = object(input);
  exact(row, ['version', 'chainId', 'families']); positive(row.version); chainIdentity(row, chainId); list(row.families, 256);
  const ids = new Set<string>(), registries = new Set<string>();
  for (const entry of row.families) {
    const family = object(entry);
    exact(family, ['familyId', 'protocol', 'assetKind', 'privacyMode', 'detector', 'parentFactoryAddress', 'issuedTokenFactoryAddress', 'issuerMode', 'protocolVersion', 'privacyModeCode', 'presentation', 'actions']);
    text(family.familyId, 128);
    if (!/^[a-z0-9][a-z0-9-]*$/.test(family.familyId)) throw new Error('Invalid token family id');
    unique(ids, family.familyId);
    if (family.protocol !== 'cipherdex' || family.assetKind !== 'liquidity-position'
      || !oneOf(family.privacyMode, ['public', 'private']) || !oneOf(family.detector, ['cipherdex-lp-v1', 'cipherdex-protocol-lp-v1'])
      || !oneOf(family.issuerMode, ['parent', 'factory'])) throw new Error('Invalid token family policy');
    address(family.parentFactoryAddress); address(family.issuedTokenFactoryAddress);
    positive(family.protocolVersion); integer(family.privacyModeCode, 2);
    if ((family.privacyMode === 'public') !== (family.privacyModeCode === 0)) throw new Error('Invalid token family privacy mode');
    unique(registries, `${family.issuedTokenFactoryAddress.toLowerCase()}:${family.privacyModeCode}`);
    const presentation = object(family.presentation);
    exact(presentation, ['groupLabel', 'badgeLabel']); text(presentation.groupLabel, 128); text(presentation.badgeLabel, 128);
    const actions = object(family.actions);
    exact(actions, ['swap', 'crossChain', 'privacyPortal', 'chatTip', 'transfer']);
    if (Object.values(actions).some(value => !oneOf(value, ['allowed', 'blocked', 'confirm']))) throw new Error('Invalid token family action');
  }
}
export function validateTrustedNftsPayload(input: unknown, chainId?: number): asserts input is TrustedNftsPayload {
  const row = object(input);
  exact(row, ['chainId', 'nfts']); chainIdentity(row, chainId); list(row.nfts, 2048);
  const seen = new Set<string>();
  for (const entry of row.nfts) {
    const nft = object(entry);
    exact(nft, ['contractAddress', 'tokenId']); address(nft.contractAddress); text(nft.tokenId, 78);
    if (!/^(?:0|[1-9][0-9]*)$/.test(nft.tokenId) || BigInt(nft.tokenId) > ethers.MaxUint256) throw new Error('Invalid NFT token id');
    unique(seen, `${nft.contractAddress.toLowerCase()}:${nft.tokenId}`);
  }
}
export function validateCotiBridgeRoutesPayload(input: unknown): asserts input is CotiBridgeRoutesPayload {
  const row = object(input);
  exact(row, ['version', 'routes']); positive(row.version); list(row.routes, 512);
  const seen = new Set<string>();
  for (const entry of row.routes) {
    const route = object(entry);
    fields(route, ['sourceChainId', 'destinationChainId', 'sourceTokenSymbol', 'destinationTokenSymbol', 'sourceTokenAddress', 'destinationTokenAddress', 'bridgeRecipientAddress', 'requiresQuotaCheck', 'quotaTokenAddress', 'quotaApiBaseUrl', 'statusApiBaseUrl', 'decimals'], ['enabled']);
    positive(route.sourceChainId); positive(route.destinationChainId);
    if (route.sourceChainId === route.destinationChainId || ![2632500, 7082400].includes(route.sourceChainId) && ![2632500, 7082400].includes(route.destinationChainId)) throw new Error('Invalid COTI chain pair');
    text(route.sourceTokenSymbol, 64); text(route.destinationTokenSymbol, 64);
    address(route.sourceTokenAddress, true); address(route.destinationTokenAddress, true); address(route.bridgeRecipientAddress);
    unique(seen, `${route.sourceChainId}:${route.destinationChainId}:${route.sourceTokenAddress.toLowerCase()}`);
    if (route.enabled !== undefined && typeof route.enabled !== 'boolean' || typeof route.requiresQuotaCheck !== 'boolean') throw new Error('Invalid COTI bridge flag');
    if (route.requiresQuotaCheck) {
      address(route.quotaTokenAddress, true); publicUrl(route.quotaApiBaseUrl);
      if (route.quotaTokenAddress.toLowerCase() !== route.sourceTokenAddress.toLowerCase()) throw new Error('Invalid quota token identity');
    } else if (route.quotaTokenAddress !== null || route.quotaApiBaseUrl !== null) throw new Error('Unsupported COTI quota configuration');
    publicUrl(route.statusApiBaseUrl); integer(route.decimals, 255);
  }
}
export function validateDomainPayload(input: unknown): asserts input is DomainPayload {
  const row = object(input);
  exact(row, ['patterns']); list(row.patterns, 256);
  const seen = new Set<string>();
  for (const pattern of row.patterns) {
    text(pattern, 256);
    const host = pattern.startsWith('*.') ? pattern.slice(2) : pattern;
    if (pattern !== pattern.toLowerCase() || host.length > 253 || !host.includes('.') || /^\d+(?:\.\d+){3}$/.test(host)
      || host.split('.').some(label => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))
      || /(^|\.)(localhost|local|internal|lan|home)$/.test(host)) throw new Error('Invalid trusted domain pattern');
    unique(seen, pattern);
  }
}
export function validateNetworkConfigurationPayload(scope: string, input: unknown): asserts input is NetworkConfigurationPayload {
  if (scope === 'chains') return validatePublicNetworkPayload(input);
  if (scope === 'coti-bridge-routes') return validateCotiBridgeRoutesPayload(input);
  const match = /^(tokens|privacy-bridges|token-families|trusted-nfts):([1-9][0-9]*)$/.exec(scope);
  if (!match) throw new Error('Invalid network scope');
  const chainId = Number(match[2]); positive(chainId);
  switch (match[1]) {
    case 'tokens': return validateTokenCatalogPayload(input, chainId);
    case 'privacy-bridges': return validatePrivacyBridgesPayload(input, chainId);
    case 'token-families': return validateTokenFamiliesPayload(input, chainId);
    case 'trusted-nfts': return validateTrustedNftsPayload(input, chainId);
  }
}
export function validateConfigurationPublication(records: readonly { kind: MetadataKind; scope: string; payload: unknown }[]): void {
  const configuration = new Map<string, unknown>();
  for (const record of records) {
    if (record.kind !== 'networks' && record.kind !== 'domains') continue;
    validateMetadataPayload(record.kind, record.scope, record.payload);
    const id = `${record.kind}:${record.scope}`;
    if (configuration.has(id)) throw new Error('Duplicate configuration scope');
    configuration.set(id, record.payload);
  }
  const chains = configuration.get('networks:chains');
  if (!chains || !configuration.has('domains:domains') || !configuration.has('networks:coti-bridge-routes')) throw new Error('Incomplete configuration publication');
  validatePublicNetworkPayload(chains);
  const required = new Set(['networks:chains', 'domains:domains', 'networks:coti-bridge-routes']);
  for (const chainId of Object.keys(chains).map(Number)) for (const prefix of NETWORK_CHAIN_SCOPES) required.add(`networks:${networkConfigScope(prefix, chainId)}`);
  if (required.size !== configuration.size || [...required].some(id => !configuration.has(id))) throw new Error('Incomplete or unsupported configuration publication');
  const coti = configuration.get('networks:coti-bridge-routes') as CotiBridgeRoutesPayload;
  if (coti.routes.some(route => !Object.hasOwn(chains, route.sourceChainId) || !Object.hasOwn(chains, route.destinationChainId))) throw new Error('COTI route uses an unsupported chain');
  for (const chainId of Object.keys(chains)) {
    const tokens = configuration.get(`networks:tokens:${chainId}`) as TokenCatalogPayload;
    for (const token of [...tokens.defaults, ...tokens.verified, ...tokens.tokens]) {
      const target = token.marketDataReference?.chainId;
      if (target !== undefined && !Object.hasOwn(chains, target)) throw new Error('Market reference uses an unsupported chain');
    }
  }
}
export function encodeMetadataHeader(value: unknown): string {
  const raw = canonicalMetadata(value);
  return ethers.encodeBase64(ethers.toUtf8Bytes(raw)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}
export function decodeMetadataHeader(value: string, max = MAX_HEADER_BYTES): unknown {
  if (!value || value.length > max || !/^[A-Za-z0-9_-]+$/.test(value)) throw new Error('Invalid metadata header');
  const json = ethers.toUtf8String(ethers.decodeBase64(value.replace(/-/g, '+').replace(/_/g, '/')));
  const parsed: unknown = JSON.parse(json);
  canonicalMetadata(parsed);
  return parsed;
}

export class MetadataVerifier {
  private readonly roots: readonly RootKey[];
  private trust: SignedTrust | null = null;
  private checkpoint: Checkpoint | null;
  private readonly memo = new Map<string, SignedRecord>();
  private readonly payloads = new Map<string, unknown>();
  private readonly heads = new Map<string, Checkpoint>();
  private readonly authenticatedRecords = new WeakMap<SignedRecord, SignedTrust>();

  constructor(roots: readonly RootKey[], checkpoint: Checkpoint | null = null) {
    this.roots = freezeMetadata(JSON.parse(canonicalMetadata(roots)) as RootKey[]);
    this.checkpoint = checkpoint;
  }
  get configured(): boolean { return this.roots.length > 0; }
  get trustHash(): string { return this.trust ? metadataDigest(this.trust) : metadataDigest(this.roots); }
  get currentTrust(): SignedTrust | null { return this.trust; }
  get trustCheckpoint(): Checkpoint | null { return this.checkpoint; }

  acceptTrust(input: unknown, now = Date.now()): SignedTrust {
    const inputDigest = metadataDigest(input);
    if (this.trust && inputDigest === metadataDigest(this.trust)) {
      checkTrustTime(this.trust.payload, now);
      return this.trust;
    }
    const wrapper = object(input);
    exact(wrapper, ['rootId', 'payload', 'signature']);
    const payload = object(wrapper.payload);
    exact(payload, ['schema', 'sequence', 'issuedAt', 'expiresAt', 'keys', 'revokedDigests', 'minimumSequences']);
    positive(payload.sequence);
    checkTrustTime({ schema: payload.schema, issuedAt: payload.issuedAt, expiresAt: payload.expiresAt }, now);
    if (!Array.isArray(payload.keys) || payload.keys.length > 16 || !Array.isArray(payload.revokedDigests) || payload.revokedDigests.length > 256) throw new Error('Trust limits exceeded');
    if (payload.revokedDigests.some(hash => typeof hash !== 'string' || !HASH.test(hash))) throw new Error('Invalid revocation');
    const minimum = object(payload.minimumSequences);
    exact(minimum, [...KINDS]);
    for (const kind of KINDS) positive(minimum[kind]);
    const ids = new Set<string>();
    for (const entry of payload.keys) {
      const key = object(entry);
      exact(key, ['id', 'publicKey', 'kinds', 'notBefore', 'expiresAt']);
      text(key.id, 64);
      if (ids.has(key.id)) throw new Error('Duplicate publishing key');
      ids.add(key.id);
      if (typeof key.publicKey !== 'string' || !/^0x(?:[0-9a-fA-F]{66}|[0-9a-fA-F]{130})$/.test(key.publicKey)) throw new Error('Invalid publishing public key');
      ethers.SigningKey.computePublicKey(key.publicKey, true);
      if (!Array.isArray(key.kinds) || !key.kinds.length || key.kinds.some(kind => !KINDS.includes(kind))) throw new Error('Invalid publishing role');
      positive(key.notBefore);
      if (payload.schema !== 2 || key.expiresAt !== null) {
        positive(key.expiresAt);
        if (key.expiresAt <= key.notBefore) throw new Error('Invalid publishing key lifetime');
      }
    }
    const root = this.roots.find(key => key.id === wrapper.rootId);
    if (!root || typeof wrapper.signature !== 'string') throw new Error('Unknown trust root');
    verifySignature('trust', payload, wrapper.signature, root.publicKey);
    const digest = metadataDigest(payload);
    if (this.checkpoint && (payload.sequence < this.checkpoint.sequence || (payload.sequence === this.checkpoint.sequence && digest !== this.checkpoint.digest))) throw new Error('Trust rollback or equivocation');
    const clone = freezeMetadata(JSON.parse(canonicalMetadata(input)) as SignedTrust);
    if (this.trustHash !== metadataDigest(clone)) this.memo.clear();
    this.trust = clone;
    this.checkpoint = { sequence: payload.sequence, digest };
    return clone;
  }

  verify<T = unknown>(payload: T, evidence: Evidence, kind: MetadataKind, scope: string, now = Date.now()): SignedRecord<T> {
    if (!KINDS.includes(kind)) throw new Error('Unsupported publication kind');
    const trust = this.trust?.payload;
    if (!trust) throw new Error('No authenticated trust policy');
    checkTrustTime(trust, now);
    const envelope = object(evidence);
    exact(envelope, ['statement', 'signature']);
    const statement = object(envelope.statement);
    exact(statement, ['schema', 'kind', 'scope', 'keyId', 'sequence', 'issuedAt', 'expiresAt', 'digest']);
    if (statement.schema !== 1 || statement.kind !== kind || statement.scope !== scope) throw new Error('Metadata scope mismatch');
    text(statement.scope, 256); text(statement.keyId, 64); positive(statement.sequence);
    const key = this.assertRecordAuthority(statement as Statement, kind, scope, now);
    validateMetadataPayload(kind, scope, payload);
    const digest = metadataDigest(payload);
    if (statement.digest !== digest) throw new Error('Metadata digest revoked, old or mismatched');
    const scopeKey = `${kind}:${scope}`;
    const memoKey = `${metadataDigest(evidence.statement)}:${evidence.signature}`;
    const cached = this.memo.get(memoKey);
    if (cached) return cached as SignedRecord<T>;
    if (typeof envelope.signature !== 'string') throw new Error('Invalid signature');
    verifySignature('record', statement, envelope.signature, key.publicKey);
    let frozenPayload = this.payloads.get(digest);
    if (frozenPayload === undefined) {
      frozenPayload = freezeMetadata(JSON.parse(canonicalMetadata(payload)) as unknown);
      this.payloads.set(digest, frozenPayload);
      while (this.payloads.size > 128) this.payloads.delete(this.payloads.keys().next().value!);
    }
    const accepted = Object.freeze({ payload: frozenPayload as T,
      statement: freezeMetadata(JSON.parse(canonicalMetadata(statement)) as Statement), signature: envelope.signature });
    this.authenticatedRecords.set(accepted, this.trust!);
    this.memo.set(memoKey, accepted);
    this.heads.delete(scopeKey);
    this.heads.set(scopeKey, { sequence: statement.sequence, digest });
    while (this.memo.size > 128) this.memo.delete(this.memo.keys().next().value!);
    while (this.heads.size > 4096) this.heads.delete(this.heads.keys().next().value!);
    return accepted;
  }

  verifyRecord<T>(record: SignedRecord<T>, kind: MetadataKind, scope: string, now = Date.now()): SignedRecord<T> {
    // Only this verifier's immutable, authenticated objects can skip JSON/schema/signature work.
    if (this.authenticatedRecords.get(record) === this.trust && this.trust !== null) {
      this.assertRecordAuthority(record.statement, kind, scope, now);
      return record;
    }
    return this.verify(record.payload, { statement: record.statement, signature: record.signature }, kind, scope, now);
  }

  private assertRecordAuthority(statement: Statement, kind: MetadataKind, scope: string, now: number): DelegatedKey {
    if (!KINDS.includes(kind)) throw new Error('Unsupported publication kind');
    const trust = this.trust?.payload;
    if (!trust) throw new Error('No authenticated trust policy');
    checkTrustTime(trust, now);
    if (statement.schema !== 1 || statement.kind !== kind || statement.scope !== scope) throw new Error('Metadata scope mismatch');
    checkTime(statement.issuedAt, statement.expiresAt, MAX_LIFETIME[kind], now);
    if (trust.revokedDigests.includes(statement.digest) || statement.sequence < trust.minimumSequences[kind]) throw new Error('Metadata digest revoked, old or mismatched');
    const key = trust.keys.find(candidate => candidate.id === statement.keyId && candidate.kinds.includes(kind));
    if (!key || key.notBefore > statement.issuedAt
      || (key.expiresAt !== null && (key.expiresAt < statement.expiresAt || key.expiresAt <= now))) throw new Error('Publishing key not authorized');
    const head = this.heads.get(`${kind}:${scope}`);
    if (head && (statement.sequence < head.sequence || (statement.sequence === head.sequence && head.digest !== statement.digest))) throw new Error('Record rollback or equivocation');
    return key;
  }
}
