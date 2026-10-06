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
  name?: string; logoUrl?: string; logoSha256?: string;
  source: string; revision: string;
};

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
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Expected metadata object');
  return value as Record<string, unknown>;
}
function exact(value: Record<string, unknown>, names: string[]): void {
  if (Object.keys(value).length !== names.length || names.some(name => !Object.hasOwn(value, name))) throw new Error('Unsupported metadata format');
}
function text(value: unknown, max: number): asserts value is string {
  if (typeof value !== 'string' || !value.length || value.length > max || !TEXT.test(value)) throw new Error('Invalid metadata text');
}
function positive(value: unknown): asserts value is number {
  if (!Number.isSafeInteger(value) || Number(value) <= 0) throw new Error('Invalid metadata integer');
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

function validatePayload(kind: MetadataKind, scope: string, payload: unknown): void {
  const row = object(payload);
  if (kind === 'networks') {
    if (scope !== 'chains') throw new Error('Invalid network scope');
    validatePublicNetworkPayload(payload);
  }
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
    if (row.logoSha256 !== undefined && (typeof row.logoSha256 !== 'string' || !HASH.test(row.logoSha256) || !row.logoUrl)) throw new Error('Invalid logo digest');
    if (kind === 'asset' && !row.logoSha256) throw new Error('Asset requires a content digest');
  }
  if (kind === 'domains') {
    if (scope !== 'domains' || !Array.isArray(row.origins) || row.origins.length > 64) throw new Error('Invalid domains catalog');
    for (const origin of row.origins) {
      text(origin, 256);
      const url = new URL(origin);
      if (url.protocol !== 'https:' || url.origin !== origin || url.username || url.password) throw new Error('Invalid trusted origin');
    }
  }
}

export function validatePublicNetworkPayload(input: unknown): void {
  const chains = object(input);
  const allowed = new Set(['name', 'explorerTxUrl', 'blockscoutUrl', 'nativeSymbol', 'rpcUrl', 'rpcWsUrl', 'chainLogoUrl', 'logoUrl', 'priceOracle', 'cgCoinId', 'cgChainId', 'cgTerminalChainId', 'twChainId', 'feeModel', 'privacy', 'supportsPrivacy', 'supportsSwap', 'displayOrder']);
  if (Object.keys(chains).length > 256) throw new Error('Public chain catalog limit');
  for (const [id, value] of Object.entries(chains)) {
    if (!/^[1-9][0-9]*$/.test(id) || !Number.isSafeInteger(Number(id))) throw new Error('Invalid public chain id');
    const row = object(value);
    if (Object.keys(row).some(key => !allowed.has(key))) throw new Error('Nonpublic or unsupported chain field');
    text(row.name, 128); text(row.nativeSymbol, 32); text(row.rpcUrl, 2048);
    for (const field of ['rpcUrl', 'rpcWsUrl']) {
      if (row[field] == null) continue;
      text(row[field], 2048);
      const url = new URL(row[field]);
      const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, '');
      const parts = host.split('.').map(Number);
      const localV4 = /^\d+\.\d+\.\d+\.\d+$/.test(host) && (parts[0] === 0 || parts[0] === 10 || parts[0] === 127
        || (parts[0] === 169 && parts[1] === 254) || (parts[0] === 172 && parts[1]! >= 16 && parts[1]! <= 31)
        || (parts[0] === 192 && parts[1] === 168) || parts[0]! >= 224);
      if (url.protocol !== (field === 'rpcWsUrl' ? 'wss:' : 'https:') || url.username || url.password || localV4
        || host === 'localhost' || /\.(localhost|local|internal)$/.test(host)
        || (host.includes(':') && /^(::|f[cd]|fe[89ab])/.test(host))) throw new Error('Private endpoint cannot be published');
    }
    for (const field of ['explorerTxUrl', 'blockscoutUrl', 'chainLogoUrl', 'logoUrl', 'priceOracle', 'cgCoinId', 'cgChainId', 'cgTerminalChainId', 'twChainId']) {
      if (row[field] != null && (typeof row[field] !== 'string' || row[field].length > 2048)) throw new Error('Invalid chain text');
    }
    for (const field of ['supportsPrivacy', 'supportsSwap']) if (row[field] !== undefined && typeof row[field] !== 'boolean') throw new Error('Invalid chain flag');
    if (row.displayOrder !== undefined && !Number.isSafeInteger(row.displayOrder)) throw new Error('Invalid chain order');
    if (row.feeModel !== undefined && !['eip1559', 'op-stack', 'coti'].includes(String(row.feeModel))) throw new Error('Invalid fee model');
    if (row.privacy != null) {
      const privacy = object(row.privacy);
      if (Object.keys(privacy).some(key => !['supportsPrivacy', 'privacyRealm', 'podInboxAddress', 'podMotherAddress'].includes(key)) || typeof privacy.supportsPrivacy !== 'boolean') throw new Error('Nonpublic privacy configuration');
      if (privacy.privacyRealm != null && !['coti-mainnet', 'coti-testnet', 'pod-mainnet', 'pod-testnet'].includes(String(privacy.privacyRealm))) throw new Error('Invalid privacy realm');
      for (const field of ['podInboxAddress', 'podMotherAddress']) if (privacy[field] != null && (typeof privacy[field] !== 'string' || !ethers.isAddress(privacy[field]))) throw new Error('Invalid privacy address');
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
    checkTime(statement.issuedAt, statement.expiresAt, MAX_LIFETIME[kind], now);
    validatePayload(kind, scope, payload);
    const digest = metadataDigest(payload);
    if (statement.digest !== digest || trust.revokedDigests.includes(digest) || statement.sequence < trust.minimumSequences[kind]) throw new Error('Metadata digest revoked, old or mismatched');
    const key = trust.keys.find(candidate => candidate.id === statement.keyId && candidate.kinds.includes(kind));
    if (!key || key.notBefore > Number(statement.issuedAt)
      || (key.expiresAt !== null && (key.expiresAt < Number(statement.expiresAt) || key.expiresAt <= now))) throw new Error('Publishing key not authorized');
    const scopeKey = `${kind}:${scope}`;
    const head = this.heads.get(scopeKey);
    if (head && (statement.sequence < head.sequence || (statement.sequence === head.sequence && head.digest !== digest))) throw new Error('Record rollback or equivocation');
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
    this.memo.set(memoKey, accepted);
    this.heads.delete(scopeKey);
    this.heads.set(scopeKey, { sequence: statement.sequence, digest });
    while (this.memo.size > 128) this.memo.delete(this.memo.keys().next().value!);
    while (this.heads.size > 4096) this.heads.delete(this.heads.keys().next().value!);
    return accepted;
  }
}
