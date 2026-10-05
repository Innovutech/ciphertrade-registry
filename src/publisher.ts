import fs from 'node:fs/promises';
import path from 'node:path';
import { ethers } from 'ethers';
import { resolveDescriptorIncludes } from './descriptorIncludes.ts';
import {
  canonicalMetadata, metadataDigest, signatureDigest, tokenIdentity, tokenScope, descriptorScope,
  MetadataVerifier, encodeMetadataHeader, MAX_HEADER_BYTES, type MetadataKind, type SignedRecord, type SignedTrust, type RootKey, type TokenPublication,
} from './protocol.ts';

export type Candidate = { kind: MetadataKind; scope: string; payload: unknown };
export type PreparedPublication = {
  schema: 1; sequence: number; issuedAt: number; expiresAt: number;
  sources: { name: string; revision: string }[]; records: Candidate[];
};
export type ImportOptions = {
  curatedDirectory: string; trustWalletDirectory?: string; registryDirectory?: string;
  chains: Record<string, { twChainId?: string }>;
  networks?: unknown; domains?: unknown;
  revisions: { curated: string; trustWallet?: string; registry?: string };
};

function safeText(value: unknown, limit: number): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= limit && !/[\u0000-\u001f\u007f\u202a-\u202e\u2066-\u2069]/u.test(value);
}
async function readJson(filename: string): Promise<unknown> {
  const stat = await fs.lstat(filename);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 512 * 1024) throw new Error(`Unsupported source file: ${path.basename(filename)}`);
  return JSON.parse(await fs.readFile(filename, 'utf8'));
}

const logoHosts = new Set(['raw.githubusercontent.com', 'assets-cdn.trustwallet.com', 'assets.coingecko.com',
  'coin-images.coingecko.com', 'ciphertrade.org', 'coti.io', 'coti.carbondefi.xyz', 's2.coinmarketcap.com']);
const logoDigests = new Map<string, Promise<string | null>>();
async function remoteLogoDigest(value: string): Promise<string | null> {
  const prior = logoDigests.get(value);
  if (prior) return prior;
  const lookup = (async () => {
    try {
      const url = new URL(value);
      if (url.protocol !== 'https:' || url.username || url.password || !logoHosts.has(url.hostname)) return null;
      const response = await fetch(url, { signal: AbortSignal.timeout(8000), redirect: 'error' });
      if (!response.ok || Number(response.headers.get('content-length')) > 256 * 1024) return null;
      const reader = response.body?.getReader();
      if (!reader) return null;
      const chunks: Uint8Array[] = [];
      let length = 0;
      for (;;) {
        const part = await reader.read();
        if (part.done) break;
        length += part.value.length;
        if (length > 256 * 1024) { await reader.cancel(); return null; }
        chunks.push(part.value);
      }
      return ethers.sha256(ethers.concat(chunks));
    } catch { return null; }
  })();
  logoDigests.set(value, lookup);
  return lookup;
}
async function logo(directory: string, relative: string, baseUrl: string): Promise<{ logoUrl: string; logoSha256: string } | {}> {
  try {
    const filename = path.join(directory, relative);
    const stat = await fs.lstat(filename);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 256 * 1024) return {};
    const bytes = await fs.readFile(filename);
    if (bytes.subarray(0, 8).toString('hex') !== '89504e470d0a1a0a') return {};
    return { logoUrl: `${baseUrl}/${relative.split(path.sep).map(encodeURIComponent).join('/')}`, logoSha256: ethers.sha256(bytes) };
  } catch { return {}; }
}

export async function importTokenSources(options: ImportOptions): Promise<Candidate[]> {
  const tokens = new Map<string, TokenPublication>();
  const assetsOnly = new Map<string, Candidate>();
  // Discover all assets for supported chains, not just our curated defaults.
  if (options.trustWalletDirectory && options.revisions.trustWallet) {
    if (!/^[0-9a-f]{40}$/.test(options.revisions.trustWallet)) throw new Error('Trust Wallet source must be an exact revision');
    for (const [id, chain] of Object.entries(options.chains)) {
      if (!chain.twChainId || !/^[a-z0-9_-]+$/.test(chain.twChainId)) continue;
      const directory = path.join(options.trustWalletDirectory, 'blockchains', chain.twChainId, 'assets');
      try {
        const native = await readJson(path.join(options.trustWalletDirectory, 'blockchains', chain.twChainId, 'info/info.json')) as Record<string, unknown>;
        const identity = tokenIdentity({ chainId: Number(id), address: '0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee', symbol: native.symbol, decimals: native.decimals });
        tokens.set(tokenScope(identity.chainId, identity.address), { ...identity,
          ...(safeText(native.name, 128) ? { name: native.name } : {}),
          ...await logo(options.trustWalletDirectory, path.join('blockchains', chain.twChainId, 'info/logo.png'), `https://raw.githubusercontent.com/trustwallet/assets/${options.revisions.trustWallet}`),
          source: 'trustwallet', revision: options.revisions.trustWallet,
        });
      } catch { /* A missing chain icon does not prevent individual token coverage. */ }
      const assets = await fs.readdir(directory, { withFileTypes: true }).catch(() => []);
      for (const asset of assets) {
        if (!asset.isDirectory() || asset.isSymbolicLink() || !ethers.isAddress(asset.name)) continue;
        const scope = tokenScope(Number(id), asset.name);
        const relative = path.join('blockchains', chain.twChainId, 'assets', asset.name, 'logo.png');
        const image = await logo(options.trustWalletDirectory, relative, `https://raw.githubusercontent.com/trustwallet/assets/${options.revisions.trustWallet}`);
        if ('logoSha256' in image) assetsOnly.set(scope, { kind: 'asset', scope, payload: {
          chainId: Number(id), address: asset.name.toLowerCase(), ...image, source: 'trustwallet', revision: options.revisions.trustWallet,
        } });
        try {
          const info = await readJson(path.join(directory, asset.name, 'info.json')) as Record<string, unknown>;
          if (typeof info.id !== 'string' || info.id.toLowerCase() !== asset.name.toLowerCase() || info.status !== 'active') {
            assetsOnly.delete(scope);
            continue;
          }
          if (!safeText(info.symbol, 64) || !Number.isInteger(info.decimals) || Number(info.decimals) < 0 || Number(info.decimals) > 255) continue;
          const identity = tokenIdentity({ chainId: Number(id), address: asset.name.toLowerCase(), symbol: info.symbol, decimals: info.decimals });
          tokens.set(tokenScope(identity.chainId, identity.address), {
            ...identity, ...(safeText(info.name, 128) ? { name: info.name } : {}),
            ...image,
            source: 'trustwallet', revision: options.revisions.trustWallet,
          });
          assetsOnly.delete(scope);
        } catch { /* Unsupported/malformed external rows are not promoted into signed identity. */ }
      }
    }
  }
  const classifications = new Map<string, Candidate>();
  for (const id of Object.keys(options.chains)) {
    for (const prefix of ['tokens', 'verified_tokens', 'default_tokens']) {
      const rows = await readJson(path.join(options.curatedDirectory, `${prefix}.${id}.json`)).catch(error => {
        if (error?.code === 'ENOENT') return [];
        throw error;
      }) as Record<string, unknown>[];
      if (!Array.isArray(rows)) throw new Error('Invalid curated token list');
      for (const row of rows) {
        const address = typeof row.tokenAddress === 'string' ? row.tokenAddress.toLowerCase() : '';
        const scope = tokenScope(Number(id), address);
        const external = tokens.get(scope);
        const symbol = row.tokenSymbol ?? external?.symbol;
        const decimals = row.decimals ?? external?.decimals;
        const digest = typeof row.logoUrl === 'string' ? await remoteLogoDigest(row.logoUrl) : null;
        // Incomplete curated records remain usable in the API, but cannot attest decimals.
        if (symbol != null && decimals != null) {
          const identity = tokenIdentity({ chainId: Number(id), address, symbol, decimals });
          tokens.set(scope, {
            ...identity,
            ...(safeText(row.name ?? row.tokenName, 128) ? { name: String(row.name ?? row.tokenName) } : external?.name ? { name: external.name } : {}),
            ...(typeof row.logoUrl === 'string' ? { logoUrl: row.logoUrl, ...(digest ? { logoSha256: digest } : {}) }
              : external?.logoUrl ? { logoUrl: external.logoUrl, ...(external.logoSha256 ? { logoSha256: external.logoSha256 } : {}) } : {}),
            source: 'ciphertrade', revision: options.revisions.curated,
          });
          assetsOnly.delete(scope);
        } else if (digest && typeof row.logoUrl === 'string') {
          assetsOnly.set(scope, { kind: 'asset', scope, payload: { chainId: Number(id), address,
            logoUrl: row.logoUrl, logoSha256: digest, source: 'ciphertrade', revision: options.revisions.curated } });
        }
        if (prefix !== 'tokens') {
          const verification = row.verification ?? (prefix === 'default_tokens' ? 'official' : 'community');
          if (!['official', 'community', 'verified'].includes(String(verification))) throw new Error('Invalid curated classification');
          classifications.set(scope, { kind: 'classification', scope, payload: {
            chainId: Number(id), address, default: prefix === 'default_tokens', verified: true, verification,
          } });
        }
      }
    }
  }
  const overrides = await readJson(path.join(options.curatedDirectory, 'classification-overrides.json')).catch(error => {
    if (error?.code === 'ENOENT') return [];
    throw error;
  });
  if (!Array.isArray(overrides) || overrides.length > 4096) throw new Error('Invalid classification overrides');
  const overrideScopes = new Set<string>();
  for (const row of overrides) {
    if (row.default !== false || row.verified !== false || row.verification !== 'unverified') throw new Error('Classification overrides only remove trust');
    const scope = tokenScope(row.chainId, row.address);
    if (overrideScopes.has(scope)) throw new Error('Duplicate classification override');
    overrideScopes.add(scope);
    classifications.set(scope, { kind: 'classification', scope, payload: { chainId: row.chainId, address: row.address.toLowerCase(), default: false, verified: false, verification: 'unverified' } });
  }
  return [...tokens].map(([scope, payload]): Candidate => ({ kind: 'token', scope, payload })).concat([...assetsOnly.values()], [...classifications.values()]);
}

export async function importDescriptors(directory: string): Promise<Candidate[]> {
  const records: Candidate[] = [];
  const scopes = new Map<string, string>();
  for (const owner of await fs.readdir(path.join(directory, 'registry'), { withFileTypes: true })) {
    if (!owner.isDirectory() || owner.isSymbolicLink()) continue;
    for (const file of await fs.readdir(path.join(directory, 'registry', owner.name), { withFileTypes: true })) {
      if (!file.isFile() || file.isSymbolicLink() || !/^calldata-.*\.json$/.test(file.name)) continue;
      const payload = await resolveDescriptorIncludes(directory, path.join(directory, 'registry', owner.name, file.name)) as {
        context?: { contract?: { deployments?: { chainId: number; address: string }[] } };
        display?: { formats?: Record<string, unknown> };
      };
      const deployments = payload.context?.contract?.deployments;
      const formats = payload.display?.formats;
      // Shared definitions are already resolved from this exact source snapshot.
      if (!Array.isArray(deployments) || !formats) continue;
      const digest = metadataDigest(payload);
      for (const deployment of deployments) {
        for (const signature of Object.keys(formats)) {
          let selector: string;
          try { selector = ethers.FunctionFragment.from(signature).selector; } catch { continue; }
          const scope = descriptorScope(deployment.chainId, deployment.address, selector);
          const prior = scopes.get(scope);
          if (prior && prior !== digest) throw new Error(`Conflicting descriptor coverage: ${scope}`);
          if (!prior) records.push({ kind: 'descriptor', scope, payload });
          scopes.set(scope, digest);
        }
      }
    }
  }
  return records;
}

export function preparedDigest(prepared: PreparedPublication): string {
  // Catalogs can be large; bind a deterministic list of individually bounded records.
  return ethers.sha256(ethers.toUtf8Bytes(JSON.stringify({
    schema: prepared.schema, sequence: prepared.sequence, issuedAt: prepared.issuedAt, expiresAt: prepared.expiresAt,
    sources: prepared.sources, records: prepared.records.map(row => ({ kind: row.kind, scope: row.scope, digest: metadataDigest(row.payload) })),
  })));
}

export function signPublication(prepared: PreparedPublication, approvedDigest: string, trust: SignedTrust, roots: RootKey[], signingKeys: Record<string, string>, kinds?: readonly MetadataKind[]): { schema: 1; trust: SignedTrust; records: SignedRecord[] } {
  if (prepared.schema !== 1 || preparedDigest(prepared) !== approvedDigest) throw new Error('Prepared snapshot differs from approved digest');
  const verifier = new MetadataVerifier(roots);
  verifier.acceptTrust(trust);
  if (encodeMetadataHeader(trust).length > MAX_HEADER_BYTES - 1024) throw new Error('Trust policy exceeds response-header budget; rotate keys or compact obsolete revocations');
  const seen = new Set<string>();
  const records = prepared.records.filter(row => !kinds || kinds.includes(row.kind)).map(row => {
    const id = `${row.kind}:${row.scope}`;
    if (seen.has(id)) throw new Error('Duplicate prepared scope');
    seen.add(id);
    const key = trust.payload.keys.find(candidate => candidate.kinds.includes(row.kind) && signingKeys[candidate.id]);
    if (!key) throw new Error(`Missing scoped publication key for ${row.kind}`);
    let signer: ethers.SigningKey;
    try { signer = new ethers.SigningKey(signingKeys[key.id]!); }
    catch { throw new Error('Invalid configured publication key'); }
    if (signer.compressedPublicKey !== ethers.SigningKey.computePublicKey(key.publicKey, true)) throw new Error('Wrong publication key');
    const statement = { schema: 1 as const, kind: row.kind, scope: row.scope, keyId: key.id,
      sequence: prepared.sequence, issuedAt: prepared.issuedAt, expiresAt: prepared.expiresAt, digest: metadataDigest(row.payload) };
    const signature = signer.sign(signatureDigest('record', statement)).compactSerialized;
    return verifier.verify(row.payload, { statement, signature }, row.kind, row.scope);
  });
  return { schema: 1, trust, records };
}

export function signTrust(payload: SignedTrust['payload'], rootId: string, privateKey: string): SignedTrust {
  canonicalMetadata(payload);
  return { rootId, payload, signature: new ethers.SigningKey(privateKey).sign(signatureDigest('trust', payload)).compactSerialized };
}

export function compactPublication(publication: { schema: 1; trust: SignedTrust; records: SignedRecord[] }) {
  const documents: Record<string, unknown> = Object.create(null);
  const records = publication.records.map(record => {
    if (record.statement.kind !== 'descriptor') return record;
    documents[record.statement.digest] = record.payload;
    return { statement: record.statement, signature: record.signature, payloadRef: record.statement.digest };
  });
  return { schema: 1 as const, trust: publication.trust, documents, records };
}
