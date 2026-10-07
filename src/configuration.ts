import fs from 'node:fs/promises';
import path from 'node:path';
import {
  canonicalMetadata, networkConfigScope, validateTokenCatalogPayload, validateConfigurationPublication,
  validatePublicNetworkPayload, validateDomainPayload, type TokenCatalogPayload, type CuratedToken,
} from './protocol.ts';
import type { Candidate } from './publisher.ts';

export async function readCatalogJson(directory: string, name: string, absent: unknown): Promise<unknown> {
  const filename = path.join(directory, name);
  try {
    const stat = await fs.lstat(filename);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 512 * 1024) throw new Error(`Unsupported configuration source: ${name}`);
    return JSON.parse(await fs.readFile(filename, 'utf8')) as unknown;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return absent;
    throw error;
  }
}

export async function readCuratedTokenCatalog(directory: string, chainId: number): Promise<TokenCatalogPayload> {
  networkConfigScope('tokens', chainId);
  const payload = {
    chainId,
    defaults: await readCatalogJson(directory, `default_tokens.${chainId}.json`, []),
    verified: await readCatalogJson(directory, `verified_tokens.${chainId}.json`, []),
    tokens: await readCatalogJson(directory, `tokens.${chainId}.json`, []),
  };
  validateTokenCatalogPayload(payload, chainId);
  canonicalMetadata(payload);
  return payload;
}

export type ClassificationRemoval = { chainId: number; address: string; default: false; verified: false; verification: 'unverified' };
export async function readClassificationRemovals(directory: string, chainIds: readonly number[]): Promise<ClassificationRemoval[]> {
  const input = await readCatalogJson(directory, 'classification-overrides.json', []);
  if (!Array.isArray(input) || input.length > 4096) throw new Error('Invalid classification overrides');
  const seen = new Set<string>();
  const rows: ClassificationRemoval[] = [];
  const fields = ['address', 'chainId', 'default', 'verification', 'verified'];
  for (const row of input) {
    if (!row || typeof row !== 'object' || Array.isArray(row)
      || Object.keys(row).length !== fields.length || fields.some(field => !Object.hasOwn(row, field))
      || row.default !== false || row.verified !== false || row.verification !== 'unverified' || !chainIds.includes(row.chainId)) throw new Error('Classification overrides only remove trust on supported chains');
    validateTokenCatalogPayload({ chainId: row.chainId, defaults: [], verified: [], tokens: [{ tokenAddress: row.address }] }, row.chainId);
    const scope = `${row.chainId}:${row.address.toLowerCase()}`;
    if (seen.has(scope)) throw new Error('Duplicate classification override');
    seen.add(scope);
    rows.push({ ...row, address: row.address.toLowerCase() });
  }
  return rows;
}

export function applyClassificationRemovals(payload: TokenCatalogPayload, removals: readonly ClassificationRemoval[]): TokenCatalogPayload {
  const addresses = new Set(removals.filter(row => row.chainId === payload.chainId).map(row => row.address));
  const retain = (row: CuratedToken) => !addresses.has(row.tokenAddress.toLowerCase());
  return { ...payload, defaults: payload.defaults.filter(retain), verified: payload.verified.filter(retain) };
}

export async function importConfigurationSources(options: { curatedDirectory: string; networks: unknown; domains: unknown }): Promise<Candidate[]> {
  validatePublicNetworkPayload(options.networks);
  validateDomainPayload(options.domains);
  const chainIds = Object.keys(options.networks).map(Number).sort((a, b) => a - b);
  const removals = await readClassificationRemovals(options.curatedDirectory, chainIds);
  const records: Candidate[] = [
    { kind: 'networks', scope: 'chains', payload: options.networks },
    { kind: 'domains', scope: 'domains', payload: options.domains },
    { kind: 'networks', scope: 'coti-bridge-routes', payload: await readCatalogJson(options.curatedDirectory, 'coti_bridge.routes.json', { version: 1, routes: [] }) },
  ];
  for (const chainId of chainIds) {
    records.push(
      { kind: 'networks', scope: networkConfigScope('tokens', chainId), payload: applyClassificationRemovals(await readCuratedTokenCatalog(options.curatedDirectory, chainId), removals) },
      { kind: 'networks', scope: networkConfigScope('privacy-bridges', chainId), payload: { chainId, bridges: await readCatalogJson(options.curatedDirectory, `privacy_bridges.${chainId}.json`, []) } },
      { kind: 'networks', scope: networkConfigScope('token-families', chainId), payload: await readCatalogJson(options.curatedDirectory, `token_families.${chainId}.json`, { version: 1, chainId, families: [] }) },
      { kind: 'networks', scope: networkConfigScope('trusted-nfts', chainId), payload: { chainId, nfts: await readCatalogJson(options.curatedDirectory, `trusted_nfts.${chainId}.json`, []) } },
    );
  }
  validateConfigurationPublication(records);
  for (const row of records) canonicalMetadata(row.payload);
  return records;
}
