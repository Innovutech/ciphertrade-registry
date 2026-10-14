import fs from 'node:fs/promises';
import path from 'node:path';
import { dappScope, normalizeDappHost, object, validateDappPayload, type DappPublication } from './protocol.ts';
import type { Candidate, ImportOptions } from './publisher.ts';

const MAX_APPS = 10000;
type CuratedEntry = Partial<Omit<DappPublication, 'source' | 'revision'>> & { host: string };

async function readCatalog(directory: string): Promise<CuratedEntry[]> {
  const file = path.join(directory, 'dapps.json');
  let stat;
  try { stat = await fs.lstat(file); }
  catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return []; throw error; }
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 512 * 1024) throw new Error('Invalid dApp catalog file');
  const catalog = object(JSON.parse(await fs.readFile(file, 'utf8')));
  if (catalog.schema !== 1 || Object.keys(catalog).length !== 2 || !Array.isArray(catalog.entries) || catalog.entries.length > MAX_APPS) throw new Error('Invalid dApp catalog');
  return catalog.entries.map(input => {
    const row = object(input);
    const allowed = ['host', 'name', 'description', 'canonicalUrl', 'domainAliases', 'searchAliases', 'logoUrl', 'enabled', 'verified'];
    if (typeof row.host !== 'string' || Object.keys(row).some(key => !allowed.includes(key))) throw new Error('Invalid curated dApp entry');
    return row as CuratedEntry;
  });
}

export async function importDappSources(options: Pick<ImportOptions, 'curatedDirectory' | 'trustWalletDirectory' | 'revisions'>): Promise<{ records: Candidate[]; skipped: string[] }> {
  if (!/^[a-f0-9]{40}$/.test(options.revisions.curated)) throw new Error('dApp catalog requires an exact revision');
  const apps = new Map<string, DappPublication>();
  const skipped: string[] = [];
  if (options.trustWalletDirectory) {
    const revision = options.revisions.trustWallet;
    if (!revision || !/^[a-f0-9]{40}$/.test(revision)) throw new Error('Trust Wallet source must be an exact revision');
    const directory = path.join(options.trustWalletDirectory, 'dapps');
    const directoryStat = await fs.lstat(directory);
    if (!directoryStat.isDirectory() || directoryStat.isSymbolicLink()) throw new Error('Invalid dApp discovery directory');
    const files = await fs.readdir(directory, { withFileTypes: true });
    if (files.length > MAX_APPS) throw new Error('dApp discovery limit exceeded');
    for (const file of files.sort((a, b) => a.name.localeCompare(b.name, 'en'))) {
      if (!file.isFile() || file.isSymbolicLink() || !file.name.endsWith('.png')) continue;
      let host: string;
      try {
        host = normalizeDappHost(file.name.slice(0, -4));
        const filename = path.join(directory, file.name);
        const stat = await fs.lstat(filename);
        if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 256 * 1024) throw new Error('Invalid logo file');
        const bytes = await fs.readFile(filename);
        if (bytes.length < 24 || bytes.subarray(0, 8).toString('hex') !== '89504e470d0a1a0a' || bytes.subarray(12, 16).toString() !== 'IHDR'
          || bytes.readUInt32BE(16) < 1 || bytes.readUInt32BE(16) > 1024 || bytes.readUInt32BE(20) < 1 || bytes.readUInt32BE(20) > 1024) throw new Error('Invalid logo dimensions');
      } catch { skipped.push(file.name); continue; }
      if (apps.has(host)) throw new Error(`Ambiguous discovered dApp identity: ${host}`);
      const payload: DappPublication = { host, name: host, description: null, canonicalUrl: `https://${host}/`, domainAliases: [], searchAliases: [],
        logoUrl: `https://raw.githubusercontent.com/trustwallet/assets/${revision}/dapps/${encodeURIComponent(file.name)}`,
        enabled: true, verified: false, source: 'trustwallet', revision };
      try { validateDappPayload(dappScope(host), payload); }
      catch { skipped.push(file.name); continue; }
      apps.set(host, payload);
    }
  }
  const claimed = new Set<string>();
  for (const entry of await readCatalog(options.curatedDirectory)) {
    const host = normalizeDappHost(entry.host);
    if (entry.domainAliases !== undefined && !Array.isArray(entry.domainAliases)) throw new Error('Invalid dApp aliases');
    const aliases = (entry.domainAliases ?? []).map(normalizeDappHost);
    for (const identity of [host, ...aliases]) {
      if (claimed.has(identity)) throw new Error(`Conflicting curated dApp identity: ${identity}`);
      claimed.add(identity);
    }
    const discovered = apps.get(host) ?? aliases.map(alias => apps.get(alias)).find(Boolean);
    const payload: DappPublication = { host, name: entry.name === undefined ? host : entry.name, description: entry.description ?? null,
      canonicalUrl: entry.canonicalUrl === undefined ? `https://${host}/` : entry.canonicalUrl, domainAliases: aliases, searchAliases: entry.searchAliases === undefined ? [] : entry.searchAliases,
      logoUrl: entry.logoUrl === undefined ? discovered?.logoUrl ?? null : entry.logoUrl,
      enabled: entry.enabled === undefined ? true : entry.enabled, verified: entry.verified === undefined ? false : entry.verified, source: 'ciphertrade', revision: options.revisions.curated };
    validateDappPayload(dappScope(host), payload);
    for (const alias of aliases) apps.delete(alias);
    apps.set(host, payload);
  }
  if (apps.size > MAX_APPS) throw new Error('dApp catalog limit exceeded');
  const records: Candidate[] = [...apps.values()].sort((a, b) => a.host.localeCompare(b.host, 'en')).map(payload => {
    const scope = dappScope(payload.host);
    validateDappPayload(scope, payload);
    return { kind: 'domains', scope, payload };
  });
  return { records, skipped };
}
