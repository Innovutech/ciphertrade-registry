import fs from 'node:fs/promises';
import path from 'node:path';
import { importTokenSources, importDescriptors, preparedDigest, signPublication, compactPublication, type ImportOptions, type PreparedPublication } from './publisher.ts';
import type { MetadataKind, RootKey, SignedTrust } from './protocol.ts';
import { importConfigurationSources } from './configuration.ts';
import { validatePublicNetworkPayload } from './protocol.ts';

const [command, configFile, output = 'work/prepared.json'] = process.argv.slice(2);
if (!configFile || !['prepare', 'sign'].includes(command ?? '')) throw new Error('Usage: node src/cli.ts prepare|sign <config.json> [output.json]');
const config = JSON.parse(await fs.readFile(configFile, 'utf8')) as ImportOptions & {
  sequence: number; issuedAt: number; expiresAt: number;
  prepared?: string; approvedDigest?: string; trustFile?: string; rootsFile?: string;
  kinds?: MetadataKind[];
};
await fs.mkdir(path.dirname(output), { recursive: true });
if (command === 'prepare') {
  if (!config.networks || !config.domains) throw new Error('Preparation requires complete public configuration');
  validatePublicNetworkPayload(config.networks);
  const records = await importTokenSources({ ...config, chains: config.networks });
  if (config.registryDirectory) records.push(...await importDescriptors(config.registryDirectory));
  records.push(...await importConfigurationSources({ curatedDirectory: config.curatedDirectory, networks: config.networks, domains: config.domains }));
  records.sort((a, b) => `${a.kind}:${a.scope}`.localeCompare(`${b.kind}:${b.scope}`, 'en'));
  const prepared: PreparedPublication = {
    schema: 1, sequence: config.sequence, issuedAt: config.issuedAt, expiresAt: config.expiresAt,
    sources: Object.entries(config.revisions).map(([name, revision]) => ({ name, revision })), records,
  };
  await fs.writeFile(output, JSON.stringify(prepared));
  console.log(JSON.stringify({ records: records.length, approvedDigest: preparedDigest(prepared) }));
} else {
  if (!config.prepared || !config.approvedDigest || !config.trustFile || !config.rootsFile) throw new Error('Signing requires prepared snapshot, approved digest, trust policy and roots');
  const prepared = JSON.parse(await fs.readFile(config.prepared, 'utf8')) as PreparedPublication;
  const trust = JSON.parse(await fs.readFile(config.trustFile, 'utf8')) as SignedTrust;
  const roots = JSON.parse(await fs.readFile(config.rootsFile, 'utf8')) as { keys: RootKey[] };
  // Secrets exist only in this isolated process; never read from an upstream source file.
  let keys: Record<string, string>;
  try { keys = JSON.parse(process.env.METADATA_SIGNING_KEYS ?? '{}') as Record<string, string>; }
  catch { throw new Error('Invalid signing secret configuration'); }
  const result = signPublication(prepared, config.approvedDigest, trust, roots.keys, keys, config.kinds);
  await fs.writeFile(output, JSON.stringify(config.kinds ? result : compactPublication(result)));
  console.log(JSON.stringify({ signedRecords: result.records.length }));
}
