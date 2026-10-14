import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { importDappSources } from './dapps.ts';
import { dappScope, normalizeDappHost, validateDappPayload, validateConfigurationPublication, type DappPublication } from './protocol.ts';
import { emptyConfigurationFixture } from './configurationFixtures.ts';
import { publicationReport } from './publicationReport.ts';

const revision = 'a'.repeat(40);
const curatedRevision = 'b'.repeat(40);
const payload = (host = 'app.example.com'): DappPublication => ({ host, name: 'Example', description: null, canonicalUrl: `https://${host}/`,
  domainAliases: [], searchAliases: [], logoUrl: null, enabled: true, verified: true, source: 'ciphertrade', revision: curatedRevision });

async function fixture(run: (directory: string, write: (entries: unknown[]) => Promise<void>, logo: (name: string, bytes?: Buffer) => Promise<void>) => Promise<void>) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'cipher-dapps-'));
  const png = Buffer.from('89504e470d0a1a0a0000000d494844520000010000000100', 'hex');
  try {
    await fs.mkdir(path.join(directory, 'dapps'));
    await run(directory, async entries => { await fs.writeFile(path.join(directory, 'dapps.json'), JSON.stringify({ schema: 1, entries })); },
      async (name, bytes = png) => { await fs.writeFile(path.join(directory, 'dapps', name), bytes); });
  } finally {
    assert.equal(path.dirname(directory), os.tmpdir());
    assert.ok(path.basename(directory).startsWith('cipher-dapps-'));
    await fs.rm(directory, { recursive: true, force: true });
  }
}
const load = (directory: string) => importDappSources({ curatedDirectory: directory, trustWalletDirectory: directory,
  revisions: { curated: curatedRevision, trustWallet: revision } });

test('dApp identities normalize IDNA and case without merging subdomains or search aliases', () => {
  assert.equal(normalizeDappHost('APP.Example.COM.'), 'app.example.com');
  assert.equal(normalizeDappHost('b\u00fccher.example.com'), 'xn--bcher-kva.example.com');
  assert.notEqual(dappScope('app.example.com'), dappScope('example.com'));
  for (const host of ['localhost', '127.1', '127.0.0.1', '0x7f000001', '[::1]', 'app.internal', 'bad_host.com', 'app.example.com:443', 'app.example.com/path', 'a..com', 'x@evil.com', 'evil.com%2f', 'a\u202e.com']) assert.throws(() => normalizeDappHost(host), host);
});

test('discovery publishes pinned logos only with unverified hostname identity; malformed sources are skipped', async () => fixture(async (directory, _write, logo) => {
  await logo('APP.Example.com.png');
  await logo('bad host.example.com.png');
  await logo('invalid_example.png');
  await logo('broken.example.com.png', Buffer.from('<svg/>'));
  const result = await load(directory);
  assert.equal(result.records.length, 1);
  const row = result.records[0]!.payload as DappPublication;
  assert.equal(row.name, 'app.example.com'); assert.equal(row.verified, false); assert.equal(row.description, null);
  assert.equal(row.logoUrl, `https://raw.githubusercontent.com/trustwallet/assets/${revision}/dapps/APP.Example.com.png`);
  assert.equal(result.skipped.length, 3);
}));

test('curated data overrides discovery, merges explicit domain aliases and supports manual additions/exclusions', async () => fixture(async (directory, write, logo) => {
  await logo('app.example.com.png'); await logo('example.com.png'); await logo('disabled.example.com.png');
  await write([
    { host: 'app.example.com', name: 'Curated', description: 'Description', domainAliases: ['example.com'], searchAliases: ['terminal'], verified: true, logoUrl: 'https://assets.example.com/icon.svg' },
    { host: 'manual.example.com', name: 'Manual', verified: true },
    { host: 'disabled.example.com', enabled: false },
  ]);
  const rows = (await load(directory)).records.map(row => row.payload as DappPublication);
  assert.equal(rows.length, 3);
  assert.equal(rows[0]!.name, 'Curated'); assert.equal(rows[0]!.verified, true); assert.equal(rows[0]!.logoUrl, 'https://assets.example.com/icon.svg');
  assert.deepEqual(rows[0]!.domainAliases, ['example.com']); assert.deepEqual(rows[0]!.searchAliases, ['terminal']);
  assert.equal(rows.find(row => row.host === 'disabled.example.com')!.enabled, false);
  assert.equal(rows.find(row => row.host === 'manual.example.com')!.verified, true);
}));

test('discovery collisions and conflicting curated identities fail preparation', async () => fixture(async (directory, write, logo) => {
  await logo('APP.example.com..png'); await logo('app.example.com.png');
  await assert.rejects(load(directory), /Ambiguous/);
  await fs.unlink(path.join(directory, 'dapps', 'APP.example.com..png'));
  await write([{ host: 'app.example.com', domainAliases: ['example.com'] }, { host: 'example.com' }]);
  await assert.rejects(load(directory), /Conflicting/);
  await write([{ host: 'app.example.com', verified: 'true' }]);
  await assert.rejects(load(directory), /verification/);
}));

test('dApp payload validation binds the exact destination, role, scope and bounded presentation fields', () => {
  const row = payload();
  validateDappPayload(dappScope(row.host), row);
  for (const patch of [{ host: 'different.example.com' }, { canonicalUrl: 'https://other.example.com/' }, { canonicalUrl: 'http://app.example.com/' },
    { canonicalUrl: 'https://app.example.com:8443/' }, { canonicalUrl: 'https://user@www.example.com/' }, { name: 'x\u202e' },
    { description: 'x'.repeat(513) }, { source: 'trustwallet' }, { logoUrl: 'https://127.0.0.1/icon.svg' }, { unexpected: true }]) {
    assert.throws(() => validateDappPayload(dappScope(row.host), { ...row, ...patch }));
  }
  const discovered = { ...row, name: row.host, verified: false, source: 'trustwallet', revision, logoUrl: `https://raw.githubusercontent.com/trustwallet/assets/${revision}/dapps/${row.host}.png` };
  validateDappPayload(dappScope(row.host), discovered);
  assert.throws(() => validateDappPayload(dappScope(row.host), { ...discovered, logoUrl: discovered.logoUrl.replace(revision, 'master') }));
});

test('optional dApps do not change required chain configuration or trusted-domain patterns', () => {
  const config = emptyConfigurationFixture();
  const dapp = { kind: 'domains' as const, scope: dappScope(payload().host), payload: payload() };
  validateConfigurationPublication(config);
  validateConfigurationPublication([...config, dapp]);
  assert.deepEqual(config.find(row => row.scope === 'domains')!.payload, { patterns: [] });
  assert.throws(() => validateConfigurationPublication([...config, dapp, dapp]), /Duplicate/);
  assert.throws(() => validateConfigurationPublication([dapp]), /Incomplete/);
});

test('source revision alone does not cause catalog review churn, while URLs and verification always do', () => {
  const row = payload();
  const record = { kind: 'domains' as const, scope: dappScope(row.host), payload: { ...row, revision } };
  const prepared = { schema: 1 as const, sequence: 2, issuedAt: 1, expiresAt: 2, sources: [], records: [record] };
  const previous = { records: [{ payload: row, statement: { kind: 'domains' as const, scope: record.scope } } as never] };
  assert.deepEqual(publicationReport(prepared, previous).changed, []);
  record.payload = { ...record.payload, verified: false };
  assert.equal(publicationReport(prepared, previous).changed.length, 1);
});

test('the curated dApp catalog validates and retains its declared identity without production-value pins', async () => {
  const directory = fileURLToPath(new URL('../catalog/', import.meta.url));
  const catalog = JSON.parse(await fs.readFile(path.join(directory, 'dapps.json'), 'utf8'));
  const imported = await importDappSources({ curatedDirectory: directory, revisions: { curated: curatedRevision } });
  assert.equal(imported.records.length, catalog.entries.length);
  for (const entry of catalog.entries) {
    const row = imported.records.find(record => record.scope === dappScope(entry.host))!.payload as DappPublication;
    assert.equal(row.name, entry.name ?? normalizeDappHost(entry.host));
    assert.equal(row.verified, entry.verified ?? false);
    assert.deepEqual(row.searchAliases, entry.searchAliases ?? []);
    assert.equal(row.logoUrl, entry.logoUrl ?? null);
  }
});
