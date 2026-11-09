import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import { ethers } from 'ethers';
import { decodeMetadataHeader, encodeMetadataHeader, metadataDigest, signatureDigest, METADATA_HEADER, TRUST_HEADER, MAX_HEADER_BYTES, type TrustPayload } from './protocol.ts';
import { assertConfigurationHeaderBudget, signTrust } from './publisher.ts';
import { emptyConfigurationFixture } from './configurationFixtures.ts';
import { checkDelivery, inspectConfiguration, latestRelease, notifyDelivery, PRODUCTION_CONFIGURATION_URL } from '../scripts/delivery-monitor.mjs';

const DAY = 86400000, now = Date.now();
const root = new ethers.SigningKey('0x' + '11'.repeat(32)), key = new ethers.SigningKey('0x' + '22'.repeat(32));
const roots = [{ id: 'root', publicKey: root.compressedPublicKey }];
const sequence = now - DAY;
function fixture() {
  const policy: TrustPayload = { schema: 2, sequence: 1, issuedAt: now - 60 * DAY, expiresAt: null,
    keys: [{ id: 'configuration', publicKey: key.compressedPublicKey, kinds: ['networks', 'domains'], notBefore: now - 60 * DAY, expiresAt: null }],
    revokedDigests: [], minimumSequences: { token: 1, asset: 1, descriptor: 1, networks: 1, domains: 1, classification: 1 } };
  const trust = (p = policy) => signTrust(p, 'root', root.privateKey);
  const sign = (scope: 'chains' | 'domains', expiresAt = now + (scope === 'domains' ? 6 : 29) * DAY, version = sequence, payload?: unknown) => {
    const row = emptyConfigurationFixture().find(row => row.scope === scope)!;
    const body = payload ?? row.payload;
    const statement = { schema: 1 as const, kind: row.kind, scope, keyId: 'configuration', sequence: version,
      issuedAt: now - DAY, expiresAt, digest: metadataDigest(body) };
    return { payload: body, statement, signature: key.sign(signatureDigest('record', statement)).compactSerialized };
  };
  const chains = sign('chains'), domains = sign('domains');
  const headers = (rows: unknown[] = [{ statement: chains.statement, signature: chains.signature }, domains]) => new Headers({
    [TRUST_HEADER]: encodeMetadataHeader(trust()), [METADATA_HEADER]: encodeMetadataHeader(rows),
  });
  const release = { tag_name: `metadata-${sequence}`, draft: false, prerelease: false, published_at: new Date(now - 3 * 3600000).toISOString(),
    assets: ['publication.json', 'publication.sha256'].map(name => ({ name, state: 'uploaded' })) };
  const options = { api: async () => [release], roots, policy: trust(), now,
    request: async () => new Response(JSON.stringify(chains.payload), { headers: headers() }) };
  return { policy, trust, sign, chains, domains, headers, release, options };
}

test('monitor authenticates mixed-expiry chains and the domain catalogue from the actual public endpoint', async () => {
  const f = fixture();
  const result = await checkDelivery({ ...f.options, request: async (url: string, options: RequestInit) => {
    assert.equal(url, PRODUCTION_CONFIGURATION_URL);
    assert.equal(new URL(url).pathname, '/chains');
    assert.equal(new URL(url).searchParams.get('configuration'), 'static');
    assert.equal(options.redirect, 'error');
    assert.equal(new Headers(options.headers).has('Authorization'), false);
    return f.options.request();
  } });
  assert.deepEqual(result.problems, []);
  assert.deepEqual(result.records, [{ scope: 'chains', sequence, expiresAt: now + 29 * DAY }, { scope: 'domains', sequence, expiresAt: now + 6 * DAY }]);
});

test('static chains header contract carries the current domain catalog and fails closed if the API budget omits it', async () => {
  const f = fixture();
  const catalog = JSON.parse(await fs.readFile(new URL('../catalog/domains.json', import.meta.url), 'utf8'));
  const domain = f.sign('domains', now + 6 * DAY, sequence, catalog);
  const chainEvidence = { statement: f.chains.statement, signature: f.chains.signature };
  // Match the API store's header packing: body evidence first, additional full domain record second.
  const pack = (extra: ReturnType<typeof f.sign>) => {
    const trustHeader = encodeMetadataHeader(f.trust()), selected: unknown[] = [];
    for (const row of [chainEvidence, extra]) {
      if (trustHeader.length + encodeMetadataHeader([...selected, row]).length <= MAX_HEADER_BYTES) selected.push(row);
    }
    return f.headers(selected);
  };
  assertConfigurationHeaderBudget([f.chains, domain], f.trust());
  const headers = pack(domain);
  const decoded = decodeMetadataHeader(headers.get(METADATA_HEADER)!) as any[];
  assert.equal(Object.hasOwn(decoded[0], 'payload'), false);
  assert.deepEqual(decoded[1].payload, catalog);
  assert.deepEqual(inspectConfiguration(f.chains.payload, headers, roots, f.trust(), now).problems, []);
  const oversized = f.sign('domains', now + 6 * DAY, sequence,
    { patterns: Array.from({ length: 128 }, (_, i) => `host-${i}.${'x'.repeat(63)}.example.com`) });
  assert.throws(() => assertConfigurationHeaderBudget([f.chains, oversized], f.trust()), /response-header budget/);
  const dropped = pack(oversized);
  assert.equal((decodeMetadataHeader(dropped.get(METADATA_HEADER)!) as unknown[]).length, 1);
  const result = inspectConfiguration(f.chains.payload, dropped, roots, f.trust(), now);
  assert.deepEqual(result.records.map((row: any) => row.scope), ['chains']);
  assert.deepEqual(result.problems.map((row: any) => row.code), ['domains-invalid']);
});

test('domain expiry/missing evidence does not hide independently valid chains', () => {
  const f = fixture();
  for (const expiresAt of [now + 2 * DAY, now, now - 1]) {
    const result = inspectConfiguration(f.chains.payload, f.headers([f.chains, f.sign('domains', expiresAt)]), roots, f.trust(), now);
    assert.ok(result.records.some((row: any) => row.scope === 'chains'));
    assert.deepEqual(result.problems.map((row: any) => row.code), [expiresAt > now ? 'domains-expiry' : 'domains-invalid']);
  }
  for (const rows of [[f.chains], [f.chains, f.domains, f.domains]]) {
    assert.deepEqual(inspectConfiguration(f.chains.payload, f.headers(rows), roots, f.trust(), now).problems.map((row: any) => row.code), ['domains-invalid']);
  }
});

test('monitor rejects forged, tampered and revoked proofs and respects current trust expiry', () => {
  const f = fixture();
  const tampered = inspectConfiguration({}, f.headers(), roots, f.trust(), now);
  assert.deepEqual(tampered.problems.map((row: any) => row.code), ['chains-invalid']);
  assert.ok(tampered.records.some((row: any) => row.scope === 'domains'));
  const forged = { ...f.domains, signature: root.sign(signatureDigest('record', f.domains.statement)).compactSerialized };
  assert.equal(inspectConfiguration(f.chains.payload, f.headers([f.chains, forged]), roots, f.trust(), now).problems[0].code, 'domains-invalid');
  const revoked = f.trust({ ...f.policy, sequence: 2, revokedDigests: [f.domains.statement.digest] });
  assert.equal(inspectConfiguration(f.chains.payload, f.headers(), roots, revoked, now).problems[0].code, 'domains-invalid');
  const finite = f.trust({ ...f.policy, sequence: 2, expiresAt: now + DAY });
  const capped = inspectConfiguration(f.chains.payload, f.headers(), roots, finite, now);
  assert.deepEqual(capped.problems.map((row: any) => row.code), ['chains-expiry', 'domains-expiry']);
  assert.ok(capped.records.every((row: any) => row.expiresAt === now + DAY));
  const expiredKey = f.trust({ ...f.policy, sequence: 2, keys: f.policy.keys.map(key => ({ ...key, expiresAt: now })) });
  assert.deepEqual(inspectConfiguration(f.chains.payload, f.headers(), roots, expiredKey, now).problems.map((row: any) => row.code), ['chains-invalid', 'domains-invalid']);
  assert.equal(inspectConfiguration(f.chains.payload, new Headers(), roots, f.trust(), now).problems[0].code, 'production-trust');
  assert.equal(inspectConfiguration(f.chains.payload, f.headers(), [], f.trust(), now).problems[0].code, 'production-trust');
});

test('published renewal success is distinct from failed delivery and stale or mixed serving versions', async () => {
  const f = fixture();
  for (const age of [3600000, 2 * 3600000]) {
    const report = await checkDelivery({ ...f.options, api: async () => [{ ...f.release, tag_name: `metadata-${sequence + 1}`, published_at: new Date(now - age).toISOString() }] });
    assert.deepEqual(report.problems.map((row: any) => row.code), age < 2 * 3600000 ? [] : ['chains-release-lag', 'domains-release-lag']);
  }
  const mixed = inspectConfiguration(f.chains.payload, f.headers([f.chains, f.sign('domains', now + 6 * DAY, sequence - 1)]), roots, f.trust(), now);
  assert.equal(mixed.problems[0].code, 'mixed-delivery');
  const failed = await checkDelivery({ ...f.options, request: async () => new Response('{}', { status: 503 }) });
  assert.ok(failed.release);
  assert.deepEqual(failed.problems.map((row: any) => row.code), ['production-http']);
  const stale = await checkDelivery({ ...f.options, api: async () => [{ ...f.release, published_at: new Date(now - 5 * DAY).toISOString() }] });
  assert.deepEqual(stale.problems.map((row: any) => row.code), ['renewal-overdue']);
  const ahead = await checkDelivery({ ...f.options, api: async () => [{ ...f.release, tag_name: `metadata-${sequence - 1}` }] });
  assert.deepEqual(ahead.problems.map((row: any) => row.code), ['chains-release-ahead', 'domains-release-ahead']);
});

test('network, malformed, oversized and release lookup failures all become actionable monitor results', async () => {
  const f = fixture();
  for (const request of [async () => { throw new Error('timeout'); }, async () => new Response('invalid json'),
    async () => new Response('x'.repeat(1024 * 1024 + 1))]) {
    const report = await checkDelivery({ ...f.options, request });
    assert.equal(report.problems[0].code, 'production-unreachable');
  }
  const report = await checkDelivery({ ...f.options, api: async () => { throw new Error('unavailable'); } });
  assert.equal(report.problems[0].code, 'release-unavailable');
  assert.equal(report.records.length, 2);
  assert.throws(() => latestRelease([{ ...f.release, assets: [] }]));
  assert.throws(() => latestRelease([{ ...f.release, published_at: 'invalid' }]));
  assert.throws(() => latestRelease([{ ...f.release, draft: true }]));
  assert.equal(latestRelease([{ ...f.release, tag_name: 'metadata-9' }, { ...f.release, tag_name: 'metadata-10' }]).sequence, 10);
});

const context = { repository: 'example/registry', runId: '101', runNumber: 5 };
const reviewers = ['reviewer'];
const failedReport = () => ({ checkedAt: now, release: { sequence, publishedAt: now - DAY }, records: [],
  problems: [{ code: 'production-http', message: 'Production configuration returned HTTP 503.' }] });
function notifications() {
  const issues: any[] = [], comments: { number: number; body: string }[] = [];
  const api = async (method: string, path: string, body?: any) => {
    if (method === 'GET' && path.includes('/comments?')) {
      const number = Number(path.split('/')[1]);
      return comments.filter(row => row.number === number).map(row => ({ body: row.body, user: { login: 'github-actions[bot]' } }));
    }
    if (method === 'GET') return structuredClone(issues);
    if (method === 'POST' && path === 'issues') {
      const issue = { number: issues.length + 1, html_url: 'https://github.com/example/registry/issues/1', user: { login: 'github-actions[bot]' }, state: 'open', ...body };
      issues.push(issue);
      return structuredClone(issue);
    }
    const number = Number(path.split('/')[1]);
    if (path.endsWith('/comments')) { comments.push({ number, body: body.body }); return {}; }
    const issue = issues.find(row => row.number === number);
    assert.ok(issue);
    Object.assign(issue, body);
    return structuredClone(issue);
  };
  return { issues, comments, api };
}

test('delivery notifications leave awaiting approval issues untouched and deduplicate retries', async () => {
  const f = notifications();
  f.issues.push({ number: 1, state: 'open', user: { login: 'github-actions[bot]' }, body: '<!-- metadata-publication-approval:v1 -->\nAwaiting approval' });
  const pending = structuredClone(f.issues[0]);
  await notifyDelivery(f.api, context, failedReport(), reviewers);
  await notifyDelivery(f.api, { ...context, runId: '102', runNumber: 6 }, failedReport(), reviewers);
  assert.equal(f.issues.length, 2);
  assert.deepEqual(f.issues[0], pending);
  assert.deepEqual(f.issues[1].assignees, reviewers);
  assert.equal(f.comments.length, 0);
  const before = structuredClone(f.issues);
  await notifyDelivery(f.api, context, { ...failedReport(), problems: [] }, reviewers);
  assert.deepEqual(f.issues, before);
});

test('monitor sends proactive mentions for changes and daily reminders, then closes only its own recovered issue', async () => {
  const f = notifications();
  await notifyDelivery(f.api, context, { ...failedReport(), problems: [] }, reviewers);
  assert.equal(f.issues.length, 0);
  await notifyDelivery(f.api, context, failedReport(), reviewers);
  assert.match(f.issues[0].body, /@reviewer/);
  const next = { ...context, runId: '102', runNumber: 6 };
  const reminder = { ...failedReport(), checkedAt: now + DAY };
  await notifyDelivery(f.api, next, reminder, reviewers);
  await notifyDelivery(f.api, next, reminder, reviewers);
  assert.equal(f.comments.length, 1);
  assert.match(f.comments[0]!.body, /@reviewer/);
  const changed = { ...reminder, problems: [{ code: 'domains-expiry', message: 'Signed domains expires within 48 hours.' }] };
  await notifyDelivery(f.api, next, changed, reviewers);
  assert.equal(f.comments.length, 2);
  await notifyDelivery(f.api, next, { ...reminder, problems: [] }, reviewers);
  await notifyDelivery(f.api, next, { ...reminder, problems: [] }, reviewers);
  assert.equal(f.issues[0].state, 'closed');
  assert.equal(f.comments.length, 3);
  await notifyDelivery(f.api, { ...next, runId: '103', runNumber: 7 }, reminder, reviewers);
  assert.equal(f.issues[0].state, 'open');
  assert.equal(f.comments.length, 4);
});

test('failed comment delivery retries notify, while user-created lookalikes cannot intercept alerts', async () => {
  const f = notifications();
  await notifyDelivery(f.api, context, failedReport(), reviewers);
  const next = { ...context, runId: '102', runNumber: 6 }, reminder = { ...failedReport(), checkedAt: now + DAY };
  const failing = async (method: string, path: string, body?: any) => {
    if (method === 'POST' && path.endsWith('/comments')) throw new Error('delivery failed');
    return f.api(method, path, body);
  };
  await assert.rejects(notifyDelivery(failing, next, reminder, reviewers), /delivery failed/);
  await notifyDelivery(f.api, next, reminder, reviewers);
  assert.equal(f.comments.length, 1);
  f.issues[0].user.login = 'outsider';
  const untouched = structuredClone(f.issues[0]);
  await notifyDelivery(f.api, next, reminder, reviewers);
  assert.equal(f.issues.length, 2);
  assert.deepEqual(f.issues[0], untouched);
});
