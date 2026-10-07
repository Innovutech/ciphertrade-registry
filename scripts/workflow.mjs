import fs from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { ethers } from 'ethers';
import { latestPublication } from './latest-publication.mjs';

const mode = process.argv[2];
const json = async file => JSON.parse(await fs.readFile(file, 'utf8'));
await fs.mkdir('work', { recursive: true });
if (mode === 'prepare') {
  if (process.env.GITHUB_RUN_ATTEMPT && process.env.GITHUB_RUN_ATTEMPT !== '1') throw new Error('Start a new change-review run instead of re-importing sources into an existing approval');
  const revisions = Object.fromEntries([
    ['curated', '.'], ['trustWallet', 'sources/trustwallet'], ['registry', 'sources/registry'],
  ].map(([name, dir]) => [name, execFileSync('git', ['-C', dir, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim()]));
  if (Object.values(revisions).some(value => !/^[a-f0-9]{40}$/.test(value))) throw new Error('Invalid source revision');
  const issuedAt = Date.now();
  const networks = await json('catalog/public-chains.json');
  await fs.writeFile('work/config.json', JSON.stringify({
    curatedDirectory: 'catalog', trustWalletDirectory: 'sources/trustwallet', registryDirectory: 'sources/registry',
    revisions, chains: networks, networks, domains: await json('catalog/domains.json'),
    sequence: Number(process.env.GITHUB_RUN_NUMBER), issuedAt, expiresAt: issuedAt + 7 * 86400000,
  }));
} else if (mode === 'digest') {
  const { preparedDigest } = await import('../src/publisher.ts');
  const prepared = await json('work/prepared.json');
  const { publicationReport } = await import('../src/publicationReport.ts');
  const previous = await latestPublication((await json('trust/roots.json')).keys);
  prepared.baseDigest = previous?.contentDigest ?? null;
  await fs.writeFile('work/prepared.json', JSON.stringify(prepared));
  const digest = preparedDigest(prepared);
  const report = publicationReport(prepared, previous ?? undefined);
  const changed = !previous || report.added.length + report.changed.length + report.removed.length > 0;
  await fs.writeFile('work/review.json', JSON.stringify(report, null, 2));
  await fs.appendFile(process.env.GITHUB_OUTPUT, `digest=${digest}\nchanged=${changed}\n`);
  await fs.appendFile(process.env.GITHUB_STEP_SUMMARY,
    `## Metadata publication\n\nApproved snapshot digest: \`${digest}\`\n\nRecords: ${prepared.records.length}. Added: ${report.added.length}; changed: ${report.changed.length}; removed: ${report.removed.length}.\n\nReview prepared-metadata/review.json and the complete prepared snapshot before approval.\n\nSources:\n${prepared.sources.map(source => `- ${source.name}: \`${source.revision}\``).join('\n')}\n`);
} else if (mode === 'finalize') {
  const { finalizePublication } = await import('../src/publicationLifecycle.ts');
  const { preparedDigest } = await import('../src/publisher.ts');
  const roots = (await json('trust/roots.json')).keys;
  const previous = await latestPublication(roots);
  const publicationMode = process.env.PUBLICATION_MODE;
  if (!['changes', 'renewal'].includes(publicationMode)) throw new Error('Invalid publication mode');
  const prepared = finalizePublication({ mode: publicationMode, previous, roots, trust: await json('trust/policy.json'),
    ...(publicationMode === 'changes' ? { reviewed: await json('work/prepared.json'), approvedDigest: process.env.APPROVED_DIGEST } : {}) });
  await fs.writeFile('work/prepared.json', JSON.stringify(prepared));
  const digest = preparedDigest(prepared);
  await fs.appendFile(process.env.GITHUB_OUTPUT, `digest=${digest}\nsequence=${prepared.sequence}\n`);
  await fs.appendFile(process.env.GITHUB_STEP_SUMMARY, `## ${publicationMode === 'renewal' ? 'Approved catalog renewal' : 'Approved changes'}\n\nSnapshot: \`${digest}\`\n\nRecords: ${prepared.records.length}. Publication version: ${prepared.sequence}.\n`);
} else if (mode === 'sign-config') {
  const roles = { tokens: ['token', 'asset'], descriptors: ['descriptor'], configuration: ['networks', 'domains', 'classification'] };
  const kinds = roles[process.env.METADATA_ROLE];
  if (!kinds || !/^0x[0-9a-f]{64}$/.test(process.env.APPROVED_DIGEST ?? '')) throw new Error('Invalid approved role or digest');
  await fs.writeFile('work/sign.json', JSON.stringify({ prepared: 'work/prepared.json', approvedDigest: process.env.APPROVED_DIGEST,
    trustFile: 'trust/policy.json', rootsFile: 'trust/roots.json', kinds }));
} else if (mode === 'assemble') {
  const { MetadataVerifier, metadataDigest, validateConfigurationPublication } = await import('../src/protocol.ts');
  const { preparedDigest } = await import('../src/publisher.ts');
  const prepared = await json('work/prepared.json');
  if (preparedDigest(prepared) !== process.env.APPROVED_DIGEST) throw new Error('Prepared artifact changed');
  const roots = await json('trust/roots.json');
  const latest = await latestPublication(roots.keys);
  if ((latest?.contentDigest ?? null) !== prepared.baseDigest || (latest && latest.sequence >= prepared.sequence)) throw new Error('Publication base changed while signing; start a new run');
  const verifier = new MetadataVerifier(roots.keys);
  const parts = await Promise.all(['tokens', 'descriptors', 'configuration'].map(role => json(`work/${role}.json`)));
  const trust = verifier.acceptTrust(parts[0].trust);
  const records = new Map();
  for (const part of parts) {
    if (metadataDigest(part.trust) !== metadataDigest(trust)) throw new Error('Signing roles used different trust policies');
    for (const record of part.records) {
      if (record.statement.sequence !== prepared.sequence || record.statement.issuedAt !== prepared.issuedAt || record.statement.expiresAt !== prepared.expiresAt) throw new Error('Signing role used a different publication version or validity period');
      verifier.verify(record.payload, { statement: record.statement, signature: record.signature }, record.statement.kind, record.statement.scope);
      const id = `${record.statement.kind}:${record.statement.scope}`;
      if (records.has(id)) throw new Error('Duplicate signed scope');
      records.set(id, record);
    }
  }
  if (records.size !== prepared.records.length) throw new Error('Incomplete role publication');
  for (const row of prepared.records) {
    if (records.get(`${row.kind}:${row.scope}`)?.statement.digest !== metadataDigest(row.payload)) throw new Error('Signed artifact differs from reviewed source');
  }
  validateConfigurationPublication([...records.values()].map(record => ({ kind: record.statement.kind, scope: record.statement.scope, payload: record.payload })));
  const { assertConfigurationHeaderBudget } = await import('../src/publisher.ts');
  assertConfigurationHeaderBudget([...records.values()], trust);
  await fs.mkdir('dist', { recursive: true });
  const { compactPublication } = await import('../src/publisher.ts');
  const bytes = JSON.stringify(compactPublication({ schema: 1, trust, records: [...records.values()] }));
  if (Buffer.byteLength(bytes) > 64 * 1024 * 1024) throw new Error('Publication exceeds API artifact budget');
  await fs.writeFile('dist/publication.json', bytes);
  await fs.writeFile('dist/publication.sha256', ethers.sha256(ethers.toUtf8Bytes(bytes)) + '\n');
} else if (mode === 'check-setup') {
  const roots = await json('trust/roots.json');
  const { MetadataVerifier } = await import('../src/protocol.ts');
  if (!roots.keys?.length) throw new Error('Production trust roots must be provisioned before publication');
  const trust = new MetadataVerifier(roots.keys).acceptTrust(await json('trust/policy.json'));
  const { assertPublishingRoles, assertReviewerEnvironment, assertSigningEnvironment } = await import('../src/publishingPolicy.ts');
  assertPublishingRoles(trust.payload);
  const reviewers = await json('trust/reviewers.json');
  if (!Array.isArray(reviewers.userIds) || !reviewers.userIds.length || reviewers.userIds.some(id => !Number.isSafeInteger(id) || id <= 0)) throw new Error('Configure stable GitHub reviewer account IDs');
  if (process.env.GITHUB_ACTIONS === 'true') {
    const repository = process.env.GITHUB_REPOSITORY;
    if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository ?? '')) throw new Error('Invalid publisher repository');
    for (const role of ['review', 'tokens', 'descriptors', 'configuration']) {
      const response = await fetch(`https://api.github.com/repos/${repository}/environments/metadata-${role}`, {
        headers: { Accept: 'application/vnd.github+json', Authorization: `Bearer ${process.env.GH_TOKEN}`, 'X-GitHub-Api-Version': '2022-11-28' },
        signal: AbortSignal.timeout(15000), redirect: 'error',
      });
      if (!response.ok) throw new Error(`Cannot verify metadata-${role} approval protection`);
      const environment = await response.json();
      if (role === 'review') assertReviewerEnvironment(environment, reviewers.userIds);
      else assertSigningEnvironment(environment);
    }
  }
} else throw new Error('Unknown workflow command');
