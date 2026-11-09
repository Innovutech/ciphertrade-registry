import fs from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { MetadataVerifier, decodeMetadataHeader, METADATA_HEADER, TRUST_HEADER, MAX_HEADER_BYTES } from '../src/protocol.ts';
import { alertReviewer, githubNotificationContext } from './approval-notification.mjs';

export const PRODUCTION_CONFIGURATION_URL = 'https://api.ciphertrade.org/chains?configuration=static';
const DAY = 86400000, EXPIRY_WARNING = 2 * DAY, DELIVERY_GRACE = 2 * 3600000;
const marker = '<!-- metadata-delivery-monitor:v1 -->';
const statePattern = /<!-- metadata-delivery-state (\{[^\n]+\}) -->/;
const bot = 'github-actions[bot]';
const problem = (code, message) => ({ code, message });

export function inspectConfiguration(body, headers, roots, policy, now = Date.now()) {
  const records = [], problems = [];
  const verifier = new MetadataVerifier(roots);
  let evidence, servedTrust;
  try {
    const rawTrust = headers.get(TRUST_HEADER), rawEvidence = headers.get(METADATA_HEADER);
    if (!rawTrust || !rawEvidence || rawTrust.length + rawEvidence.length > MAX_HEADER_BYTES) throw new Error('Missing or oversized evidence');
    servedTrust = verifier.acceptTrust(decodeMetadataHeader(rawTrust), now);
    const current = new MetadataVerifier(roots).acceptTrust(policy, now);
    if (current.payload.sequence >= servedTrust.payload.sequence) verifier.acceptTrust(current, now);
    evidence = decodeMetadataHeader(rawEvidence);
    if (!Array.isArray(evidence) || evidence.length > 32) throw new Error('Invalid evidence list');
  } catch {
    return { records, problems: [problem('production-trust', 'Production metadata trust/evidence is missing, invalid, revoked or expired.')] };
  }
  for (const [kind, scope] of [['networks', 'chains'], ['domains', 'domains']]) {
    try {
      const matches = evidence.filter(row => row?.statement?.kind === kind && row.statement.scope === scope);
      if (matches.length !== 1) throw new Error('Missing or duplicate scope');
      const row = matches[0];
      const signed = verifier.verify(scope === 'chains' ? body : row.payload,
        { statement: row.statement, signature: row.signature }, kind, scope, now);
      const authority = verifier.currentTrust.payload;
      const key = authority.keys.find(key => key.id === signed.statement.keyId);
      const expiresAt = Math.min(signed.statement.expiresAt, authority.expiresAt ?? Infinity,
        servedTrust.payload.expiresAt ?? Infinity, key.expiresAt ?? Infinity);
      records.push({ scope, sequence: signed.statement.sequence, expiresAt });
      if (expiresAt - now <= EXPIRY_WARNING) problems.push(problem(`${scope}-expiry`, `Signed ${scope} expires within 48 hours.`));
    } catch {
      problems.push(problem(`${scope}-invalid`, `Signed ${scope} evidence is missing, invalid, revoked or expired.`));
    }
  }
  if (records.length === 2 && records[0].sequence !== records[1].sequence) problems.push(problem('mixed-delivery', 'Production chains and domains are from different releases.'));
  return { records, problems };
}

export function latestRelease(releases) {
  if (!Array.isArray(releases) || releases.length > 100) throw new Error('Invalid release listing');
  const release = releases.filter(row => !row.draft && !row.prerelease && /^metadata-[1-9][0-9]*$/.test(row.tag_name))
    .sort((a, b) => Number(b.tag_name.slice(9)) - Number(a.tag_name.slice(9)))[0];
  if (!release) throw new Error('No published metadata release');
  const sequence = Number(release.tag_name.slice(9)), publishedAt = Date.parse(release.published_at);
  if (!Number.isSafeInteger(sequence) || !Number.isFinite(publishedAt)
    || !['publication.json', 'publication.sha256'].every(name => release.assets?.some(asset => asset.name === name && asset.state === 'uploaded'))) {
    throw new Error('Incomplete metadata release');
  }
  return { sequence, publishedAt };
}

async function boundedJson(response) {
  const reader = response.body.getReader(), chunks = [];
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > 1024 * 1024) throw new Error('Configuration response exceeds 1 MiB');
      chunks.push(value);
    }
  } finally { await reader.cancel(); }
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

export async function checkDelivery({ api, roots, policy, request = fetch, now = Date.now() }) {
  const report = { checkedAt: now, release: null, records: [], problems: [] };
  try { report.release = latestRelease(await api('GET', 'releases?per_page=100')); }
  catch { report.problems.push(problem('release-unavailable', 'Latest published metadata release could not be read or is incomplete.')); }
  try {
    const response = await request(PRODUCTION_CONFIGURATION_URL, { redirect: 'error', signal: AbortSignal.timeout(30000), headers: { Accept: 'application/json' } });
    if (!response.ok) {
      await response.body?.cancel();
      report.problems.push(problem('production-http', `Production configuration returned HTTP ${response.status}.`));
    } else {
      const inspected = inspectConfiguration(await boundedJson(response), response.headers, roots, policy, now);
      report.records = inspected.records;
      report.problems.push(...inspected.problems);
    }
  } catch { report.problems.push(problem('production-unreachable', 'Production configuration could not be fetched or parsed within its limits.')); }
  const release = report.release;
  if (release) {
    if (release.publishedAt > now + 60000) report.problems.push(problem('release-time', 'Latest release has a future publication time.'));
    if (now - release.publishedAt >= 5 * DAY) report.problems.push(problem('renewal-overdue', 'No metadata release has been published for five days; check approved-catalog renewal.'));
    for (const row of report.records) {
      if (row.sequence < release.sequence && now - release.publishedAt >= DELIVERY_GRACE) {
        report.problems.push(problem(`${row.scope}-release-lag`, `Production ${row.scope} is behind the latest release beyond the two-hour delivery grace period.`));
      }
      if (row.sequence > release.sequence) report.problems.push(problem(`${row.scope}-release-ahead`, `Production ${row.scope} is newer than the latest listed release; verify release provenance.`));
    }
  }
  return report;
}

function stateOf(issue) {
  try { return JSON.parse(issue.body.match(statePattern)?.[1] ?? 'null'); } catch { return null; }
}

async function findIssue(api) {
  for (let page = 1; page <= 10; page++) {
    const issues = await api('GET', `issues?state=all&sort=updated&direction=desc&per_page=100&page=${page}`);
    const found = issues.find(issue => !issue.pull_request && issue.user?.login === bot && issue.body?.startsWith(marker) && stateOf(issue));
    if (found) return found;
    if (issues.length < 100) return null;
  }
  throw new Error('Delivery issue lookup exceeded its page limit');
}

export async function notifyDelivery(api, context, report, reviewers) {
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(context.repository) || !/^[1-9][0-9]*$/.test(context.runId)
    || !Number.isSafeInteger(context.runNumber) || context.runNumber < 1 || !Number.isSafeInteger(report.checkedAt)
    || !reviewers.length || reviewers.some(login => !/^[A-Za-z0-9-]+$/.test(login))) throw new Error('Invalid delivery notification context');
  const issue = await findIssue(api), old = issue && stateOf(issue);
  if (old?.runNumber > context.runNumber) return issue;
  const runUrl = `https://github.com/${context.repository}/actions/runs/${context.runId}`;
  const healthy = report.problems.length === 0;
  if (healthy && (!issue || issue.state === 'closed')) return issue;
  const fingerprint = createHash('sha256').update(JSON.stringify([report.problems.map(row => row.code).sort(), report.release?.sequence, report.records])).digest('hex');
  const incident = issue?.state === 'open' ? old.incident : context.runId;
  const revision = old?.fingerprint === fingerprint && issue?.state === 'open' ? old.revision : (old?.revision ?? 0) + 1;
  const notification = `${incident}:${revision}:${fingerprint}:${Math.floor(report.checkedAt / DAY)}`;
  const state = { runNumber: context.runNumber, runId: context.runId, incident, revision, fingerprint, notification, phase: healthy ? 'healthy' : 'alert' };
  const alertMarker = `<!-- metadata-delivery-alert ${notification} -->`;
  const lines = [marker, `<!-- metadata-delivery-state ${JSON.stringify(state)} -->`, '',
    `**Status:** ${healthy ? 'Delivery recovered' : 'Delivery or expiry needs attention'}`, '',
    `Checked: ${new Date(report.checkedAt).toISOString()}. [Monitor run](${runUrl}).`, '',
    `[Production signed configuration and domains](${PRODUCTION_CONFIGURATION_URL})`, ''];
  if (report.release) lines.push(`Latest release: [metadata-${report.release.sequence}](https://github.com/${context.repository}/releases/tag/metadata-${report.release.sequence}).`, '');
  for (const row of report.records) lines.push(`- ${row.scope}: signed version ${row.sequence}; effective expiry ${new Date(row.expiresAt).toISOString()}.`);
  for (const row of report.problems) lines.push(`- **${row.code}:** ${row.message}`);
  lines.push('', 'A successful auto-renewal/release does not prove VPS delivery. Check the API downloader, validation progress, installed release and serving process.', '',
    'This issue never approves pending additions or dispatches signing. Pending approval issues are separate. Renewals reuse only the last approved catalog.', '',
    'Reviewers receive a fresh mention for changed incidents and a daily reminder while unresolved. GitHub inbox/email/mobile delivery follows personal notification settings.');
  const body = lines.join('\n');
  if (healthy) {
    await alertReviewer(api, issue, alertMarker, `${alertMarker}\nDelivery recovered: signed chains and domains are current-valid with no expiry warning or overdue release delivery. [Check](${runUrl}).`);
    return api('PATCH', `issues/${issue.number}`, { body, title: 'Metadata delivery: recovered', state: 'closed', state_reason: 'completed' });
  }
  const alert = `${alertMarker}\n${reviewers.map(login => `@${login}`).join(' ')}: metadata delivery/expiry needs attention.\n\n${report.problems.map(row => `- ${row.message}`).join('\n')}\n\n[Inspect the monitor](${runUrl}). This is not an approval request.`;
  const title = 'Metadata delivery or expiry needs attention';
  if (!issue) return api('POST', 'issues', { title, body: `${body}\n\n${alert}`, assignees: reviewers });
  const updated = await api('PATCH', `issues/${issue.number}`, { title, body: `${body}${issue.body.includes(alertMarker) ? '\n' + alertMarker : ''}`, state: 'open', assignees: reviewers });
  await alertReviewer(api, updated, alertMarker, alert);
  return updated;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const { api, repository, reviewers } = await githubNotificationContext();
  let report;
  try {
    const roots = JSON.parse(await fs.readFile('trust/roots.json', 'utf8')).keys;
    const policy = JSON.parse(await fs.readFile('trust/policy.json', 'utf8'));
    report = await checkDelivery({ api, roots, policy });
  } catch { report = { checkedAt: Date.now(), records: [], release: null, problems: [problem('monitor-failed', 'The delivery monitor could not load its public trust configuration.')] }; }
  const issue = await notifyDelivery(api, { repository, runId: process.env.GITHUB_RUN_ID, runNumber: Number(process.env.GITHUB_RUN_NUMBER) }, report, reviewers);
  const summary = `Metadata delivery: ${report.problems.length ? 'needs attention' : 'healthy'}${issue ? ` ([#${issue.number}](${issue.html_url}))` : ''}.\n`;
  console.log(summary);
  if (process.env.GITHUB_STEP_SUMMARY) await fs.appendFile(process.env.GITHUB_STEP_SUMMARY, summary);
  if (report.problems.length) process.exitCode = 1;
}
