import fs from 'node:fs/promises';
import { pathToFileURL } from 'node:url';

const marker = '<!-- metadata-publication-approval:v1 -->';
const statePattern = /<!-- metadata-approval-state (\{[^\n]+\}) -->/;
const bot = 'github-actions[bot]';
const repositories = { trustWallet: 'trustwallet/assets', registry: 'ethereum/clear-signing-erc7730-registry' };

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
  throw new Error('Approval issue lookup exceeded its page limit');
}

function counts(report) {
  return `${report.added.length} added, ${report.changed.length} changed, ${report.removed.length} removed`;
}

async function alertReviewer(api, issue, marker, body) {
  if (issue.body.includes(marker)) return;
  for (let page = 1; page <= 10; page++) {
    const comments = await api('GET', `issues/${issue.number}/comments?per_page=100&page=${page}`);
    if (comments.some(comment => comment.user?.login === bot && comment.body.includes(marker))) return;
    if (comments.length < 100) {
      await api('POST', `issues/${issue.number}/comments`, { body });
      return;
    }
  }
  throw new Error('Approval notification lookup exceeded its page limit');
}

function bodyFor(context, report, state) {
  const { repository, runId, digest } = context;
  const url = `https://github.com/${repository}/actions/runs/${runId}`;
  const baseline = report.baseline?.sequence;
  const lines = [marker, `<!-- metadata-approval-state ${JSON.stringify(state)} -->`, '',
    '**Status:** Awaiting approval', '',
    `[Review and approve this batch](${url}) · [Download the complete before/after report and exact snapshot](${url}#artifacts)`, '',
    `**Changes:** ${counts(report)}. **Records:** ${report.recordCount}.`,
    `**Exact logo URL edits:** ${report.summary.logoUrlsChanged}. **Curated spam conflicts:** ${report.spamConflicts.length}.`, '',
    `**Snapshot digest:** \`${digest}\``, ''];
  if (Number.isSafeInteger(baseline) && baseline > 0) lines.push(`Compared with [metadata-${baseline}](https://github.com/${repository}/releases/tag/metadata-${baseline}).`, '');
  if (report.capacity?.largestDescriptorBytes >= report.capacity?.recordLimitBytes * 0.9) lines.push(`**Descriptor capacity:** ${report.capacity.largestDescriptorBytes} / ${report.capacity.recordLimitBytes} bytes for the largest document. Future growth beyond this per-record bound requires attention.`, '');
  lines.push('Source comparisons:');
  for (const source of report.sources) {
    const repo = source.name === 'curated' ? repository : repositories[source.name];
    if (!repo || !/^[a-f0-9]{40}$/.test(source.revision)) throw new Error('Invalid notification source');
    const previous = source.previousRevision;
    const target = /^[a-f0-9]{40}$/.test(previous ?? '') && previous !== source.revision
      ? `compare/${previous}...${source.revision}` : `commit/${source.revision}`;
    lines.push(`- [${source.name}: ${source.revision.slice(0, 12)}](https://github.com/${repo}/${target})`);
  }
  // JSON fences and escaped mention/fence characters keep upstream metadata inert.
  const preview = [...report.changes, ...report.additions, ...report.removals].slice(0, 8);
  const text = JSON.stringify(preview, (_key, value) => typeof value === 'string' && value.length > 240 ? `${value.slice(0, 240)}…` : value, 2)
    .slice(0, 16000).replaceAll('@', '\\u0040').replaceAll('`', '\\u0060').replaceAll('<', '\\u003c');
  lines.push('', '<details><summary>Before/after preview (complete values are in review.json)</summary>', '', '```json', text, '```', '', '</details>', '',
    'One approval covers this exact batch. New tokens and every exact logo URL edit require approval. Renewals continue automatically with the last approved contents.', '',
    'A newer prepared batch supersedes earlier unapproved requests. The comparison always uses the last published catalog; committed fixes remain in the repository.', '',
    'GitHub inbox, email and mobile delivery follow your personal notification settings.');
  return lines.join('\n');
}

export async function notifyApproval(api, context, report, reviewers) {
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(context.repository) || !/^[1-9][0-9]*$/.test(context.runId)
    || !Number.isSafeInteger(context.runNumber) || context.runNumber < 1 || !/^0x[0-9a-f]{64}$/.test(context.digest)) throw new Error('Invalid approval notification context');
  if (!reviewers.length || reviewers.some(login => !/^[A-Za-z0-9-]+$/.test(login))) throw new Error('Invalid approval notification reviewers');
  const issue = await findIssue(api);
  const old = issue && stateOf(issue);
  if (old && old.runNumber > context.runNumber) return issue;
  const changed = report.added.length + report.changed.length + report.removed.length > 0;
  if (!changed) {
    if (!issue) return issue;
    const state = { runId: context.runId, runNumber: context.runNumber, digest: context.digest, phase: 'no-changes' };
    const body = issue.body.replace(statePattern, `<!-- metadata-approval-state ${JSON.stringify(state)} -->`)
      .replace(/\*\*Status:\*\*[^\n]*/, '**Status:** No unpublished changes');
    if (issue.state === 'open') await api('POST', `issues/${issue.number}/comments`, { body: `The latest preparation found no unpublished changes. [Run](https://github.com/${context.repository}/actions/runs/${context.runId}).` });
    return api('PATCH', `issues/${issue.number}`, { body, state: 'closed', state_reason: 'completed' });
  }
  const state = { runId: context.runId, runNumber: context.runNumber, digest: context.digest, phase: 'waiting' };
  const body = bodyFor(context, report, state);
  const title = `Metadata approval needed: ${counts(report)}`;
  const mention = reviewers.map(login => `@${login}`).join(' ');
  const alertMarker = `<!-- metadata-approval-alert ${context.runId}:${context.digest} -->`;
  const alert = `${alertMarker}\n${mention} — metadata approval needed: **${counts(report)}**.\n\n[Review this batch](https://github.com/${context.repository}/actions/runs/${context.runId}) · [Complete before/after report](https://github.com/${context.repository}/actions/runs/${context.runId}#artifacts)\n\nSnapshot: \`${context.digest}\`. This request supersedes earlier unapproved batches.`;
  if (old?.runId === context.runId && old.digest === context.digest) {
    await alertReviewer(api, issue, alertMarker, alert);
    return issue;
  }
  if (!issue) return api('POST', 'issues', { title, body: `${body}\n\n${alert}`, assignees: reviewers });
  const updated = await api('PATCH', `issues/${issue.number}`, { title, body, state: 'open', assignees: reviewers });
  // A new comment, rather than just editing the issue, delivers a fresh mention.
  await alertReviewer(api, updated, alertMarker, alert);
  return updated;
}

export async function finishApproval(api, context, result, reviewers, sequence) {
  const issue = await findIssue(api);
  const old = issue && stateOf(issue);
  // An older publication must never close or overwrite a newer request.
  if (!old || old.runId !== context.runId || old.phase !== 'waiting') return issue;
  if (!['success', 'failure', 'cancelled', 'skipped'].includes(result)) throw new Error('Invalid publication result');
  const published = result === 'success';
  if (published && !/^[1-9][0-9]*$/.test(sequence ?? '')) throw new Error('Missing publication version');
  const status = published ? 'Published' : `Publication ${result}; review the linked run`;
  const state = { ...old, phase: result };
  const body = issue.body.replace(statePattern, `<!-- metadata-approval-state ${JSON.stringify(state)} -->`)
    .replace('**Status:** Awaiting approval', `**Status:** ${status}`);
  const link = published ? `https://github.com/${context.repository}/releases/tag/metadata-${sequence}` : `https://github.com/${context.repository}/actions/runs/${context.runId}`;
  await api('POST', `issues/${issue.number}/comments`, { body: `${published ? '' : reviewers.map(login => `@${login}`).join(' ') + ' — '}${status}. [${published ? 'Signed release' : 'Workflow details'}](${link}).` });
  return api('PATCH', `issues/${issue.number}`, { body, title: published ? 'Metadata publication: published' : 'Metadata publication needs attention', state: published ? 'closed' : 'open', ...(published ? { state_reason: 'completed' } : {}) });
}

export async function preparationFailed(api, context, reviewers) {
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(context.repository) || !/^[1-9][0-9]*$/.test(context.runId)
    || !Number.isSafeInteger(context.runNumber) || context.runNumber < 1 || !reviewers.length
    || reviewers.some(login => !/^[A-Za-z0-9-]+$/.test(login))) throw new Error('Invalid failure notification context');
  const issue = await findIssue(api);
  const old = issue && stateOf(issue);
  if (old && old.runNumber > context.runNumber) return issue;
  const alertMarker = `<!-- metadata-preparation-failure ${context.runId} -->`;
  const url = `https://github.com/${context.repository}/actions/runs/${context.runId}`;
  const alert = `${alertMarker}\n${reviewers.map(login => `@${login}`).join(' ')} — a metadata preparation failed before approval. [Inspect the failed run](${url}). Any earlier valid approval request remains available; automatic renewals use the last approved catalog.`;
  if (issue?.state === 'open' && old.phase === 'waiting') {
    await alertReviewer(api, issue, alertMarker, alert);
    return issue;
  }
  const state = { runId: context.runId, runNumber: context.runNumber, phase: 'preparation-failed' };
  const body = `${marker}\n<!-- metadata-approval-state ${JSON.stringify(state)} -->\n\n**Status:** Preparation failed; no new batch is ready for approval.\n\n[Inspect the failed preparation](${url}).\n\n${alert}`;
  if (!issue) return api('POST', 'issues', { title: 'Metadata preparation needs attention', body, assignees: reviewers });
  const updated = await api('PATCH', `issues/${issue.number}`, { title: 'Metadata preparation needs attention', body: body.replace(`\n\n${alert}`, ''), state: 'open', assignees: reviewers });
  await alertReviewer(api, updated, alertMarker, alert);
  return updated;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const repository = process.env.GITHUB_REPOSITORY;
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository ?? '') || !process.env.GH_TOKEN) throw new Error('Missing GitHub notification configuration');
  const api = async (method, path, body) => {
    const response = await fetch(`https://api.github.com/repos/${repository}/${path}`, { method, redirect: 'error',
      headers: { Accept: 'application/vnd.github+json', Authorization: `Bearer ${process.env.GH_TOKEN}`, 'Content-Type': 'application/json', 'X-GitHub-Api-Version': '2022-11-28' },
      ...(body ? { body: JSON.stringify(body) } : {}), signal: AbortSignal.timeout(30000) });
    if (!response.ok) throw new Error(`GitHub notification request failed: ${method} ${path} (${response.status})`);
    return response.json();
  };
  const policy = JSON.parse(await fs.readFile('trust/reviewers.json', 'utf8'));
  const environment = await api('GET', 'environments/metadata-review');
  const people = environment.protection_rules.filter(rule => rule.type === 'required_reviewers').flatMap(rule => rule.reviewers)
    .filter(row => row.type === 'User' && policy.userIds.includes(row.reviewer.id));
  const reviewers = [...new Set(people.map(row => row.reviewer.login))];
  if (!reviewers.length) throw new Error('No configured reviewer available for approval notification');
  const context = { repository, runId: process.env.GITHUB_RUN_ID, runNumber: Number(process.env.GITHUB_RUN_NUMBER), digest: process.env.APPROVED_DIGEST };
  let issue;
  if (process.argv[2] === 'ready') issue = await notifyApproval(api, context, JSON.parse(await fs.readFile('work/review.json', 'utf8')), reviewers);
  else if (process.argv[2] === 'finish') issue = await finishApproval(api, context, process.env.PUBLICATION_RESULT, reviewers, process.env.PUBLICATION_SEQUENCE);
  else if (process.argv[2] === 'failed') issue = await preparationFailed(api, context, reviewers);
  else throw new Error('Unknown notification command');
  if (issue) {
    console.log(`Approval issue: ${issue.html_url}`);
    if (process.env.GITHUB_STEP_SUMMARY) await fs.appendFile(process.env.GITHUB_STEP_SUMMARY, `Approval tracking: [#${issue.number}](${issue.html_url})\n`);
  }
}
