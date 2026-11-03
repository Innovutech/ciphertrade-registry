import test from 'node:test';
import assert from 'node:assert/strict';
import { notifyApproval, finishApproval } from '../scripts/approval-notification.mjs';

const context = { repository: 'example/registry', runId: '101', runNumber: 5, digest: `0x${'a'.repeat(64)}` };
const reviewers = ['reviewer'];
const report = {
  added: ['token:1:new'], changed: ['token:1:existing'], removed: [], recordCount: 20,
  summary: { logoUrlsChanged: 1 }, spamConflicts: [], baseline: { sequence: 123 },
  sources: [{ name: 'curated', revision: 'a'.repeat(40), previousRevision: 'b'.repeat(40) }],
  changes: [{ id: 'token:1:existing', fields: [{ path: '/name', before: 'old', after: '@outsider ``` </details>' }] }],
  additions: [{ id: 'token:1:new' }], removals: [],
};

function fixture() {
  const issues: any[] = [], calls: any[] = [], comments: any[] = [];
  const api = async (method: string, path: string, body?: any) => {
    calls.push({ method, path, body });
    if (method === 'GET') return path.includes('/comments?') ? comments.map(body => ({ body, user: { login: 'github-actions[bot]' } })) : structuredClone(issues);
    if (path === 'issues' && method === 'POST') {
      const issue = { number: issues.length + 1, html_url: 'https://github.com/example/registry/issues/1', state: 'open', user: { login: 'github-actions[bot]' }, ...body };
      issues.unshift(issue);
      return structuredClone(issue);
    }
    if (path.endsWith('/comments')) { comments.push(body.body); return { id: comments.length }; }
    const issue = issues.find(row => path === `issues/${row.number}`);
    assert.ok(issue);
    Object.assign(issue, body);
    return structuredClone(issue);
  };
  return { api, issues, calls, comments };
}

test('an approval issue contains the exact digest, changes and reviewer notification while upstream mentions stay inert', async () => {
  const f = fixture();
  const issue = await notifyApproval(f.api, context, report, reviewers);
  assert.equal(f.issues.length, 1);
  assert.deepEqual(issue.assignees, reviewers);
  assert.ok(issue.body.includes(context.digest));
  assert.ok(issue.body.includes('1 added, 1 changed, 0 removed'));
  assert.ok(issue.body.includes('actions/runs/101#artifacts'));
  assert.ok(issue.body.includes('compare/' + 'b'.repeat(40)));
  assert.ok(issue.body.includes('@reviewer'));
  assert.ok(!issue.body.includes('@outsider'));
  assert.ok(!issue.body.includes('``` </details>'));
  assert.ok(issue.body.includes('\\u0040outsider'));
});

test('a newer batch reuses one issue, reopens it and posts a fresh notification; retries do not duplicate it', async () => {
  const f = fixture();
  await notifyApproval(f.api, context, report, reviewers);
  f.issues[0].state = 'closed';
  const newer = { ...context, runId: '102', runNumber: 6, digest: `0x${'b'.repeat(64)}` };
  await notifyApproval(f.api, newer, report, reviewers);
  await notifyApproval(f.api, newer, report, reviewers);
  assert.equal(f.issues.length, 1);
  assert.equal(f.issues[0].state, 'open');
  assert.equal(f.comments.length, 1);
  assert.ok(f.comments[0].includes('@reviewer'));
  assert.ok(f.issues[0].body.includes(newer.digest));
  assert.ok(!f.issues[0].body.includes(context.digest));
});

test('older preparations and publication completions cannot overwrite or close a newer request', async () => {
  const f = fixture();
  await notifyApproval(f.api, { ...context, runId: '102', runNumber: 6 }, report, reviewers);
  const before = JSON.stringify(f.issues);
  await notifyApproval(f.api, context, report, reviewers);
  await finishApproval(f.api, context, 'success', reviewers, '999');
  assert.equal(JSON.stringify(f.issues), before);
  assert.equal(f.comments.length, 0);
});

test('successful publication closes only its own approval issue with the exact release link', async () => {
  const f = fixture();
  await notifyApproval(f.api, context, report, reviewers);
  await finishApproval(f.api, context, 'success', reviewers, '999');
  await finishApproval(f.api, context, 'success', reviewers, '999');
  assert.equal(f.issues[0].state, 'closed');
  assert.ok(f.issues[0].body.includes('**Status:** Published'));
  assert.equal(f.comments.length, 1);
  assert.ok(f.comments[0].includes('/releases/tag/metadata-999'));
});

test('a failed publication leaves a visible open request and alerts its reviewer', async () => {
  const f = fixture();
  await notifyApproval(f.api, context, report, reviewers);
  await finishApproval(f.api, context, 'failure', reviewers);
  assert.equal(f.issues[0].state, 'open');
  assert.ok(f.issues[0].body.includes('Publication failure'));
  assert.ok(f.comments[0].includes('@reviewer'));
});

test('a no-change preparation creates no issue and closes an obsolete request', async () => {
  const f = fixture();
  const empty = { ...report, added: [], changed: [], removed: [] };
  await notifyApproval(f.api, context, empty, reviewers);
  assert.equal(f.issues.length, 0);
  await notifyApproval(f.api, context, report, reviewers);
  await notifyApproval(f.api, { ...context, runId: '102', runNumber: 6 }, empty, reviewers);
  await finishApproval(f.api, context, 'cancelled', reviewers);
  assert.equal(f.issues[0].state, 'closed');
});

test('retrying a notification after a comment delivery failure still alerts the reviewer', async () => {
  const f = fixture();
  await notifyApproval(f.api, context, report, reviewers);
  const newer = { ...context, runId: '102', runNumber: 6 };
  const failing = async (method: string, path: string, body?: any) => {
    if (method === 'POST' && path.endsWith('/comments')) throw new Error('Transient comment failure');
    return f.api(method, path, body);
  };
  await assert.rejects(notifyApproval(failing, newer, report, reviewers), /Transient/);
  await notifyApproval(f.api, newer, report, reviewers);
  assert.equal(f.comments.length, 1);
  assert.ok(f.comments[0].includes('@reviewer'));
});

test('a user-created lookalike issue cannot intercept approval updates', async () => {
  const f = fixture();
  await notifyApproval(f.api, context, report, reviewers);
  f.issues[0].user.login = 'outsider';
  const body = f.issues[0].body;
  await notifyApproval(f.api, { ...context, runId: '102', runNumber: 6 }, report, reviewers);
  assert.equal(f.issues.length, 2);
  assert.equal(f.issues[1].body, body);
});
