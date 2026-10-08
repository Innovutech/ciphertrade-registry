import fs from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { catalogDigest } from '../src/publicationLifecycle.ts';

const MAX_SNAPSHOT = 64 * 1024 * 1024;
const PROVENANCE = 'review-provenance.json';
const sourceNames = new Set(['curated', 'trustWallet', 'registry']);
const command = (file, args, timeout = 30000) => execFileSync(file, args, {
  encoding: 'utf8', timeout, maxBuffer: MAX_SNAPSHOT, stdio: ['ignore', 'pipe', 'pipe'],
});

function validSources(sources) {
  return Array.isArray(sources) && sources.length > 0 && sources.length <= 3
    && new Set(sources.map(row => row?.name)).size === sources.length
    && sources.every(row => sourceNames.has(row?.name) && /^[a-f0-9]{40}$/.test(row?.revision));
}
async function readJson(filename, limit = MAX_SNAPSHOT) {
  const stat = await fs.lstat(filename);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > limit) throw new Error('Unsupported review artifact');
  return JSON.parse(await fs.readFile(filename, 'utf8'));
}

// This provenance is review information only. Signed publication verification
// remains the authority for the baseline, and categories never control approval.
export async function releaseReviewContext(previous, run = command) {
  if (!previous) return { sources: [], publishedAt: undefined };
  const tag = `metadata-${previous.sequence}`;
  try {
    const release = JSON.parse(run('gh', ['release', 'view', tag, '--json', 'publishedAt,assets']));
    let sources = [];
    if (release.assets?.some(asset => asset.name === PROVENANCE)) {
      const directory = `work/review-baseline/${previous.sequence}`;
      await fs.mkdir(directory, { recursive: true });
      run('gh', ['release', 'download', tag, '--pattern', PROVENANCE, '--dir', directory, '--clobber']);
      const provenance = await readJson(`${directory}/${PROVENANCE}`, 1024 * 1024);
      if (provenance.schema === 1 && provenance.sequence === previous.sequence
        && provenance.contentDigest === previous.contentDigest && validSources(provenance.sources)) sources = provenance.sources;
    }
    return { sources, publishedAt: release.publishedAt };
  } catch { return { sources: [], publishedAt: undefined }; }
}

export async function previousReviewSources(previous, release, run = command) {
  if (!previous) return { sources: [], notes: [] };
  if (release.sources.length) return { sources: release.sources, notes: [] };
  // Older releases did not retain source provenance. Recover it from a retained
  // successful publication's signing input only when every payload matches.
  try {
    const runs = JSON.parse(run('gh', ['run', 'list', '--workflow', 'publish.yml', '--status', 'success', '--limit', '10', '--json', 'databaseId']));
    for (const row of runs) {
      if (!Number.isSafeInteger(row.databaseId) || row.databaseId <= 0) continue;
      try {
        const directory = `work/review-baseline/run-${row.databaseId}`;
        await fs.mkdir(directory, { recursive: true });
        run('gh', ['run', 'download', String(row.databaseId), '--name', 'signing-metadata', '--dir', directory]);
        const prepared = await readJson(`${directory}/prepared.json`);
        if (prepared.schema === 1 && Array.isArray(prepared.records) && prepared.records.length <= 100000
          && validSources(prepared.sources) && catalogDigest(prepared.records) === previous.contentDigest) {
          return { sources: prepared.sources, notes: ['Previous source revisions recovered from a successful run whose signing input matches the verified baseline catalog.'] };
        }
      } catch { /* Missing/expired artifacts do not interrupt publication. */ }
    }
  } catch { /* Source links are optional review context. */ }
  const revisions = new Map();
  for (const row of previous.records) {
    const name = row.payload?.source === 'trustwallet' ? 'trustWallet' : row.payload?.source === 'ciphertrade' ? 'curated' : null;
    if (name && /^[a-f0-9]{40}$/.test(row.payload?.revision)) {
      if (!revisions.has(name)) revisions.set(name, new Set());
      revisions.get(name).add(row.payload.revision);
    }
  }
  const sources = [...revisions].filter(([, values]) => values.size === 1).map(([name, values]) => ({ name, revision: [...values][0] }));
  return { sources, notes: ['Some previous source revisions were not retained; unavailable comparisons are explicitly marked.'] };
}

export async function publicationReviewContext(prepared, previous) {
  const release = await releaseReviewContext(previous);
  const history = await previousReviewSources(previous, release);
  return { repository: process.env.GITHUB_REPOSITORY, previousSources: history.sources,
    ...(previous ? { baseline: { sequence: previous.sequence, contentDigest: previous.contentDigest, ...(release.publishedAt ? { publishedAt: release.publishedAt } : {}) } } : {}),
    notes: history.notes };
}

export async function publicationProvenance(prepared, previous) {
  let sources = prepared.sources;
  if (sources.some(row => row.name === 'approved-catalog')) {
    const release = await releaseReviewContext(previous);
    sources = release.sources; // Preserve original sources across renewals when available.
  }
  return { schema: 1, sequence: prepared.sequence, contentDigest: catalogDigest(prepared.records), sources };
}
