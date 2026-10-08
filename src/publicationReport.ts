import { canonicalMetadata, metadataDigest, type SignedRecord } from './protocol.ts';
import type { PreparedPublication } from './publisher.ts';

export type ReviewContext = {
  repository?: string;
  baseline?: { sequence: number; contentDigest: string; publishedAt?: string };
  previousSources?: PreparedPublication['sources'];
  notes?: string[];
};
export type FieldChange = { path: string; before?: unknown; after?: unknown };

function fieldChanges(before: unknown, after: unknown, path = ''): FieldChange[] {
  if (canonicalMetadata(before) === canonicalMetadata(after)) return [];
  if (before && after && typeof before === 'object' && typeof after === 'object' && !Array.isArray(before) && !Array.isArray(after)) {
    const a = before as Record<string, unknown>, b = after as Record<string, unknown>;
    return [...new Set([...Object.keys(a), ...Object.keys(b)])].sort().flatMap(key => {
      const pointer = `${path}/${key.replaceAll('~', '~0').replaceAll('/', '~1')}`;
      if (!Object.hasOwn(a, key)) return [{ path: pointer, after: b[key] }];
      if (!Object.hasOwn(b, key)) return [{ path: pointer, before: a[key] }];
      return fieldChanges(a[key], b[key], pointer);
    });
  }
  return [{ path: path || '/', before, after }];
}

export function publicationReport(prepared: PreparedPublication, previous?: { records: SignedRecord[] }, context: ReviewContext = {}) {
  const cache = new WeakMap<object, string>();
  const hash = (value: unknown) => {
    if (value && typeof value === 'object') {
      const cached = cache.get(value);
      if (cached) return cached;
      const digest = metadataDigest(value);
      cache.set(value, digest);
      return digest;
    }
    return metadataDigest(value);
  };
  const payload = (kind: string, value: unknown) => {
    if (kind !== 'token' && kind !== 'asset') return value;
    const { revision: _revision, ...rest } = value as Record<string, unknown>;
    return rest;
  };
  const beforeRows = new Map((previous?.records ?? []).map(row => [`${row.statement.kind}:${row.statement.scope}`, row]));
  const afterRows = new Map(prepared.records.map(row => [`${row.kind}:${row.scope}`, row]));
  const added: string[] = [], changed: string[] = [], removed: string[] = [];
  const changes: { id: string; kind: string; scope: string; category: string; fields: FieldChange[] }[] = [];
  const documents = new Map<string, { label: string; records: string[]; category: string; fields: FieldChange[] }>();
  const summary = { tokenDetailsChanged: 0, logoUrlsChanged: 0, descriptorSchemaRecords: 0, descriptorSchemaDocuments: 0, otherChangedRecords: 0 };
  for (const [id, row] of afterRows) {
    const prior = beforeRows.get(id);
    if (!prior) { added.push(id); continue; }
    // Preserve the existing approval gate, including every URL/schema edit.
    if (hash(payload(row.kind, prior.payload)) === hash(payload(row.kind, row.payload))) continue;
    changed.push(id);
    const fields = fieldChanges(prior.payload, row.payload).filter(field => !(['token', 'asset'].includes(row.kind) && field.path === '/revision'));
    let category = 'content';
    if (row.kind === 'token' || row.kind === 'asset') {
      if (fields.some(field => field.path !== '/logoUrl')) summary.tokenDetailsChanged++;
      if (fields.some(field => field.path === '/logoUrl')) {
        summary.logoUrlsChanged++;
        if (fields.length === 1) category = 'logo-url';
      }
    } else if (row.kind === 'descriptor') {
      if (fields.length === 1 && fields[0]!.path === '/$schema') {
        category = 'schema-reference';
        summary.descriptorSchemaRecords++;
      }
      const key = `${hash(prior.payload)}:${hash(row.payload)}`;
      let document = documents.get(key);
      if (!document) {
        const data = row.payload as { metadata?: { owner?: string; contractName?: string }; context?: { $id?: string } };
        const label = [data.metadata?.owner, data.metadata?.contractName ?? data.context?.$id].filter(Boolean).join(' — ') || row.scope;
        document = { label, records: [], category, fields };
        documents.set(key, document);
      }
      document.records.push(id);
    }
    if (category === 'content' && row.kind !== 'token' && row.kind !== 'asset') summary.otherChangedRecords++;
    changes.push({ id, kind: row.kind, scope: row.scope, category, fields });
  }
  for (const id of beforeRows.keys()) if (!afterRows.has(id)) removed.push(id);
  summary.descriptorSchemaDocuments = [...documents.values()].filter(document => document.category === 'schema-reference').length;
  const repositories: Record<string, string> = { trustWallet: 'trustwallet/assets', registry: 'ethereum/clear-signing-erc7730-registry' };
  if (context.repository && /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(context.repository)) repositories.curated = context.repository;
  const sources = prepared.sources.map(source => {
    const prior = context.previousSources?.find(row => row.name === source.name)?.revision;
    const repository = repositories[source.name];
    const exact = /^[a-f0-9]{40}$/.test(source.revision);
    return { ...source, ...(prior ? { previousRevision: prior } : {}),
      ...(repository && exact ? { url: `https://github.com/${repository}/commit/${source.revision}` } : {}),
      ...(repository && exact && prior && /^[a-f0-9]{40}$/.test(prior) && prior !== source.revision
        ? { compareUrl: `https://github.com/${repository}/compare/${prior}...${source.revision}` } : {}) };
  });
  const baseline = context.baseline ? { ...context.baseline,
    ...(repositories.curated ? { url: `https://github.com/${repositories.curated}/releases/tag/metadata-${context.baseline.sequence}` } : {}) } : null;
  return { firstPublication: !previous, sequence: prepared.sequence, sources, added, changed, removed,
    recordCount: prepared.records.length, baseline, summary, changes, documents: [...documents.values()],
    additions: added.map(id => ({ id, after: afterRows.get(id)!.payload })),
    removals: removed.map(id => ({ id, before: beforeRows.get(id)!.payload })), notes: context.notes ?? [] };
}

export type PublicationReport = ReturnType<typeof publicationReport>;

function escape(value: string) {
  return value.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;')
    .replaceAll('\\', '&#92;').replaceAll('*', '&#42;').replaceAll('_', '&#95;')
    .replaceAll('|', '&#124;').replaceAll('`', '&#96;').replaceAll('[', '&#91;').replaceAll(']', '&#93;').replaceAll('\r', '').replaceAll('\n', '<br>');
}
function display(value: unknown, complete = false) {
  const text = JSON.stringify(value) ?? '(absent)';
  return escape(!complete && text.length > 500 ? `${text.slice(0, 500)}… (full value in review.json)` : text);
}

export function renderPublicationReview(report: PublicationReport, digest: string, compact = false) {
  if (!/^0x[0-9a-f]{64}$/.test(digest)) throw new Error('Invalid review snapshot digest');
  const lines = ['## Metadata publication review', '', `Snapshot awaiting approval: \`${digest}\``, ''];
  if (report.baseline) {
    const name = `metadata-${report.baseline.sequence}`;
    lines.push(`Compared with: ${report.baseline.url ? `[${name}](${report.baseline.url})` : name}${report.baseline.publishedAt ? ` (published ${escape(report.baseline.publishedAt)})` : ''}.`,
      `Baseline content digest: \`${report.baseline.contentDigest}\``, '');
  } else lines.push(report.firstPublication ? 'First publication; all records require review.' : 'Baseline publication details unavailable.', '');
  lines.push(`Records: ${report.recordCount}. Added: ${report.added.length}; changed: ${report.changed.length}; removed: ${report.removed.length}.`, '',
    '| Change category | Count |', '| --- | ---: |',
    `| Token details changed, excluding logo URLs | ${report.summary.tokenDetailsChanged} |`,
    `| Exact logo URLs changed; approval required | ${report.summary.logoUrlsChanged} |`,
    `| Descriptor schema references | ${report.summary.descriptorSchemaDocuments} documents / ${report.summary.descriptorSchemaRecords} records |`,
    `| Other changed records | ${report.summary.otherChangedRecords} |`, '',
    'Every URL and schema edit remains a change requiring approval. Signing and verification bind the exact logo URL; image content is not used to suppress or downgrade URL changes.', '',
    '### Sources', '', '| Source | Previous revision | Prepared revision | Comparison |', '| --- | --- | --- | --- |');
  for (const source of report.sources) {
    const revision = source.url ? `[${source.revision.slice(0, 12)}](${source.url})` : escape(source.revision);
    lines.push(`| ${escape(source.name)} | ${source.previousRevision ? escape(source.previousRevision.slice(0, 12)) : 'Unavailable'} | ${revision} | ${source.compareUrl ? `[View changes](${source.compareUrl})` : source.previousRevision === source.revision ? 'Unchanged' : 'Previous revision unavailable'} |`);
  }
  const details = [
    ...report.documents.map(document => ({ label: `${document.label} (${document.records.length} records; ${document.category})`, fields: document.fields })),
    ...report.changes.filter(change => change.kind !== 'descriptor').map(change => ({ label: change.id, fields: change.fields })),
    ...report.additions.map(change => ({ label: `Added ${change.id}`, fields: [{ path: '/', after: change.after }] })),
    ...report.removals.map(change => ({ label: `Removed ${change.id}`, fields: [{ path: '/', before: change.before }] })),
  ];
  lines.push('', '### Before / after', '');
  const limit = compact ? 20 : details.length;
  if (!details.length) lines.push('No field changes.');
  for (const item of details.slice(0, limit)) {
    lines.push(`**${escape(item.label.length > 200 ? `${item.label.slice(0, 200)}…` : item.label)}**`, '', '| Field (JSON Pointer) | Before | After |', '| --- | --- | --- |');
    for (const field of item.fields.slice(0, compact ? 10 : item.fields.length)) lines.push(`| ${escape(field.path)} | ${display(field.before, field.path === '/logoUrl')} | ${display(field.after, field.path === '/logoUrl')} |`);
    if (compact && item.fields.length > 10) lines.push('', 'Additional fields are included in review.md and review.json.');
    lines.push('');
  }
  if (details.length > limit) lines.push(`Showing ${limit} of ${details.length} entries; the complete list is in review.md and review.json.`, '');
  if (report.notes.length) lines.push('### Review notes', '', ...report.notes.map(note => `- ${escape(note)}`), '');
  lines.push('Download **prepared-metadata** from this run’s **Artifacts** section: **review.md** is the readable report, **review.json** contains complete field values and scopes, and **prepared.json** is the exact snapshot submitted for approval.', '');
  return lines.join('\n');
}
