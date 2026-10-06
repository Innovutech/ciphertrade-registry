import { metadataDigest, type SignedRecord } from './protocol.ts';
import type { PreparedPublication } from './publisher.ts';

export function publicationReport(prepared: PreparedPublication, previous?: { records: SignedRecord[] }) {
  const digest = (kind: string, payload: unknown) => {
    if (kind !== 'token' && kind !== 'asset') return metadataDigest(payload);
    const { revision: _revision, ...rest } = payload as Record<string, unknown>;
    return metadataDigest(rest);
  };
  const before = new Map((previous?.records ?? []).map(row => [`${row.statement.kind}:${row.statement.scope}`, digest(row.statement.kind, row.payload)]));
  const after = new Map(prepared.records.map(row => [`${row.kind}:${row.scope}`, digest(row.kind, row.payload)]));
  const added: string[] = [], changed: string[] = [], removed: string[] = [];
  for (const [scope, digest] of after) {
    if (!before.has(scope)) added.push(scope);
    else if (before.get(scope) !== digest) changed.push(scope);
  }
  for (const scope of before.keys()) if (!after.has(scope)) removed.push(scope);
  return { firstPublication: !previous, sequence: prepared.sequence, sources: prepared.sources, added, changed, removed };
}
