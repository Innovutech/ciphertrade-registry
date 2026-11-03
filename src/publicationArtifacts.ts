import { metadataDigest, type SignedRecord, type SignedTrust } from './protocol.ts';
import type { PreparedPublication } from './publisher.ts';

// Internal artifacts share descriptor documents just like the public release.
// Approval and signatures still bind the original expanded payload at each scope.
export function encodePrepared(prepared: PreparedPublication) {
  const documents: Record<string, unknown> = Object.create(null);
  const hashes = new WeakMap<object, string>();
  const records = prepared.records.map(row => {
    if (row.kind !== 'descriptor') return row;
    const payload = row.payload as object;
    let digest = hashes.get(payload);
    if (!digest) { digest = metadataDigest(payload); hashes.set(payload, digest); }
    documents[digest] = payload;
    return { kind: row.kind, scope: row.scope, payloadRef: digest };
  });
  return { ...prepared, documents, records };
}

function expand(input: any, signed: boolean) {
  if (input?.schema !== 1 || !Array.isArray(input.records) || input.records.length > 100000) throw new Error('Invalid publication artifact');
  const documents = input.documents ?? {};
  if (!documents || typeof documents !== 'object' || Array.isArray(documents)) throw new Error('Invalid artifact documents');
  const verified = new Set<string>();
  const records = input.records.map((row: any) => {
    if (!row || typeof row !== 'object') throw new Error('Invalid artifact record');
    if (!Object.hasOwn(row, 'payloadRef')) {
      if (!Object.hasOwn(row, 'payload')) throw new Error('Missing artifact payload');
      return row;
    }
    const ref = row.payloadRef;
    const kind = signed ? row.statement?.kind : row.kind;
    if (kind !== 'descriptor' || Object.hasOwn(row, 'payload') || typeof ref !== 'string' || !/^0x[0-9a-f]{64}$/.test(ref)
      || !Object.hasOwn(documents, ref) || (signed && row.statement.digest !== ref)) throw new Error('Invalid artifact reference');
    if (!verified.has(ref)) {
      if (metadataDigest(documents[ref]) !== ref) throw new Error('Artifact document digest mismatch');
      verified.add(ref);
    }
    const { payloadRef: _ref, ...rest } = row;
    return { ...rest, payload: documents[ref] };
  });
  if (Object.keys(documents).some(ref => !verified.has(ref))) throw new Error('Unused artifact document');
  const { documents: _documents, ...header } = input;
  return { ...header, records };
}

export function decodePrepared(input: unknown): PreparedPublication { return expand(input, false); }

export function encodeSignedPart(part: { schema: 1; trust: SignedTrust; records: SignedRecord[] }) {
  const documents: Record<string, unknown> = Object.create(null);
  const records = part.records.map(row => {
    if (row.statement.kind !== 'descriptor') return row;
    documents[row.statement.digest] = row.payload;
    return { statement: row.statement, signature: row.signature, payloadRef: row.statement.digest };
  });
  return { ...part, documents, records };
}

export function decodeSignedPart(input: unknown): { schema: 1; trust: SignedTrust; records: SignedRecord[] } { return expand(input, true); }

export function artifactJson(input: unknown): string {
  const text = JSON.stringify(input);
  if (Buffer.byteLength(text) > 64 * 1024 * 1024) throw new Error('Publication artifact exceeds 64 MiB budget');
  return text;
}
