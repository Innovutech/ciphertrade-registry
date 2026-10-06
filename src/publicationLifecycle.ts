import { ethers } from 'ethers';
import { MetadataVerifier, metadataDigest, type RootKey, type SignedTrust, type SignedRecord, type Evidence } from './protocol.ts';
import { preparedDigest, type Candidate, type PreparedPublication } from './publisher.ts';

export type Publication = { schema: 1; trust: SignedTrust; documents?: Record<string, unknown>; records: (Evidence & { payload?: unknown; payloadRef?: string })[] };
export type VerifiedPublication = { trust: SignedTrust; records: SignedRecord[]; sequence: number; contentDigest: string };
const WEEK = 7 * 86400000;

export function catalogDigest(records: Candidate[]): string {
  const rows = records.map(row => [row.kind, row.scope, metadataDigest(row.payload)]).sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b), 'en'));
  return ethers.sha256(ethers.toUtf8Bytes(JSON.stringify(rows)));
}

export function verifyPrevious(input: Publication, roots: RootKey[], now = Date.now()): VerifiedPublication {
  if (input?.schema !== 1 || !Array.isArray(input.records) || !input.records.length || input.records.length > 100000) throw new Error('Invalid previous publication');
  const verifier = new MetadataVerifier(roots);
  verifier.acceptTrust(input.trust, Math.min(now, input.trust.payload.issuedAt));
  const scopes = new Set<string>();
  const sequences = new Set<number>();
  const records = input.records.map(row => {
    if (row.statement.issuedAt > now + 60000) throw new Error('Future publication');
    if (row.payloadRef && (row.payloadRef !== row.statement.digest || !input.documents || !Object.hasOwn(input.documents, row.payloadRef))) throw new Error('Invalid previous document reference');
    const payload = row.payloadRef ? input.documents![row.payloadRef] : row.payload;
    const id = `${row.statement.kind}:${row.statement.scope}`;
    if (scopes.has(id)) throw new Error('Duplicate previous scope');
    scopes.add(id);
    sequences.add(row.statement.sequence);
    return verifier.verify(payload, { statement: row.statement, signature: row.signature }, row.statement.kind, row.statement.scope, row.statement.issuedAt);
  });
  if (sequences.size !== 1) throw new Error('Mixed previous publication versions');
  return { trust: input.trust, records, sequence: [...sequences][0]!, contentDigest: catalogDigest(records.map(row => ({ ...row.statement, payload: row.payload }))) };
}

export function finalizePublication(options: {
  mode: 'changes' | 'renewal'; previous: VerifiedPublication | null;
  reviewed?: PreparedPublication; approvedDigest?: string;
  trust: SignedTrust; roots: RootKey[]; now?: number;
}): PreparedPublication {
  const { mode, previous, trust, roots } = options;
  const now = options.now ?? Date.now();
  const verifier = new MetadataVerifier(roots);
  if (previous) verifier.acceptTrust(previous.trust, previous.trust.payload.issuedAt);
  verifier.acceptTrust(trust, now);
  let records: Candidate[];
  let sources: PreparedPublication['sources'];
  if (mode === 'renewal') {
    if (!previous || options.reviewed || options.approvedDigest) throw new Error('Renewal requires only an authenticated previous publication');
    for (const row of previous.records) {
      const key = trust.payload.keys.find(key => key.id === row.statement.keyId && key.kinds.includes(row.statement.kind));
      const oldKey = previous.trust.payload.keys.find(key => key.id === row.statement.keyId);
      if (!key || !oldKey || ethers.SigningKey.computePublicKey(key.publicKey, true) !== ethers.SigningKey.computePublicKey(oldKey.publicKey, true)
        || key.notBefore > row.statement.issuedAt || (key.expiresAt !== null && key.expiresAt <= now)
        || trust.payload.revokedDigests.includes(row.statement.digest)
        || row.statement.sequence < trust.payload.minimumSequences[row.statement.kind]) throw new Error('Previously approved data is no longer authorized for renewal');
    }
    records = previous.records.map(row => ({ kind: row.statement.kind, scope: row.statement.scope, payload: row.payload }));
    sources = [{ name: 'approved-catalog', revision: previous.contentDigest }];
  } else if (mode === 'changes') {
    const reviewed = options.reviewed;
    if (!reviewed || !options.approvedDigest || preparedDigest(reviewed) !== options.approvedDigest) throw new Error('Reviewed snapshot changed');
    if (reviewed.baseDigest === undefined || reviewed.baseDigest !== (previous?.contentDigest ?? null)) throw new Error('Reviewed catalog base was superseded; review again');
    records = reviewed.records;
    sources = reviewed.sources;
  } else throw new Error('Unsupported publication mode');
  const sequence = Math.max(now, (previous?.sequence ?? 0) + 1);
  if (!Number.isSafeInteger(sequence) || sequence <= 0) throw new Error('Invalid publication sequence');
  let expiresAt = Math.min(now + WEEK, trust.payload.expiresAt ?? Infinity);
  for (const kind of new Set(records.map(row => row.kind))) {
    const keys = trust.payload.keys.filter(key => key.kinds.includes(kind) && key.notBefore <= now && (key.expiresAt === null || key.expiresAt > now));
    if (!keys.length) throw new Error('No current publishing key for catalog');
    expiresAt = Math.min(expiresAt, Math.max(...keys.map(key => key.expiresAt ?? Infinity)));
  }
  if (expiresAt <= now) throw new Error('Publication authorization expired');
  return { schema: 1, sequence, issuedAt: now, expiresAt, sources, records, baseDigest: previous?.contentDigest ?? null };
}
