import type { MetadataKind, Statement, TrustPayload } from './protocol.ts';

export const PUBLICATION_LIFETIME = 30 * 86400000;
const DOMAIN_LIFETIME = 7 * 86400000;
type PublicationWindow = { issuedAt: number; expiresAt: number };

export function recordExpiry(window: PublicationWindow, kind: MetadataKind, keyId: string, trust: TrustPayload): number {
  if (!Number.isSafeInteger(window.issuedAt) || window.issuedAt <= 0 || !Number.isSafeInteger(window.expiresAt)
    || window.expiresAt <= window.issuedAt) throw new Error('Invalid publication validity period');
  const key = trust.keys.find(key => key.id === keyId && key.kinds.includes(kind));
  if (!key || key.notBefore > window.issuedAt) throw new Error('Publishing key not authorized');
  // The prepared deadline is an upper bound, not a shared expiry for every role.
  const expiresAt = Math.min(window.expiresAt, window.issuedAt + (kind === 'domains' ? DOMAIN_LIFETIME : PUBLICATION_LIFETIME),
    trust.expiresAt ?? Infinity, key.expiresAt ?? Infinity);
  if (expiresAt <= window.issuedAt) throw new Error('Publication authorization expired');
  return expiresAt;
}

export function assertRecordPublication(statement: Statement, prepared: PublicationWindow & { sequence: number }, trust: TrustPayload): void {
  if (statement.sequence !== prepared.sequence || statement.issuedAt !== prepared.issuedAt
    || statement.expiresAt !== recordExpiry(prepared, statement.kind, statement.keyId, trust)) {
    throw new Error('Signing role used a different publication version or validity period');
  }
}
