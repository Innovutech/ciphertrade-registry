import { parsePositionActionPolicyCatalog } from './positionActionPolicy.ts';
import type { Candidate } from './publisher.ts';
import type { VerifiedPublication } from './publicationLifecycle.ts';

const prefix = 'position-actions:';
export const isPositionPolicyScope = (scope: string) => scope.startsWith(prefix);

export function positionPolicyScope(chainId: number): string {
  if (!Number.isSafeInteger(chainId) || chainId <= 0) throw new Error('Invalid position policy chain');
  return `${prefix}v1:${chainId}`;
}

export function validatePositionPolicyDescriptor(row: Candidate): void {
  if (!isPositionPolicyScope(row.scope)) return;
  const chainId = Number(row.scope.split(':')[2]);
  if (row.kind !== 'descriptor' || row.scope !== positionPolicyScope(chainId)) throw new Error('Invalid reserved position policy scope');
  const catalog = parsePositionActionPolicyCatalog(row.payload);
  if (catalog.policies.some(policy => policy.chainId !== chainId)) throw new Error('Position policy chain differs from descriptor scope');
}

// Absence is not signed evidence of withdrawal. Include the empty replacement
// before hashing the snapshot for review, never while signing or renewing it.
export function positionPolicyWithdrawals(records: readonly Candidate[], previous: VerifiedPublication | null): Candidate[] {
  const present = new Set(records.filter(row => row.kind === 'descriptor').map(row => row.scope));
  return (previous?.records ?? []).flatMap(({ statement: { kind, scope } }) =>
    kind === 'descriptor' && isPositionPolicyScope(scope) && !present.has(scope)
      ? [{ kind, scope, payload: { schemaVersion: 1, policies: [] } }] : []);
}
