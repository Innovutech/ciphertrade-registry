import { ethers } from 'ethers';
import type { TrustPayload } from './protocol.ts';

export function assertPublishingRoles(trust: TrustPayload): void {
  const roles = [new Set(['token', 'asset']), new Set(['descriptor']), new Set(['networks', 'domains', 'classification'])];
  const found = new Set<number>();
  const material = new Set<string>();
  for (const key of trust.keys) {
    const role = roles.findIndex(kinds => key.kinds.every(kind => kinds.has(kind)));
    if (role < 0) throw new Error('A publishing key crosses isolated roles');
    const publicKey = ethers.SigningKey.computePublicKey(key.publicKey, true);
    if (material.has(publicKey)) throw new Error('Publishing roles must not reuse key material');
    material.add(publicKey);
    if (key.notBefore <= Date.now() && (key.expiresAt === null || key.expiresAt > Date.now())) found.add(role);
  }
  if (found.size !== roles.length) throw new Error('Each publication role needs a current dedicated key');
}

export function assertReviewerEnvironment(input: unknown, allowedUserIds: readonly number[]): void {
  const environment = input as { protection_rules?: { type?: string; reviewers?: { type?: string; reviewer?: { id?: number } }[] }[]; deployment_branch_policy?: { protected_branches?: boolean } };
  const reviewers = environment?.protection_rules?.find(rule => rule.type === 'required_reviewers')?.reviewers;
  if (!allowedUserIds.length || !Array.isArray(reviewers) || !reviewers.length
    || reviewers.some(entry => entry.type !== 'User' || !allowedUserIds.includes(entry.reviewer?.id ?? -1))) {
    throw new Error('Publication environment must require an allowlisted reviewer');
  }
  if (environment.deployment_branch_policy?.protected_branches !== true) throw new Error('Publication environment must restrict deployment to protected branches');
}

export function assertSigningEnvironment(input: unknown): void {
  const environment = input as { protection_rules?: { type?: string }[]; deployment_branch_policy?: { protected_branches?: boolean } };
  if (environment?.deployment_branch_policy?.protected_branches !== true) throw new Error('Signing environment must restrict deployment to protected branches');
  if (environment.protection_rules?.some(rule => rule.type === 'required_reviewers' || rule.type === 'wait_timer')) throw new Error('Signing jobs must not block approved-catalog renewal; review changes in metadata-review');
}
