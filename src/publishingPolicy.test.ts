import test from 'node:test';
import assert from 'node:assert/strict';
import { ethers } from 'ethers';
import { assertPublishingRoles, assertReviewerEnvironment, assertSigningEnvironment } from './publishingPolicy.ts';
import type { TrustPayload } from './protocol.ts';

test('production keys cannot cross roles or merely rename the same key material', () => {
  const roles = [['token', 'asset'], ['descriptor'], ['networks', 'domains', 'classification']];
  const policy = { keys: roles.map((kinds, i) => ({ id: `role-${i}`, publicKey: ethers.Wallet.createRandom().signingKey.compressedPublicKey, kinds, notBefore: 1, expiresAt: Date.now() + 86400000 })) } as TrustPayload;
  assert.doesNotThrow(() => assertPublishingRoles(policy));
  const mixed = structuredClone(policy);
  mixed.keys[0]!.kinds.push('descriptor');
  assert.throws(() => assertPublishingRoles(mixed), /crosses/);
  const shared = structuredClone(policy);
  shared.keys[1]!.publicKey = shared.keys[0]!.publicKey;
  assert.throws(() => assertPublishingRoles(shared), /reuse/);
});

test('publication refuses absent, unrestricted or non-allowlisted approval gates', () => {
  const environment = { deployment_branch_policy: { protected_branches: true }, protection_rules: [{ type: 'required_reviewers', reviewers: [{ type: 'User', reviewer: { id: 123 } }] }] };
  assert.doesNotThrow(() => assertReviewerEnvironment(environment, [123]));
  assert.throws(() => assertReviewerEnvironment({}, [123]));
  assert.throws(() => assertReviewerEnvironment(environment, [456]));
  assert.throws(() => assertReviewerEnvironment({ ...environment, deployment_branch_policy: null }, [123]));
  assert.throws(() => assertReviewerEnvironment({ ...environment, protection_rules: [{ type: 'required_reviewers', reviewers: [{ type: 'Team', reviewer: { id: 123 } }] }] }, [123]));
});

test('automated signing stays protected-branch-only and cannot silently keep renewal approval gates', () => {
  assert.doesNotThrow(() => assertSigningEnvironment({ deployment_branch_policy: { protected_branches: true }, protection_rules: [] }));
  assert.throws(() => assertSigningEnvironment({}));
  assert.throws(() => assertSigningEnvironment({ deployment_branch_policy: { protected_branches: false } }));
  assert.throws(() => assertSigningEnvironment({ deployment_branch_policy: { protected_branches: true }, protection_rules: [{ type: 'required_reviewers' }] }));
});
