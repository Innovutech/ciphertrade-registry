import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { importDescriptors, importPositionPolicyDescriptors } from './publisher.ts';
import { createInitialPositionActionPolicyCatalog } from './positionPolicyCatalog.ts';
import { validatePositionPolicyDescriptor } from './positionPolicyDescriptors.ts';

const chainId = 2632500;
const chains = { [chainId]: {} };
const empty = { schemaVersion: 1, policies: [] };
const scope = 'position-actions:v1:2632500';

test('unsigned production catalogs reproduce all supported recipes from the recorded deployment evidence', async () => {
  const actual = await importPositionPolicyDescriptors(fileURLToPath(new URL('../catalog/', import.meta.url)), { ...chains, 1: {} });
  const evidence = JSON.parse(await fs.readFile(new URL('../evidence/position-actions-v1.json', import.meta.url), 'utf8'));
  const { policies } = createInitialPositionActionPolicyCatalog(evidence.deployments);
  assert.deepEqual(actual.map(row => row.scope).sort(), ['position-actions:v1:1', scope]);
  for (const [id, count] of [[1, 4], [chainId, 29]]) {
    const perChain = policies.filter(policy => policy.chainId === id);
    assert.equal(perChain.length, count);
    assert.deepEqual(actual.find(row => row.scope === `position-actions:v1:${id}`),
      { kind: 'descriptor', scope: `position-actions:v1:${id}`, payload: { schemaVersion: 1, policies: perChain } });
  }
});

test('reserved scopes require the exact kind, chain, version and shared parser', () => {
  validatePositionPolicyDescriptor({ kind: 'descriptor', scope, payload: empty });
  for (const tail of ['01', '0', '-1', '1e2', '1:extra', '9007199254740992', '1\n']) {
    assert.throws(() => validatePositionPolicyDescriptor({ kind: 'descriptor', scope: 'position-actions:v1:' + tail, payload: empty }));
  }
  assert.throws(() => validatePositionPolicyDescriptor({ kind: 'descriptor', scope: 'position-actions:v2:1', payload: empty }));
  assert.throws(() => validatePositionPolicyDescriptor({ kind: 'networks', scope, payload: empty }));
  for (const payload of [{ ...empty, extra: true }, { ...empty, schemaVersion: 2 }, { ...empty, policies: [{}] }, { display: {} }]) {
    assert.throws(() => validatePositionPolicyDescriptor({ kind: 'descriptor', scope, payload }));
  }
});

test('registry scopes are derived only from deployment and selector; curated files cannot alias a chain', async t => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'position-descriptors-'));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  const owner = path.join(dir, 'registry', 'test');
  await fs.mkdir(owner, { recursive: true });
  const address = '0x' + '11'.repeat(20);
  const doc = { scope, ...empty, context: { contract: { deployments: [{ chainId, address }] } }, display: { formats: { 'transfer(address,uint256)': {} } } };
  const file = path.join(owner, 'calldata-test.json');
  await fs.writeFile(file, JSON.stringify(doc));
  const display = await importDescriptors(dir);
  assert.deepEqual(display.map(row => row.scope), [`${chainId}:${address}:0xa9059cbb`]);
  await fs.writeFile(file, JSON.stringify({ ...doc, context: { contract: { deployments: [{ chainId: 'position-actions:v1', address }] } } }));
  await assert.rejects(importDescriptors(dir));
  assert.deepEqual(await importPositionPolicyDescriptors(dir, chains), []);
  await fs.writeFile(path.join(dir, 'position-actions.02632500.json'), JSON.stringify(empty));
  await assert.rejects(importPositionPolicyDescriptors(dir, chains), /noncanonical/);
  await fs.rename(path.join(dir, 'position-actions.02632500.json'), path.join(dir, 'position-actions.1.json'));
  await assert.rejects(importPositionPolicyDescriptors(dir, chains), /Unknown position policy chain/);
});
