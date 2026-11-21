import test from 'node:test';
import assert from 'node:assert/strict';
import { ZeroAddress } from 'ethers';
import { createInitialPositionActionPolicyCatalog, carbonPositionPolicyId, cipherDexOrderPositionPolicyId,
  cipherDexLiquidityPositionPolicyId, type InitialPositionPolicyDeployments } from './positionPolicyCatalog.ts';
import { evaluatePositionActionPolicy, materializePositionPolicyDescriptor, positionActionPolicyDigest,
  type PositionActionPolicyContext } from './positionActionPolicy.ts';

const address = (byte: string) => '0x' + byte.repeat(20);
const CONTROLLER = address('11'), VOUCHER = address('22'), PUBLIC = address('33'), PRIVATE = address('44'), ROUTER = address('55');
const OWNER = address('66'), TOKEN0 = address('77'), TOKEN1 = address('88'), LP = address('99'), POOL = address('ab');
const HASH = '0x' + 'ab'.repeat(32);
function deployments(): InitialPositionPolicyDeployments {
  return { carbon: [1, 2632500].map(chainId => ({ chainId: chainId as 1 | 2632500, controller: CONTROLLER, voucher: VOUCHER,
    integrity: { [CONTROLLER]: { kind: 'code' as const, codeHash: HASH }, [VOUCHER]: { kind: 'code' as const, codeHash: HASH } } })),
    cipherdex: { chainId: 2632500, publicBook: PUBLIC, privateBook: PRIVATE, liquidityRouter: ROUTER, marketPresentationRevision: 'reviewed-market-v1' } };
}
const state = { baseToken: TOKEN0, quoteToken: TOKEN1, baseDecimals: 18, quoteDecimals: 6, buyBudgetRaw: '100', sellBudgetRaw: '200',
  buyFundMaxRaw: '1000', sellFundMaxRaw: '1000', token0Address: TOKEN0, token1Address: TOKEN1,
  token0Decimals: 18, token1Decimals: 6, lpTokenAddress: LP, availableSharesRaw: '100',
  baseAsset: TOKEN0, quoteAsset: TOKEN1, expiryRaw: '1100', creditKind: 'bounty' };

test('initial unsigned catalog covers current signing actions with explicit per-chain/book/mode ids', () => {
  const catalog = createInitialPositionActionPolicyCatalog(deployments());
  assert.equal(catalog.policies.length, 33);
  const ids = catalog.policies.map(policy => policy.id);
  for (const chain of [1, 2632500]) for (const action of ['update-strategy', 'fund-strategy', 'withdraw-strategy', 'close-strategy']) {
    assert.ok(ids.includes(carbonPositionPolicyId(chain, action)));
  }
  for (const book of ['public', 'private'] as const) for (const action of ['cancel-order', 'amend-order', 'add-reward', 'claim-credit']) {
    assert.ok(ids.includes(cipherDexOrderPositionPolicyId(2632500, book, action)));
  }
  assert.ok(ids.includes(cipherDexOrderPositionPolicyId(2632500, 'private', 'reveal-order')));
  for (const mode of [0, 1, 2, 3] as const) for (const action of ['add-liquidity', 'remove-liquidity', 'claim-fees']) {
    assert.ok(ids.includes(cipherDexLiquidityPositionPolicyId(2632500, mode, action)));
  }
  for (const mode of [1, 2] as const) for (const action of ['reveal-position', 'reveal-accounting']) {
    assert.ok(ids.includes(cipherDexLiquidityPositionPolicyId(2632500, mode, action)));
  }
  assert.equal(ids.some(id => /transfer/.test(id)), false);
  assert.ok(Object.isFrozen(catalog.policies));
});
test('every generated form resolves from declared independent facts and returns only native proof requirements', () => {
  for (const policy of createInitialPositionActionPolicyCatalog(deployments()).policies) {
    const managementAddress = policy.protocolId === 'carbon' ? CONTROLLER
      : policy.execution.kind === 'local' && policy.execution.capability === 'cipherdex-liquidity-v1' ? POOL
        : policy.id.includes('-private-') ? PRIVATE : PUBLIC;
    const partial: PositionActionPolicyContext = { chainId: policy.chainId, protocolId: policy.protocolId, actionId: policy.actionId,
      positionId: 'selected-position', revision: '1', owner: OWNER, recipient: OWNER, managementAddress,
      state, descriptor: {}, parameters: {}, nowSeconds: 1000, expiresAt: 1060,
      limits: { maxNativeValue: '0', spends: [], approvals: [], minimumReceives: [] },
      ...(policy.deployment.kind === 'fixed' ? { deploymentIntegrity: policy.deployment.integrity } : {}) };
    const descriptor = materializePositionPolicyDescriptor(policy, partial);
    const parameters: Record<string, string | boolean> = { ...descriptor.defaults as Record<string, string | boolean> };
    for (const field of descriptor.inputs as Record<string, unknown>[]) parameters[field.key as string] = (field.value ?? field.min ?? false) as string | boolean;
    const c = { ...partial, descriptor, parameters };
    const evaluated = evaluatePositionActionPolicy(policy, c, [{ to: managementAddress, data: '0x12345678', value: '0' }]);
    assert.equal(evaluated.status, 'requires-local-validation', policy.id);
    assert.equal(descriptor.policyId, policy.id);
    assert.equal(descriptor.id, policy.actionId);
  }
});
test('book and liquidity mode variants retain fixed execution/preview/target and amount semantics', () => {
  const catalog = createInitialPositionActionPolicyCatalog(deployments());
  const find = (id: string) => catalog.policies.find(policy => policy.id === id)!;
  for (const mode of [0, 1, 2, 3] as const) {
    const add = find(cipherDexLiquidityPositionPolicyId(2632500, mode, 'add-liquidity'));
    assert.equal(add.descriptor.execution, mode === 0 ? 'api' : 'local');
    assert.equal(add.descriptor.preview, mode === 0 ? 'api' : 'local');
    assert.deepEqual(add.deployment, { kind: 'local', capability: 'cipherdex-deployment-v1', scope: { kind: 'liquidity', mode } });
    assert.deepEqual(add.descriptor.targets, [mode === 0 ? ROUTER : { source: 'context', key: 'managementAddress' }]);
    const remove = find(cipherDexLiquidityPositionPolicyId(2632500, mode, 'remove-liquidity'));
    assert.equal(remove.descriptor.requiresLocalAmounts, mode === 1 || mode === 2);
    assert.equal(remove.execution.kind, 'local');
  }
  const pub = find(cipherDexOrderPositionPolicyId(2632500, 'public', 'amend-order'));
  const priv = find(cipherDexOrderPositionPolicyId(2632500, 'private', 'amend-order'));
  assert.deepEqual(pub.descriptor.defaults, { marketPresentationRevision: 'reviewed-market-v1' });
  assert.deepEqual(priv.descriptor.defaults, {});
  assert.deepEqual(pub.deployment, { kind: 'local', capability: 'cipherdex-deployment-v1', scope: { kind: 'order', book: 'public' } });
  assert.deepEqual(priv.deployment, { kind: 'local', capability: 'cipherdex-deployment-v1', scope: { kind: 'order', book: 'private' } });
  assert.notEqual(positionActionPolicyDigest(pub), positionActionPolicyDigest(priv));
});

test('private reveal forms preserve existing local SDK workflows only for modes 1 and 2', () => {
  const catalog = createInitialPositionActionPolicyCatalog(deployments());
  for (const mode of [0, 1, 2, 3] as const) for (const action of ['reveal-position', 'reveal-accounting']) {
    const policy = catalog.policies.find(policy => policy.id === cipherDexLiquidityPositionPolicyId(2632500, mode, action));
    if (mode === 0 || mode === 3) { assert.equal(policy, undefined); continue; }
    assert.ok(policy);
    assert.deepEqual(policy.execution, { kind: 'local', capability: 'cipherdex-liquidity-v1' });
    assert.deepEqual(policy.deployment, { kind: 'local', capability: 'cipherdex-deployment-v1', scope: { kind: 'liquidity', mode } });
    assert.deepEqual(policy.descriptor, { execution: 'local', family: 'reveal',
      label: action === 'reveal-position' ? 'Reveal' : 'Accounting', title: action === 'reveal-position' ? 'Reveal position' : 'Reveal accounting',
      icon: action === 'reveal-position' ? 'eye' : 'refresh', group: 'read', order: action === 'reveal-position' ? 0 : 1,
      inputs: [], defaults: {}, spend: [] });
  }
});

test('public market revision is required reviewed input, digest-bound and never taken from runtime state', () => {
  const find = (input: InitialPositionPolicyDeployments) => createInitialPositionActionPolicyCatalog(input).policies
    .find(policy => policy.id === cipherDexOrderPositionPolicyId(2632500, 'public', 'amend-order'))!;
  const input = deployments(), policy = find(input);
  const partial: PositionActionPolicyContext = { chainId: 2632500, protocolId: 'cipherdex', actionId: 'amend-order',
    positionId: 'selected-position', revision: '1', owner: OWNER, recipient: OWNER, managementAddress: PUBLIC,
    state: { ...state, marketPresentationRevision: 'untrusted-api-revision' }, descriptor: {},
    parameters: { limitPrice: '1', expiryRaw: '1100', marketPresentationRevision: 'reviewed-market-v1' },
    nowSeconds: 1000, expiresAt: 1060, limits: { maxNativeValue: '0', spends: [], approvals: [], minimumReceives: [] } };
  const descriptor = materializePositionPolicyDescriptor(policy, partial);
  assert.deepEqual(descriptor.defaults, { marketPresentationRevision: 'reviewed-market-v1' });
  assert.equal((descriptor.inputs as Record<string, unknown>[]).some(field => Object.hasOwn(field, 'value')), false);
  const calls = [{ to: PUBLIC, data: '0x12345678', value: '0' }];
  assert.equal(evaluatePositionActionPolicy(policy, { ...partial, descriptor }, calls).status, 'requires-local-validation');
  assert.throws(() => evaluatePositionActionPolicy(policy, { ...partial, descriptor,
    parameters: { ...partial.parameters, marketPresentationRevision: 'untrusted-api-revision' } }, calls), /constant changed/);
  input.cipherdex!.marketPresentationRevision = 'reviewed-market-v2';
  assert.notEqual(positionActionPolicyDigest(find(input)), positionActionPolicyDigest(policy));
  for (const revision of ['', ' ', 'revision\n', 'a'.repeat(257), '\u202erevision']) {
    input.cipherdex!.marketPresentationRevision = revision;
    assert.throws(() => createInitialPositionActionPolicyCatalog(input), /reviewed market presentation revision/);
  }
  const { marketPresentationRevision: _, ...missing } = deployments().cipherdex!;
  assert.throws(() => createInitialPositionActionPolicyCatalog({ carbon: [], cipherdex: missing } as InitialPositionPolicyDeployments), /reviewed market presentation revision/);
});
test('generation fails without explicit real integrity input and never manufactures pins', () => {
  const input = deployments(); input.carbon[0]!.integrity = {};
  assert.throws(() => createInitialPositionActionPolicyCatalog(input), /integrity/);
  const zero = deployments(); zero.carbon[0]!.controller = ZeroAddress;
  assert.throws(() => createInitialPositionActionPolicyCatalog(zero));
  const duplicate = deployments(); duplicate.carbon = [duplicate.carbon[0]!, duplicate.carbon[0]!];
  assert.throws(() => createInitialPositionActionPolicyCatalog(duplicate), /duplicate/);
  const emptyCode = deployments(); emptyCode.carbon[0]!.integrity = { [CONTROLLER]: { kind: 'code', codeHash: '0x' + '00'.repeat(32) },
    [VOUCHER]: { kind: 'code', codeHash: HASH } };
  assert.throws(() => createInitialPositionActionPolicyCatalog(emptyCode), /empty deployment/);
  assert.deepEqual(createInitialPositionActionPolicyCatalog({ carbon: [] }).policies, []);
});
test('Carbon fixed roots and independent form asset bindings cannot be replaced by the API', () => {
  const policy = createInitialPositionActionPolicyCatalog(deployments()).policies.find(policy => policy.id === carbonPositionPolicyId(1, 'fund-strategy'))!;
  assert.equal(policy.deployment.kind, 'fixed');
  if (policy.deployment.kind !== 'fixed') assert.fail();
  assert.deepEqual(policy.deployment.contracts, { controller: CONTROLLER, voucher: VOUCHER });
  const context = { owner: OWNER, recipient: OWNER, managementAddress: CONTROLLER, positionId: 'position', revision: '1', state };
  const form = materializePositionPolicyDescriptor(policy, context);
  const fields = form.inputs as { asset: string; decimals: number }[];
  assert.deepEqual(fields.map(field => [field.asset, field.decimals]), [[TOKEN1, 6], [TOKEN0, 18]]);
  assert.throws(() => materializePositionPolicyDescriptor(policy, { ...context, state: {} }), /missing state binding/);
});
