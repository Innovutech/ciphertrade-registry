import test from 'node:test';
import assert from 'node:assert/strict';
import { Interface, ZeroAddress } from 'ethers';
import { canonicalPositionPolicyJson, evaluatePositionActionPolicy, materializePositionPolicyDescriptor,
  parsePositionActionPolicy, parsePositionActionPolicyCatalog, positionActionPolicyDigest,
  type PositionActionPolicy, type PositionActionPolicyContext, type PositionPolicyCallRule, type PositionPolicyTransaction } from './positionActionPolicy.ts';

const OWNER = '0x' + '11'.repeat(20), TOKEN = '0x' + '22'.repeat(20), TARGET = '0x' + '33'.repeat(20);
const SHARE = '0x' + '44'.repeat(20), OTHER = '0x' + '55'.repeat(20);
const CODE_HASH = '0x' + 'aa'.repeat(32);
const input = (key: string) => ({ source: 'input' as const, key });
const state = (key: string) => ({ source: 'state' as const, key });
const context = (key: string) => ({ source: 'context' as const, key });
const method = 'deposit(uint256,uint256,uint256,address,uint64)';
const abi = new Interface(['function ' + method]), erc20 = new Interface(['function approve(address,uint256)']);
function policy(): PositionActionPolicy {
  return { schemaVersion: 1, id: 'simple-deposit-v1', chainId: 1, protocolId: 'simple', actionId: 'deposit',
    descriptor: { execution: 'api', family: 'fund', label: 'Deposit', title: 'Deposit tokens', icon: 'add', group: 'funds', order: 10,
      inputs: [
        { key: 'amount', label: 'Amount', type: 'amount', asset: state('token'), decimals: state('decimals'), min: '1', max: '1000' },
        { key: 'minimum', label: 'Minimum shares', type: 'amount', asset: state('share'), decimals: 18, min: '1', max: '1000' },
        { key: 'deadline', label: 'Deadline', type: 'timestamp', min: '1', max: '9999999', allowNoExpiry: false },
      ], defaults: { positionIdRaw: '7' }, spend: [{ asset: state('token'), amountField: 'amount' }] },
    deployment: { kind: 'fixed', addresses: [TARGET], contracts: {}, integrity: { [TARGET]: { kind: 'code', codeHash: CODE_HASH } } }, execution: { kind: 'calls', sequence: [
      { kind: 'erc20-approval', asset: state('token'), spender: context('managementAddress'), amount: '0' },
      { kind: 'erc20-approval', asset: state('token'), spender: context('managementAddress'), amount: input('amount') },
      { kind: 'call', target: context('managementAddress'), method,
        args: [input('positionIdRaw'), input('amount'), input('minimum'), context('recipient'), input('deadline')], value: '0',
        recipient: { kind: 'argument', path: [3] }, spends: [{ asset: state('token'), amount: [1] }],
        minimumReceives: [{ asset: state('share'), amount: [2] }], deadline: { path: [4], maxDelaySeconds: 600 } },
    ] } };
}
function fixture(p = policy()): { p: PositionActionPolicy; c: PositionActionPolicyContext; calls: { -readonly [K in keyof PositionPolicyTransaction]: PositionPolicyTransaction[K] }[] } {
  const c: PositionActionPolicyContext = { chainId: 1, protocolId: p.protocolId, actionId: p.actionId, positionId: 'position:7', revision: '8',
    owner: OWNER, recipient: OWNER, managementAddress: TARGET, descriptor: {},
    parameters: { amount: '10', minimum: '9', deadline: '1100', positionIdRaw: '7' },
    state: { token: TOKEN, share: SHARE, decimals: 18 }, nowSeconds: 1000, expiresAt: 1060,
    ...(p.deployment.kind === 'fixed' ? { deploymentIntegrity: structuredClone(p.deployment.integrity) } : {}),
    limits: { maxNativeValue: '0', spends: [{ asset: TOKEN, amountRaw: '10' }],
      approvals: [{ asset: TOKEN, spender: TARGET, amountRaw: '10' }], minimumReceives: [{ asset: SHARE, amountRaw: '9' }] } };
  const calls = [{ to: TOKEN, value: '0', data: erc20.encodeFunctionData('approve', [TARGET, 0]) },
    { to: TOKEN, value: '0', data: erc20.encodeFunctionData('approve', [TARGET, 10]) },
    { to: TARGET, value: '0', data: abi.encodeFunctionData(method, [7, 10, 9, OWNER, 1100]) }];
  return { p, c: { ...c, descriptor: materializePositionPolicyDescriptor(p, c) }, calls };
}
function operation(p: PositionActionPolicy): PositionPolicyCallRule {
  assert.equal(p.execution.kind, 'calls');
  return (p.execution as { sequence: PositionPolicyCallRule[] }).sequence.at(-1)!;
}
function run(f = fixture()) { return evaluatePositionActionPolicy(f.p, f.c, f.calls); }
test('generic selected scalar arguments, exact approvals, receipt and deadline authorize canonical calls', () => {
  const f = fixture(), result = run(f);
  assert.equal(result.status, 'authorized');
  if (result.status !== 'authorized') assert.fail();
  assert.deepEqual(result.spends, [{ asset: TOKEN, amountRaw: '10' }]);
  assert.deepEqual(result.approvals, [{ asset: TOKEN, spender: TARGET, amountRaw: '10' }]);
  assert.deepEqual(result.minimumReceives, [{ asset: SHARE, amountRaw: '9' }]);
  assert.equal(result.policyDigest, positionActionPolicyDigest(f.p));
  assert.ok(Object.isFrozen(result.spends));
  assert.equal((f.c.descriptor as { policyId: string }).policyId, f.p.id);
});
test('policy/catalog parser is strict, bounded, detached and versioned', () => {
  const p = policy(), parsed = parsePositionActionPolicy(p);
  p.descriptor.label = 'Spoof'; assert.equal(parsed.descriptor.label, 'Deposit');
  assert.ok(Object.isFrozen(parsed.descriptor.inputs[0]));
  for (const patch of [{ schemaVersion: 2 }, { unknown: true }, { execution: { kind: 'eval', code: 'true' } },
    { execution: { kind: 'local', capability: 'carbon-strategy-v2' } }, { deployment: { kind: 'factory', address: TARGET } }]) {
    assert.throws(() => parsePositionActionPolicy({ ...policy(), ...patch }));
  }
  assert.throws(() => parsePositionActionPolicyCatalog({ schemaVersion: 1, policies: [policy(), policy()] }));
  assert.equal(parsePositionActionPolicyCatalog({ schemaVersion: 1, policies: [policy(), { ...policy(), id: 'second-mode' }] }).policies.length, 2);
  assert.deepEqual(parsePositionActionPolicyCatalog({ schemaVersion: 1, policies: [] }).policies, []);
  const long = policy(); operation(long).args = [Array.from({ length: 17 }, () => '0')];
  assert.throws(() => parsePositionActionPolicy(long));
});
test('canonical serializer rejects accessors, cycles, hidden keys and non-JSON scalars', () => {
  let touched = false;
  const getter = Object.defineProperty({}, 'foo', { enumerable: true, get() { touched = true; return 1; } });
  const list = Object.defineProperty([1], '0', { get() { touched = true; return 1; } });
  const cycle: unknown[] = []; cycle.push(cycle);
  for (const value of [getter, list, cycle, new Date(), { x: undefined }, { x: 1n }, [,], { x: -1 }, { [Symbol()]: 1 }]) {
    assert.throws(() => canonicalPositionPolicyJson(value));
  }
  assert.equal(touched, false);
  assert.equal(canonicalPositionPolicyJson({ b: 2, a: 1 }), '{"a":1,"b":2}');
});
test('form labels, policy reference, assets, decimals, defaults, units and unknown fields are binding', () => {
  for (const mutate of [
    (d: any) => { d.label = 'Claim free tokens'; }, (d: any) => { d.policyId = 'other'; },
    (d: any) => { d.inputs[0].asset = OTHER; }, (d: any) => { d.inputs[0].decimals = 6; },
    (d: any) => { d.inputs[0].label = 'Claim'; }, (d: any) => { d.defaults.positionIdRaw = '8'; },
    (d: any) => { d.inputs[0].unknown = true; }, (d: any) => { d.inputs[0].type = 'bytes'; },
    (d: any) => { d.spend[0].asset = OTHER; }, (d: any) => { d.targets = [OTHER]; },
    (d: any) => { d.enabled = false; },
  ]) {
    const f = fixture(), descriptor = structuredClone(f.c.descriptor); mutate(descriptor);
    assert.throws(() => run({ ...f, c: { ...f.c, descriptor } }), /descriptor/);
  }
});
test('all canonical ABI words and transaction identities are enforced, not just selector', () => {
  for (const args of [[8, 10, 9, OWNER, 1100], [7, 11, 9, OWNER, 1100], [7, 10, 8, OWNER, 1100],
    [7, 10, 9, OTHER, 1100], [7, 10, 9, OWNER, 1101]]) {
    const f = fixture(); f.calls[2]!.data = abi.encodeFunctionData(method, args); assert.throws(() => run(f), /calldata/);
  }
  for (const patch of [{ to: OTHER }, { value: '1' }, { from: OTHER }, { chainId: 2 }, { data: '0x12345678' }, { delegatecall: true }]) {
    const f = fixture(); Object.assign(f.calls[2]!, patch); assert.throws(() => run(f));
  }
  const f = fixture(); f.calls[2]!.data += '00'.repeat(32); assert.throws(() => run(f), /calldata/);
  const padding = fixture(); padding.calls[2]!.data = padding.calls[2]!.data.slice(0, 10 + 4 * 64) + '01' + padding.calls[2]!.data.slice(12 + 4 * 64);
  assert.throws(() => run(padding), /calldata/);
});
test('approval spender, token, amount, order, repeats and missing/extra sequence members reject', () => {
  for (const [spender, amount] of [[OTHER, '10'], [TARGET, ((1n << 256n) - 1n).toString()], [TARGET, '11']] as const) {
    const f = fixture(); f.calls[1]!.data = erc20.encodeFunctionData('approve', [spender, amount]); assert.throws(() => run(f));
  }
  const target = fixture(); target.calls[1]!.to = OTHER; assert.throws(() => run(target));
  const missing = fixture(); missing.calls.shift(); assert.throws(() => run(missing), /sequence/);
  const extra = fixture(); extra.calls.push(extra.calls[2]!); assert.throws(() => run(extra), /sequence/);
  const order = fixture(); order.calls.reverse(); assert.throws(() => run(order));
  const repeat = fixture();
  if (repeat.p.execution.kind !== 'calls') assert.fail();
  repeat.p.execution.sequence.splice(2, 0, repeat.p.execution.sequence[1]!); repeat.calls.splice(2, 0, repeat.calls[1]!);
  assert.throws(() => run(repeat), /repeated approval/);
});
test('cumulative token/native and independent approval/minimum limits are checked', () => {
  const f = fixture();
  if (f.p.execution.kind !== 'calls') assert.fail();
  f.p.execution.sequence.push(operation(f.p)); f.calls.push(f.calls[2]!);
  assert.throws(() => run(f), /cumulative token/);
  for (const limits of [
    { ...fixture().c.limits, spends: [{ asset: TOKEN, amountRaw: '9' }] },
    { ...fixture().c.limits, approvals: [{ asset: TOKEN, spender: TARGET, amountRaw: '9' }] },
    { ...fixture().c.limits, minimumReceives: [{ asset: SHARE, amountRaw: '10' }] },
  ]) { const f = fixture(); assert.throws(() => run({ ...f, c: { ...f.c, limits } })); }
  const p = policy(); p.descriptor.inputs.push({ key: 'nativeAmount', label: 'Native amount', type: 'amount', asset: ZeroAddress, decimals: 18, min: '0', max: '10' });
  p.descriptor.spend.push({ asset: ZeroAddress, amountField: 'nativeAmount' }); operation(p).value = '1';
  const n = fixture(p); n.calls[2]!.value = '1';
  const c = { ...n.c, parameters: { ...n.c.parameters, nativeAmount: '1' },
    limits: { ...n.c.limits, maxNativeValue: '1', spends: [...n.c.limits.spends, { asset: ZeroAddress, amountRaw: '1' }] } };
  assert.equal(run({ ...n, c }).status, 'authorized');
  if (n.p.execution.kind !== 'calls') assert.fail();
  n.p.execution.sequence.push(operation(n.p)); n.calls.push(n.calls[2]!);
  assert.throws(() => run({ ...n, c }), /cumulative native/);
});
test('no authority from API effects, missing state, stale context, mismatched identity or input keys', () => {
  for (const patch of [{ state: {} }, { effects: { complete: true } }, { expiresAt: 1000 }, { expiresAt: 1700 },
    { chainId: 2 }, { actionId: 'withdraw' }, { protocolId: 'spoof' }, { managementAddress: OTHER },
    { parameters: { ...fixture().c.parameters, arbitrary: 'x' } },
    { parameters: { ...fixture().c.parameters, positionIdRaw: '8' } }]) {
    const f = fixture(); assert.throws(() => run({ ...f, c: { ...f.c, ...patch } as PositionActionPolicyContext }));
  }
  for (const deadline of ['1000', '1059', '1601']) {
    const f = fixture(); f.calls[2]!.data = abi.encodeFunctionData(method, [7, 10, 9, OWNER, deadline]);
    assert.throws(() => run({ ...f, c: { ...f.c, parameters: { ...f.c.parameters, deadline } } }), /deadline/);
  }
});
test('bounded static tuples/fixed arrays work, arbitrary bytes and dynamic arrays do not', () => {
  const p = policy(), rule = operation(p);
  rule.method = 'deposit((uint256,uint256,uint256,address,uint64)[1])'; rule.args = [[rule.args]];
  rule.recipient = { kind: 'argument', path: [0, 0, 3] }; rule.spends[0]!.amount = [0, 0, 1];
  rule.minimumReceives[0]!.amount = [0, 0, 2]; rule.deadline!.path = [0, 0, 4];
  const f = fixture(p); f.calls[2]!.data = new Interface(['function ' + rule.method]).encodeFunctionData(rule.method, [[[7, 10, 9, OWNER, 1100]]]);
  assert.equal(run(f).status, 'authorized');
  for (const signature of ['execute(bytes)', 'multicall(bytes[])', 'deposit((uint256,bytes))', 'deposit(uint256[])',
    'deposit(uint256[17])', 'deposit(string)', 'deposit(int256)', 'approve(address,uint256)', 'deposit(uint)']) {
    const p = policy(); operation(p).method = signature; assert.throws(() => parsePositionActionPolicy(p));
  }
});
test('native capabilities yield a commitment request, never permission or an API-complete bypass', () => {
  for (const capability of ['carbon-strategy-v1', 'cipherdex-order-v1', 'cipherdex-liquidity-v1'] as const) {
    const p = policy(); p.protocolId = capability === 'carbon-strategy-v1' ? 'carbon' : 'cipherdex';
    p.execution = { kind: 'local', capability };
    if (capability !== 'carbon-strategy-v1') p.deployment = { kind: 'local', capability: 'cipherdex-deployment-v1',
      scope: capability === 'cipherdex-order-v1' ? { kind: 'order', book: 'public' } : { kind: 'liquidity', mode: 0 } };
    const f = fixture(p), result = run(f); assert.equal(result.status, 'requires-local-validation');
    assert.equal(Object.hasOwn(result, 'complete'), false);
    f.calls[2]!.data = '0x12345678'; const changed = run(f);
    assert.equal(changed.status, 'requires-local-validation'); assert.notEqual(result.transactionsDigest, changed.transactionsDigest);
    assert.throws(() => parsePositionActionPolicy({ ...p, execution: { ...p.execution, complete: true } }));
  }
  const p = policy(); p.deployment = { kind: 'local', capability: 'cipherdex-deployment-v1', scope: { kind: 'order', book: 'public' } };
  assert.throws(() => parsePositionActionPolicy(p), /fixed/);
});

test('local scope is mandatory, strict, capability-specific and included in the signed digest', () => {
  const p = policy(); p.protocolId = 'cipherdex'; p.execution = { kind: 'local', capability: 'cipherdex-liquidity-v1' };
  p.deployment = { kind: 'local', capability: 'cipherdex-deployment-v1', scope: { kind: 'liquidity', mode: 1 } };
  const original = positionActionPolicyDigest(p);
  p.deployment.scope = { kind: 'liquidity', mode: 2 };
  assert.notEqual(positionActionPolicyDigest(p), original);
  assert.equal(run(fixture(p)).status, 'requires-local-validation');
  const missingScope = { kind: 'local', capability: 'cipherdex-deployment-v1' };
  assert.throws(() => parsePositionActionPolicy({ ...p, deployment: missingScope }));
  for (const scope of [{ kind: 'liquidity', mode: 4 }, { kind: 'liquidity', mode: -1 }, { kind: 'liquidity', mode: '1' },
    { kind: 'liquidity', mode: 1.5 }, { kind: 'liquidity', mode: 1, book: 'private' }, { kind: 'future', mode: 1 },
    { kind: 'order', book: 'public' }, { kind: 'order', book: 'other' }]) {
    assert.throws(() => parsePositionActionPolicy({ ...p, deployment: { ...missingScope, scope } }));
  }
  p.execution = { kind: 'local', capability: 'cipherdex-order-v1' };
  assert.throws(() => parsePositionActionPolicy(p), /scope mismatch/);
  p.deployment.scope = { kind: 'order', book: 'public' };
  const publicDigest = positionActionPolicyDigest(p);
  p.deployment.scope = { kind: 'order', book: 'private' };
  assert.notEqual(positionActionPolicyDigest(p), publicDigest);
  p.deployment = policy().deployment;
  assert.throws(() => parsePositionActionPolicy(p), /scope mismatch/);
});

test('every fixed root pins code or proxy implementation and requires independent observed integrity', () => {
  const p = policy();
  if (p.deployment.kind !== 'fixed') assert.fail();
  p.deployment.integrity[TARGET] = { kind: 'eip1967', proxyCodeHash: CODE_HASH, implementation: OTHER, implementationCodeHash: '0x' + 'bb'.repeat(32) };
  assert.equal(run(fixture(p)).status, 'authorized');
  for (const deploymentIntegrity of [{}, { [TARGET]: { kind: 'code', codeHash: CODE_HASH } },
    { [TARGET]: { ...p.deployment.integrity[TARGET], implementation: TOKEN } },
    { [TARGET]: { ...p.deployment.integrity[TARGET], implementationCodeHash: CODE_HASH } }]) {
    const f = fixture(p); assert.throws(() => run({ ...f, c: { ...f.c, deploymentIntegrity } as PositionActionPolicyContext }));
  }
  const f = fixture(p), { deploymentIntegrity: _, ...missing } = f.c;
  assert.throws(() => run({ ...f, c: missing }));
  p.deployment.contracts.voucher = SHARE; assert.throws(() => parsePositionActionPolicy(p), /cover every fixed root/);
  delete p.deployment.contracts.voucher;
  p.deployment.integrity[TARGET] = { kind: 'code', codeHash: '0x' + '00'.repeat(32) }; assert.throws(() => parsePositionActionPolicy(p), /empty deployment/);
});
