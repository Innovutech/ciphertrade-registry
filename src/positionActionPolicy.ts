import { FunctionFragment, Interface, ZeroAddress, getAddress, keccak256, toUtf8Bytes, type ParamType } from 'ethers';

/** This module verifies policy structure and calldata, NOT publication signatures.
 * Only a separately verified publication may supply a policy to the signing gateway.
 * Context is constructed by that gateway from user selection and independent local/RPC
 * validation. API descriptors, effects, state claims and booleans are not authority. */
export const POSITION_ACTION_POLICY_VERSION = 1 as const;
export const POSITION_ACTION_POLICY_CAPABILITIES = Object.freeze([
  'static-abi-v1', 'erc20-approval-v1', 'cipherdex-order-v1', 'cipherdex-liquidity-v1', 'carbon-strategy-v1',
] as const);
export type PositionPolicyCapability = 'cipherdex-order-v1' | 'cipherdex-liquidity-v1' | 'carbon-strategy-v1';
export type PositionPolicyScalar = string | number | boolean;
export type PositionPolicyBinding = { source: 'input' | 'state' | 'context'; key: string };
export type PositionPolicyValue = PositionPolicyScalar | PositionPolicyBinding;
export type PositionPolicyArgument = PositionPolicyValue | PositionPolicyArgument[];
export type PositionPolicyPath = number[];
type FieldBase = { key: string; label: string; value?: PositionPolicyValue };
export type PositionPolicyInput = FieldBase & (
  | { type: 'amount'; asset: PositionPolicyValue; decimals: PositionPolicyValue; min: PositionPolicyValue; max: PositionPolicyValue; display?: 'percentage' }
  | { type: 'decimal'; decimals: PositionPolicyValue; min: PositionPolicyValue; max: PositionPolicyValue; unit?: { baseAsset: PositionPolicyValue; quoteAsset: PositionPolicyValue } }
  | { type: 'timestamp'; min: PositionPolicyValue; max: PositionPolicyValue; allowNoExpiry: boolean }
  | { type: 'choice'; options: { value: string; label: string }[] }
  | { type: 'boolean' }
);
export type PositionPolicyDescriptor = {
  execution: 'api' | 'local' | 'transfer'; family: 'reveal' | 'claim' | 'cancel' | 'update' | 'fund' | 'withdraw' | 'transfer' | 'tip';
  label: string; title: string; icon: 'eye' | 'refresh' | 'download' | 'close' | 'edit' | 'add' | 'send';
  group: 'read' | 'manage' | 'funds'; order: number; inputs: PositionPolicyInput[];
  defaults: Record<string, PositionPolicyValue>; spend: { asset: PositionPolicyValue; amountField: string }[];
  preview?: 'api' | 'local'; requiresLocalAmounts?: boolean; targets?: PositionPolicyValue[];
};
export type PositionPolicyDeployment =
  | { kind: 'fixed'; addresses: string[]; contracts: Record<string, string>; integrity: Record<string, PositionPolicyIntegrity> }
  // Factory membership and existing hardcoded deployment roots remain the local
  // CipherDEX validator's responsibility; this never authorizes generic calls.
  | { kind: 'local'; capability: 'cipherdex-deployment-v1'; scope: PositionPolicyLocalScope };
export type PositionPolicyLocalScope =
  | { kind: 'order'; book: 'public' | 'private' }
  | { kind: 'liquidity'; mode: 0 | 1 | 2 | 3 };
export type PositionPolicyIntegrity =
  | { kind: 'code'; codeHash: string }
  | { kind: 'eip1967'; proxyCodeHash: string; implementation: string; implementationCodeHash: string };
export type PositionPolicyCallRule = {
  kind: 'call'; target: PositionPolicyValue; method: string; args: PositionPolicyArgument[]; value: PositionPolicyValue;
  recipient: { kind: 'sender' } | { kind: 'argument'; path: PositionPolicyPath };
  spends: { asset: PositionPolicyValue; amount: PositionPolicyPath }[];
  minimumReceives: { asset: PositionPolicyValue; amount: PositionPolicyPath }[];
  deadline: null | { path: PositionPolicyPath; maxDelaySeconds: number };
};
export type PositionPolicyApprovalRule = {
  kind: 'erc20-approval'; asset: PositionPolicyValue; spender: PositionPolicyValue; amount: PositionPolicyValue;
};
export type PositionActionPolicy = {
  schemaVersion: 1; id: string; chainId: number; protocolId: string; actionId: string;
  descriptor: PositionPolicyDescriptor; deployment: PositionPolicyDeployment;
  execution: { kind: 'calls'; sequence: (PositionPolicyCallRule | PositionPolicyApprovalRule)[] }
    | { kind: 'local'; capability: PositionPolicyCapability };
};
export type PositionActionPolicyCatalog = { schemaVersion: 1; policies: PositionActionPolicy[] };
export type PositionPolicyTransaction = Readonly<{ to: string; data: string; value: string; label?: string; from?: string; chainId?: number }>;
export type PositionPolicyAmount = Readonly<{ asset: string; amountRaw: string }>;
export type PositionPolicyApproval = Readonly<{ asset: string; spender: string; amountRaw: string }>;
export type PositionActionPolicyContext = Readonly<{
  chainId: number; protocolId: string; actionId: string; positionId: string; revision: string;
  owner: string; recipient: string; managementAddress: string;
  descriptor: unknown; parameters: Readonly<Record<string, string | boolean>>;
  /** Flat typed values obtained independently, never copied from plan.effects. */
  state: Readonly<Record<string, PositionPolicyScalar>>;
  /** Same-block observed code/storage identities from the trusted runtime reader. */
  deploymentIntegrity?: Readonly<Record<string, PositionPolicyIntegrity>>;
  limits: Readonly<{ maxNativeValue: string; spends: readonly PositionPolicyAmount[];
    approvals: readonly PositionPolicyApproval[]; minimumReceives: readonly PositionPolicyAmount[] }>;
  nowSeconds: number; expiresAt: number;
}>;
type EvaluationCommitments = Readonly<{
  policyDigest: string; contextDigest: string; transactionsDigest: string; expiresAt: number; nativeValue: string;
}>;
export type PositionPolicyEvaluation = EvaluationCommitments & (
  | Readonly<{ status: 'authorized'; spends: readonly PositionPolicyAmount[]; approvals: readonly PositionPolicyApproval[];
    minimumReceives: readonly PositionPolicyAmount[] }>
  | Readonly<{ status: 'requires-local-validation'; capability: PositionPolicyCapability }>
);

const UINT_MAX = (1n << 256n) - 1n;
const MAX_JSON_NODES = 32768;
const MAX_JSON_BYTES = 1048576;
const MAX_CALLS = 16;
const CONTEXT_KEYS = ['owner', 'recipient', 'managementAddress', 'positionId', 'revision'] as const;
const bad = (reason: string): never => { throw new Error(`Position policy: ${reason}`); };
function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) bad('invalid object');
  return value as Record<string, unknown>;
}
function keys(value: Record<string, unknown>, required: readonly string[], optional: readonly string[] = []): void {
  if (required.some(key => !Object.hasOwn(value, key)) || Object.keys(value).some(key => !required.includes(key) && !optional.includes(key))) bad('unknown or missing field');
}
function array(value: unknown, max: number): unknown[] {
  if (!Array.isArray(value) || value.length > max) bad('list exceeds bound');
  return value as unknown[];
}
function integer(value: unknown, max: number, min = 0): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < min || value > max) bad('invalid integer');
  return value as number;
}
function text(value: unknown, max = 160): string {
  if (typeof value !== 'string' || !value.trim() || value.length > max || /[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/.test(value)) bad('invalid text');
  return value as string;
}
function identifier(value: unknown): string {
  const result = text(value, 80);
  if (!/^[a-z][a-zA-Z0-9_-]*$/.test(result) || ['__proto__', 'constructor', 'prototype'].includes(result)) bad('invalid identifier');
  return result;
}
function choice<T extends string>(value: unknown, choices: readonly T[]): T {
  if (!choices.includes(value as T)) bad('unsupported primitive or version');
  return value as T;
}
function boolean(value: unknown): boolean {
  if (typeof value !== 'boolean') bad('invalid boolean');
  return value as boolean;
}
function uint(value: unknown, bits = 256): string {
  if (typeof value !== 'string' || !/^(0|[1-9]\d{0,77})$/.test(value) || BigInt(value) >= 1n << BigInt(bits)) bad('invalid unsigned integer');
  return value as string;
}
function address(value: unknown, nonzero = false): string {
  if (typeof value !== 'string' || !/^0x[\da-fA-F]{40}$/.test(value)) bad('invalid address');
  let result: string;
  try { result = getAddress(value as string).toLowerCase(); } catch { return bad('invalid address checksum'); }
  if (nonzero && result === ZeroAddress) bad('zero deployment address');
  return result;
}
function scalar(value: unknown): PositionPolicyScalar {
  if (typeof value === 'boolean') return value;
  if (typeof value === 'number') return integer(value, Number.MAX_SAFE_INTEGER);
  if (typeof value === 'string' && value.length <= 512 && !/[\u0000-\u001f\u007f]/.test(value)) return value;
  return bad('invalid scalar');
}
function binding(value: unknown, allowInput = true): PositionPolicyValue {
  if (!value || typeof value !== 'object') return scalar(value);
  const row = object(value); keys(row, ['source', 'key']);
  const source = choice(row.source, allowInput ? ['input', 'state', 'context'] : ['state', 'context']);
  const key = identifier(row.key);
  if (source === 'context' && !(CONTEXT_KEYS as readonly string[]).includes(key)) bad('unsupported context binding');
  return { source, key };
}
function map<T>(value: unknown, max: number, parse: (value: unknown) => T): Record<string, T> {
  const row = object(value), entries = Object.entries(row);
  if (entries.length > max) bad('too many bindings');
  return Object.fromEntries(entries.map(([key, value]) => [identifier(key), parse(value)]));
}
function unique(values: readonly string[]): void { if (new Set(values).size !== values.length) bad('duplicate entry'); }
function freeze<T>(value: T): T {
  if (value && typeof value === 'object') { for (const item of Object.values(value)) freeze(item); Object.freeze(value); }
  return value;
}

/** Sorted-key JSON, with no coercion, accessors, cycles, sparse arrays or hidden keys.
 * Bounds apply before ethers parses any ABI or performs hashing. */
export function canonicalPositionPolicyJson(value: unknown): string {
  let count = 0, bytes = 0;
  const visit = (item: unknown, depth: number): string => {
    if (++count > MAX_JSON_NODES || depth > 24) bad('JSON complexity exceeds bound');
    if (item === null || typeof item === 'boolean') return String(item);
    if (typeof item === 'number') return String(integer(item, Number.MAX_SAFE_INTEGER));
    if (typeof item === 'string') {
      bytes += item.length;
      if (item.length > 131074 || bytes > MAX_JSON_BYTES) bad('JSON size exceeds bound');
      return JSON.stringify(item);
    }
    if (Array.isArray(item)) {
      if (item.length > 512 || Reflect.ownKeys(item).length !== item.length + 1) bad('invalid JSON array');
      return '[' + Array.from({ length: item.length }, (_, index) => {
        const entry = Object.getOwnPropertyDescriptor(item, String(index));
        if (!entry || !Object.hasOwn(entry, 'value')) bad('invalid JSON array entry');
        return visit(entry!.value, depth + 1);
      }).join(',') + ']';
    }
    const row = object(item), names = Reflect.ownKeys(row);
    if (names.length > 256 || names.some(key => typeof key !== 'string')) bad('invalid JSON keys');
    return '{' + (names as string[]).sort().map(key => {
      const entry = Object.getOwnPropertyDescriptor(row, key)!;
      if (key.length > 160 || !entry.enumerable || !Object.hasOwn(entry, 'value') || ['__proto__', 'constructor', 'prototype'].includes(key)) bad('invalid JSON property');
      return JSON.stringify(key) + ':' + visit(entry.value, depth + 1);
    }).join(',') + '}';
  };
  const result = visit(value, 0);
  if (result.length > MAX_JSON_BYTES) bad('JSON size exceeds bound');
  return result;
}

function parseField(value: unknown): PositionPolicyInput {
  const row = object(value), type = choice(row.type, ['amount', 'decimal', 'timestamp', 'choice', 'boolean']);
  const required = ['key', 'label', 'type'], optional = ['value'];
  if (type === 'amount') { required.push('asset', 'decimals', 'min', 'max'); optional.push('display'); }
  if (type === 'decimal') { required.push('decimals', 'min', 'max'); optional.push('unit'); }
  if (type === 'timestamp') required.push('min', 'max', 'allowNoExpiry');
  if (type === 'choice') required.push('options');
  keys(row, required, optional);
  const base = { key: identifier(row.key), label: text(row.label, 100),
    ...(row.value === undefined ? {} : { value: binding(row.value, false) }) };
  switch (type) {
    case 'boolean': return { ...base, type };
    case 'choice': {
      const options = array(row.options, 32).map(value => {
        const entry = object(value); keys(entry, ['value', 'label']);
        return { value: text(entry.value, 80), label: text(entry.label, 100) };
      });
      if (!options.length) bad('empty choices'); unique(options.map(option => option.value));
      return { ...base, type, options };
    }
    case 'timestamp': return { ...base, type, min: binding(row.min, false), max: binding(row.max, false), allowNoExpiry: boolean(row.allowNoExpiry) };
    case 'amount': return { ...base, type, min: binding(row.min, false), max: binding(row.max, false),
      asset: binding(row.asset, false), decimals: binding(row.decimals, false),
      ...(row.display === undefined ? {} : { display: choice(row.display, ['percentage'] as const) }) };
    case 'decimal': {
      let unit: { baseAsset: PositionPolicyValue; quoteAsset: PositionPolicyValue } | undefined;
      if (row.unit !== undefined) {
        const entry = object(row.unit); keys(entry, ['baseAsset', 'quoteAsset']);
        unit = { baseAsset: binding(entry.baseAsset, false), quoteAsset: binding(entry.quoteAsset, false) };
      }
      return { ...base, type, min: binding(row.min, false), max: binding(row.max, false), decimals: binding(row.decimals, false), ...(unit ? { unit } : {}) };
    }
  }
}
function parseDescriptor(value: unknown): PositionPolicyDescriptor {
  const row = object(value);
  keys(row, ['execution', 'family', 'label', 'title', 'icon', 'group', 'order', 'inputs', 'defaults', 'spend'], ['preview', 'requiresLocalAmounts', 'targets']);
  const inputs = array(row.inputs, 16).map(parseField), defaults = map(row.defaults, 32, value => binding(value, false));
  unique([...inputs.map(field => field.key), ...Object.keys(defaults)]);
  const spend = array(row.spend, 16).map(value => {
    const entry = object(value); keys(entry, ['asset', 'amountField']);
    const amountField = identifier(entry.amountField), field = inputs.find(field => field.key === amountField);
    if (!field || field.type !== 'amount') bad('spend must bind an amount input');
    return { asset: binding(entry.asset, false), amountField };
  });
  unique(spend.map(entry => entry.amountField));
  const execution = choice(row.execution, ['api', 'local', 'transfer']);
  if (row.preview !== undefined && row.preview !== execution) bad('preview execution mismatch');
  return { execution, family: choice(row.family, ['reveal', 'claim', 'cancel', 'update', 'fund', 'withdraw', 'transfer', 'tip']),
    label: text(row.label, 24), title: text(row.title, 100), icon: choice(row.icon, ['eye', 'refresh', 'download', 'close', 'edit', 'add', 'send']),
    group: choice(row.group, ['read', 'manage', 'funds']), order: integer(row.order, 1000), inputs, defaults, spend,
    ...(row.preview === undefined ? {} : { preview: choice(row.preview, ['api', 'local'] as const) }),
    ...(row.requiresLocalAmounts === undefined ? {} : { requiresLocalAmounts: boolean(row.requiresLocalAmounts) }),
    ...(row.targets === undefined ? {} : { targets: array(row.targets, 16).map(value => binding(value, false)) }) };
}
function parseDeployment(value: unknown): PositionPolicyDeployment {
  const row = object(value);
  if (row.kind === 'local') {
    keys(row, ['kind', 'capability', 'scope']);
    const entry = object(row.scope);
    let scope: PositionPolicyLocalScope;
    if (entry.kind === 'order') {
      keys(entry, ['kind', 'book']); scope = { kind: 'order', book: choice(entry.book, ['public', 'private']) };
    } else {
      keys(entry, ['kind', 'mode']); choice(entry.kind, ['liquidity']);
      scope = { kind: 'liquidity', mode: integer(entry.mode, 3) as 0 | 1 | 2 | 3 };
    }
    return { kind: 'local', capability: choice(row.capability, ['cipherdex-deployment-v1']), scope };
  }
  keys(row, ['kind', 'addresses', 'contracts', 'integrity']); choice(row.kind, ['fixed']);
  const addresses = array(row.addresses, 16).map(value => address(value, true));
  if (!addresses.length) bad('empty deployment'); unique(addresses);
  const contracts = map(row.contracts, 16, value => address(value, true)), integrity = parseIntegrityMap(row.integrity);
  const required = [...new Set([...addresses, ...Object.values(contracts)])].sort();
  if (Object.keys(integrity).sort().join(',') !== required.join(',')) bad('deployment integrity must cover every fixed root');
  return { kind: 'fixed', addresses, contracts, integrity };
}
function codeHash(value: unknown): string {
  if (typeof value !== 'string' || !/^0x[\da-fA-F]{64}$/.test(value)) bad('invalid code hash');
  const hash = (value as string).toLowerCase();
  if (hash === '0x' + '00'.repeat(32) || hash === keccak256('0x')) bad('empty deployment code');
  return hash;
}
function parseIntegrityMap(value: unknown): Record<string, PositionPolicyIntegrity> {
  const entries = Object.entries(object(value));
  if (entries.length > 32) bad('too many deployment integrity roots');
  const result = entries.map(([key, value]): [string, PositionPolicyIntegrity] => {
    const target = address(key, true), row = object(value);
    if (row.kind === 'code') {
      keys(row, ['kind', 'codeHash']); return [target, { kind: 'code', codeHash: codeHash(row.codeHash) }];
    }
    keys(row, ['kind', 'proxyCodeHash', 'implementation', 'implementationCodeHash']); choice(row.kind, ['eip1967']);
    const implementation = address(row.implementation, true);
    if (implementation === target) bad('self-referential proxy implementation');
    return [target, { kind: 'eip1967', proxyCodeHash: codeHash(row.proxyCodeHash), implementation, implementationCodeHash: codeHash(row.implementationCodeHash) }];
  });
  unique(result.map(([target]) => target));
  return Object.fromEntries(result);
}
function argument(value: unknown, depth = 0): PositionPolicyArgument {
  if (depth > 4) bad('argument depth exceeds bound');
  return Array.isArray(value) ? array(value, 16).map(value => argument(value, depth + 1)) : binding(value);
}
function path(value: unknown): PositionPolicyPath {
  const result = array(value, 5).map(value => integer(value, 15));
  if (!result.length) bad('empty argument path'); return result;
}
const forbiddenMethods = new Set([
  'approve(address,uint256)', 'setApprovalForAll(address,bool)', 'transfer(address,uint256)',
  'transferFrom(address,address,uint256)', 'safeTransferFrom(address,address,uint256)',
].map(method => FunctionFragment.from(method).selector));
function method(value: unknown): { fragment: FunctionFragment; abi: Interface } {
  const signature = text(value, 1024);
  // Bound nesting before asking ethers to parse the signature.
  let depth = 0;
  for (const char of signature) { if (char === '(' && ++depth > 5) bad('ABI depth exceeds bound'); if (char === ')' && --depth < 0) bad('invalid ABI'); }
  if (depth !== 0 || !/^[a-zA-Z_][a-zA-Z0-9_]*\([a-zA-Z0-9_,()[\]]*\)$/.test(signature)) bad('noncanonical method');
  let fragment: FunctionFragment;
  try { fragment = FunctionFragment.from(signature); } catch { return bad('invalid method'); }
  if (fragment.format('sighash') !== signature || forbiddenMethods.has(fragment.selector)) bad('unsupported or noncanonical method');
  let leaves = 0;
  const check = (type: ParamType, depth: number): void => {
    if (depth > 4 || ++leaves > 64) bad('ABI complexity exceeds bound');
    if (type.baseType === 'array') {
      const length = type.arrayLength, child = type.arrayChildren;
      if (!length || length < 1 || length > 16 || !child) bad('dynamic or oversized ABI array');
      for (let index = 0; index < length!; index++) check(child!, depth + 1);
    } else if (type.baseType === 'tuple') {
      if (!type.components?.length || type.components.length > 16) bad('invalid ABI tuple');
      type.components!.forEach(child => check(child, depth + 1));
    } else if (!['address', 'bool', 'bytes32'].includes(type.type) && !/^uint(8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|136|144|152|160|168|176|184|192|200|208|216|224|232|240|248|256)$/.test(type.type)) {
      bad('unsupported ABI primitive');
    }
  };
  if (fragment.inputs.length > 16) bad('too many ABI inputs');
  fragment.inputs.forEach(input => check(input, 0));
  return { fragment, abi: new Interface([fragment]) };
}
function typeAt(types: readonly ParamType[], indexes: PositionPolicyPath): ParamType {
  let type: ParamType | undefined;
  for (const [offset, index] of indexes.entries()) {
    if (offset === 0) type = types[index];
    else if (type?.baseType === 'tuple') type = type.components?.[index];
    else if (type?.baseType === 'array' && index < (type.arrayLength ?? 0)) type = type.arrayChildren ?? undefined;
    else type = undefined;
    if (!type) bad('argument path outside ABI');
  }
  return type!;
}
function parseRule(value: unknown): PositionPolicyCallRule | PositionPolicyApprovalRule {
  const row = object(value);
  if (row.kind === 'erc20-approval') {
    keys(row, ['kind', 'asset', 'spender', 'amount']);
    return { kind: 'erc20-approval', asset: binding(row.asset), spender: binding(row.spender), amount: binding(row.amount) };
  }
  keys(row, ['kind', 'target', 'method', 'args', 'value', 'recipient', 'spends', 'minimumReceives', 'deadline']); choice(row.kind, ['call']);
  const { fragment } = method(row.method), args = array(row.args, 16).map(value => argument(value));
  const checkArgs = (type: ParamType, value: PositionPolicyArgument): void => {
    const children = type.baseType === 'tuple' ? type.components : type.baseType === 'array' ? Array.from({ length: type.arrayLength! }, () => type.arrayChildren!) : null;
    if (children) {
      if (!Array.isArray(value) || value.length !== children.length) bad('argument shape differs from ABI');
      children.forEach((child, index) => checkArgs(child, (value as PositionPolicyArgument[])[index]!));
    } else if (Array.isArray(value)) bad('argument shape differs from ABI');
  };
  if (args.length !== fragment.inputs.length) bad('argument count differs from ABI');
  fragment.inputs.forEach((type, index) => checkArgs(type, args[index]!));
  const argumentPath = (value: unknown, expected: 'address' | 'uint') => {
    const result = path(value), type = typeAt(fragment.inputs, result);
    if (expected === 'uint' ? !type.type.startsWith('uint') : type.type !== expected) bad('semantic path has wrong type');
    return result;
  };
  const recipient = object(row.recipient);
  let recipientRule: PositionPolicyCallRule['recipient'];
  if (recipient.kind === 'sender') { keys(recipient, ['kind']); recipientRule = { kind: 'sender' }; }
  else { keys(recipient, ['kind', 'path']); choice(recipient.kind, ['argument']); recipientRule = { kind: 'argument', path: argumentPath(recipient.path, 'address') }; }
  const amounts = (value: unknown) => array(value, 16).map(value => {
    const entry = object(value); keys(entry, ['asset', 'amount']);
    return { asset: binding(entry.asset), amount: argumentPath(entry.amount, 'uint') };
  });
  let deadline: PositionPolicyCallRule['deadline'] = null;
  if (row.deadline !== null) {
    const entry = object(row.deadline); keys(entry, ['path', 'maxDelaySeconds']);
    deadline = { path: argumentPath(entry.path, 'uint'), maxDelaySeconds: integer(entry.maxDelaySeconds, 86400, 1) };
  }
  return { kind: 'call', target: binding(row.target), method: fragment.format('sighash'), args, value: binding(row.value),
    recipient: recipientRule, spends: amounts(row.spends), minimumReceives: amounts(row.minimumReceives), deadline };
}
function parsePolicy(value: unknown): PositionActionPolicy {
  const row = object(value); keys(row, ['schemaVersion', 'id', 'chainId', 'protocolId', 'actionId', 'descriptor', 'deployment', 'execution']);
  if (row.schemaVersion !== 1) bad('unsupported policy version');
  const id = identifier(row.id), chainId = integer(row.chainId, Number.MAX_SAFE_INTEGER, 1), protocolId = identifier(row.protocolId), actionId = identifier(row.actionId);
  const descriptor = parseDescriptor(row.descriptor), deployment = parseDeployment(row.deployment), raw = object(row.execution);
  let execution: PositionActionPolicy['execution'];
  if (raw.kind === 'local') {
    keys(raw, ['kind', 'capability']);
    const capability = choice(raw.capability, ['cipherdex-order-v1', 'cipherdex-liquidity-v1', 'carbon-strategy-v1']);
    if (capability === 'carbon-strategy-v1' ? protocolId !== 'carbon' || deployment.kind !== 'fixed'
      : protocolId !== 'cipherdex') bad('local capability protocol mismatch');
    if (capability !== 'carbon-strategy-v1' && (deployment.kind !== 'local'
      || deployment.scope.kind !== (capability === 'cipherdex-order-v1' ? 'order' : 'liquidity'))) bad('local capability scope mismatch');
    execution = { kind: 'local', capability };
  } else {
    keys(raw, ['kind', 'sequence']); choice(raw.kind, ['calls']);
    if (deployment.kind !== 'fixed') bad('generic calls require fixed reviewed deployment');
    const sequence = array(raw.sequence, MAX_CALLS).map(parseRule);
    if (!sequence.some(rule => rule.kind === 'call')) bad('missing operation');
    execution = { kind: 'calls', sequence };
  }
  return { schemaVersion: 1, id, chainId, protocolId, actionId, descriptor, deployment, execution };
}
export function parsePositionActionPolicy(value: unknown): PositionActionPolicy {
  canonicalPositionPolicyJson(value);
  return freeze(parsePolicy(value));
}
export function parsePositionActionPolicyCatalog(value: unknown): PositionActionPolicyCatalog {
  canonicalPositionPolicyJson(value);
  const row = object(value); keys(row, ['schemaVersion', 'policies']);
  if (row.schemaVersion !== 1) bad('unsupported catalog version');
  const policies = array(row.policies, 128).map(parsePolicy);
  unique(policies.map(policy => policy.id));
  return freeze({ schemaVersion: 1, policies });
}
export function positionActionPolicyDigest(value: unknown): string {
  return keccak256(toUtf8Bytes('cipher-position-action-policy-v1\n' + canonicalPositionPolicyJson(parsePositionActionPolicy(value))));
}

export type PositionPolicyBindingsContext = Pick<PositionActionPolicyContext,
  'owner' | 'recipient' | 'managementAddress' | 'positionId' | 'revision' | 'state'>;
function resolve(value: PositionPolicyValue, context: PositionPolicyBindingsContext, parameters: Readonly<Record<string, string | boolean>> = {}): PositionPolicyScalar {
  if (typeof value !== 'object') return value;
  const source = value.source === 'input' ? parameters : value.source === 'state' ? context.state : context;
  if (!Object.hasOwn(source, value.key)) bad(`missing ${value.source} binding ${value.key}`);
  return scalar((source as Record<string, unknown>)[value.key]);
}
function decimal(value: unknown, decimals: number): bigint {
  if (typeof value !== 'string' || value.length > 207 || !/^(0|[1-9]\d{0,77})(\.\d+)?$/.test(value)) bad('invalid decimal');
  const [whole, fraction = ''] = (value as string).split('.');
  if (fraction.length > decimals) bad('decimal precision exceeds bound');
  return BigInt(whole + fraction.padEnd(decimals, '0'));
}
function validateFieldValue(field: Record<string, unknown>, value: unknown): void {
  if (field.type === 'boolean') { boolean(value); return; }
  if (field.type === 'choice') {
    if (!(field.options as { value: string }[]).some(option => option.value === value)) bad('invalid selected choice');
    return;
  }
  const amount = field.type === 'decimal' ? decimal(value, field.decimals as number) : BigInt(uint(value, field.type === 'timestamp' ? 64 : 256));
  if (field.type === 'timestamp' && field.allowNoExpiry && amount === (1n << 64n) - 1n) return;
  const bound = (value: unknown) => field.type === 'decimal' ? decimal(value, field.decimals as number) : BigInt(uint(value, field.type === 'timestamp' ? 64 : 256));
  if (amount < bound(field.min) || amount > bound(field.max)) bad('selected input outside signed form bounds');
}
function materialize(policy: PositionActionPolicy, context: PositionPolicyBindingsContext): Record<string, unknown> {
  const template = policy.descriptor;
  const inputs = template.inputs.map(field => {
    const result: Record<string, unknown> = { key: field.key, label: field.label, type: field.type };
    if (field.type === 'amount' || field.type === 'decimal') result.decimals = integer(resolve(field.decimals, context), field.type === 'decimal' ? 128 : 255);
    if (field.type === 'amount') {
      result.asset = address(resolve(field.asset, context));
      if (field.display) result.display = field.display;
    }
    if (field.type === 'amount' || field.type === 'decimal' || field.type === 'timestamp') {
      result.min = resolve(field.min, context); result.max = resolve(field.max, context);
      const bound = (value: unknown) => field.type === 'decimal' ? decimal(value, result.decimals as number) : BigInt(uint(value, field.type === 'timestamp' ? 64 : 256));
      if (bound(result.min) > bound(result.max)) bad('invalid signed form range');
    }
    if (field.type === 'timestamp') result.allowNoExpiry = field.allowNoExpiry;
    if (field.type === 'choice') result.options = field.options.map(option => ({ ...option }));
    if (field.type === 'decimal' && field.unit) {
      const unit = { baseAsset: address(resolve(field.unit.baseAsset, context)), quoteAsset: address(resolve(field.unit.quoteAsset, context)) };
      if (unit.baseAsset === unit.quoteAsset) bad('identical price unit assets'); result.unit = unit;
    }
    if (field.value !== undefined) { result.value = resolve(field.value, context); validateFieldValue(result, result.value); }
    return result;
  });
  const defaults = Object.fromEntries(Object.entries(template.defaults).map(([key, value]) => {
    const result = resolve(value, context);
    if (typeof result !== 'string' && typeof result !== 'boolean') bad('invalid form constant');
    return [key, result];
  }));
  const spend = template.spend.map(entry => {
    const asset = address(resolve(entry.asset, context));
    if (inputs.find(field => field.key === entry.amountField)?.asset !== asset) bad('spend input asset mismatch');
    return { asset, amountField: entry.amountField };
  });
  const result: Record<string, unknown> = { ...template, id: policy.actionId, policyId: policy.id, enabled: true, reason: null, inputs, defaults, spend };
  if (template.targets) {
    result.targets = template.targets.map(value => address(resolve(value, context), true));
    unique(result.targets as string[]);
  }
  return result;
}
/** Build the reviewed form from independently sourced facts before showing it.
 * The caller may use its existing positionsContract parser to obtain UI types. */
export function materializePositionPolicyDescriptor(policy: PositionActionPolicy, context: PositionPolicyBindingsContext): Readonly<Record<string, unknown>> {
  canonicalPositionPolicyJson(context);
  return freeze(materialize(parsePositionActionPolicy(policy), context));
}
export function assertPositionPolicyDescriptor(policy: PositionActionPolicy, context: PositionActionPolicyContext): Readonly<Record<string, unknown>> {
  const expected = materializePositionPolicyDescriptor(policy, context);
  if (canonicalPositionPolicyJson(context.descriptor) !== canonicalPositionPolicyJson(expected)) bad('selected descriptor differs from signed template');
  return expected;
}
function addAmount(target: Map<string, bigint>, key: string, amount: bigint): void {
  const total = (target.get(key) ?? 0n) + amount;
  if (total > UINT_MAX) bad('cumulative amount exceeds uint256');
  target.set(key, total);
}
function amounts(input: unknown): Map<string, bigint> {
  const result = new Map<string, bigint>();
  for (const value of array(input, 32)) {
    const row = object(value); keys(row, ['asset', 'amountRaw']);
    const asset = address(row.asset);
    if (result.has(asset)) bad('duplicate amount limit');
    result.set(asset, BigInt(uint(row.amountRaw)));
  }
  return result;
}
function approvals(input: unknown): Map<string, bigint> {
  const result = new Map<string, bigint>();
  for (const value of array(input, 32)) {
    const row = object(value); keys(row, ['asset', 'spender', 'amountRaw']);
    const key = address(row.asset, true) + ':' + address(row.spender, true);
    if (result.has(key)) bad('duplicate approval limit');
    result.set(key, BigInt(uint(row.amountRaw)));
  }
  return result;
}
function checkContext(context: PositionActionPolicyContext, policy: PositionActionPolicy): void {
  canonicalPositionPolicyJson(context);
  keys(object(context), ['chainId', 'protocolId', 'actionId', 'positionId', 'revision', 'owner', 'recipient', 'managementAddress',
    'descriptor', 'parameters', 'state', 'limits', 'nowSeconds', 'expiresAt'], ['deploymentIntegrity']);
  if (context.chainId !== policy.chainId || context.protocolId !== policy.protocolId || context.actionId !== policy.actionId) bad('selected policy identity mismatch');
  text(context.positionId, 512); text(context.revision, 256);
  address(context.owner, true); address(context.recipient, true);
  const management = address(context.managementAddress, true);
  if (policy.deployment.kind === 'fixed' && !policy.deployment.addresses.includes(management)) bad('management deployment mismatch');
  if (policy.deployment.kind === 'fixed') {
    const observed = parseIntegrityMap(context.deploymentIntegrity);
    if (canonicalPositionPolicyJson(observed) !== canonicalPositionPolicyJson(policy.deployment.integrity)) bad('deployment code or implementation changed');
  } else if (context.deploymentIntegrity !== undefined) bad('unexpected local deployment evidence');
  map(context.parameters, 32, value => {
    if (typeof value !== 'boolean' && (typeof value !== 'string' || value.length > 256)) bad('invalid selected parameter');
    return value;
  });
  map(context.state, 128, scalar);
  integer(context.nowSeconds, Number.MAX_SAFE_INTEGER);
  integer(context.expiresAt, Number.MAX_SAFE_INTEGER);
  if (context.expiresAt <= context.nowSeconds || context.expiresAt - context.nowSeconds > 600) bad('expired or excessive authorization lifetime');
  keys(object(context.limits), ['maxNativeValue', 'spends', 'approvals', 'minimumReceives']);
  uint(context.limits.maxNativeValue);
}
function transactions(value: readonly PositionPolicyTransaction[], context: PositionActionPolicyContext): PositionPolicyTransaction[] {
  canonicalPositionPolicyJson(value);
  const result = array(value, MAX_CALLS).map(value => {
    const row = object(value); keys(row, ['to', 'data', 'value'], ['label', 'from', 'chainId']);
    const to = address(row.to, true), amount = uint(row.value);
    if (typeof row.data !== 'string' || !/^0x(?:[\da-fA-F]{2}){4,65536}$/.test(row.data)) bad('invalid bounded calldata');
    if (row.from !== undefined && address(row.from, true) !== address(context.owner)) bad('transaction sender mismatch');
    if (row.chainId !== undefined && row.chainId !== context.chainId) bad('transaction chain mismatch');
    if (row.label !== undefined) text(row.label, 160);
    // Transport labels are not authorization/review text. The gateway displays
    // the signed descriptor, not these untrusted per-transaction labels.
    return { to, data: (row.data as string).toLowerCase(), value: amount };
  });
  if (!result.length) bad('empty transaction sequence');
  return result;
}
function resolveArgument(type: ParamType, value: PositionPolicyArgument, context: PositionActionPolicyContext): unknown {
  if (type.baseType === 'array') return (value as PositionPolicyArgument[]).map(value => resolveArgument(type.arrayChildren!, value, context));
  if (type.baseType === 'tuple') return type.components!.map((child, index) => resolveArgument(child, (value as PositionPolicyArgument[])[index]!, context));
  const resolved = resolve(value as PositionPolicyValue, context, context.parameters);
  if (type.type === 'address') return address(resolved);
  if (type.type === 'bool') return boolean(resolved);
  if (type.type.startsWith('uint')) return uint(resolved, Number(type.type.slice(4)));
  if (type.type !== 'bytes32' || typeof resolved !== 'string' || !/^0x[\da-fA-F]{64}$/.test(resolved)) bad('invalid bytes32 binding');
  return (resolved as string).toLowerCase();
}
function at(args: readonly unknown[], indexes: PositionPolicyPath): unknown {
  let value: unknown = args;
  for (const index of indexes) { if (!Array.isArray(value) || index >= value.length) bad('invalid argument path'); value = (value as unknown[])[index]; }
  return value;
}
function amountList(value: Map<string, bigint>): PositionPolicyAmount[] {
  return [...value].sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([asset, amount]) => ({ asset, amountRaw: amount.toString() }));
}
const approvalAbi = new Interface(['function approve(address,uint256)']);

/** Deterministic, synchronous, bounded evaluation. The trusted caller supplies
 * current time and independently read state. There is no network, eval, callback,
 * API effect comparison or dynamic semantic registration in this module.
 * A local result is only a request for the built-in runtime validator. It is NOT
 * permission to sign; the gateway must bind its fresh private proof to all three
 * digests and preserve its existing deployment/SDK/plaintext checks. */
export function evaluatePositionActionPolicy(policyValue: PositionActionPolicy, context: PositionActionPolicyContext,
  transactionValues: readonly PositionPolicyTransaction[]): PositionPolicyEvaluation {
  const policy = parsePositionActionPolicy(policyValue);
  checkContext(context, policy);
  const descriptor = assertPositionPolicyDescriptor(policy, context), parameters = context.parameters;
  const fields = descriptor.inputs as Record<string, unknown>[], defaults = descriptor.defaults as Record<string, string | boolean>;
  const parameterKeys = [...fields.map(field => String(field.key)), ...Object.keys(defaults)].sort();
  if (Object.keys(parameters).sort().join(',') !== parameterKeys.join(',')) bad('selected parameter keys changed');
  for (const [key, value] of Object.entries(defaults)) if (parameters[key] !== value) bad('selected constant changed');
  for (const field of fields) validateFieldValue(field, parameters[String(field.key)]);
  const selected = new Map<string, bigint>();
  for (const entry of descriptor.spend as { asset: string; amountField: string }[]) addAmount(selected, entry.asset, BigInt(uint(parameters[entry.amountField])));
  const spendLimits = amounts(context.limits.spends), approvalLimits = approvals(context.limits.approvals), receiveLimits = amounts(context.limits.minimumReceives);
  const calls = transactions(transactionValues, context);
  const spent = new Map<string, bigint>(), approved = new Map<string, bigint>(), received = new Map<string, bigint>();
  let native = 0n;
  for (const call of calls) native += BigInt(call.value);
  if (native > UINT_MAX || native > BigInt(context.limits.maxNativeValue)
    || native > (selected.get(ZeroAddress) ?? 0n) || native > (spendLimits.get(ZeroAddress) ?? 0n)) bad('cumulative native spend exceeds selection');
  const commitments = {
    policyDigest: positionActionPolicyDigest(policy),
    contextDigest: keccak256(toUtf8Bytes('cipher-position-action-context-v1\n' + canonicalPositionPolicyJson(context))),
    transactionsDigest: keccak256(toUtf8Bytes('cipher-position-action-transactions-v1\n' + canonicalPositionPolicyJson(calls))),
    expiresAt: context.expiresAt, nativeValue: native.toString(),
  };
  if (policy.execution.kind === 'local') return freeze({ ...commitments, status: 'requires-local-validation', capability: policy.execution.capability });
  if (calls.length !== policy.execution.sequence.length) bad('transaction sequence length mismatch');
  const fixed = policy.deployment as Extract<PositionPolicyDeployment, { kind: 'fixed' }>;
  const targets = descriptor.targets as string[] | undefined ?? [address(context.managementAddress)];
  if (targets.some(target => !fixed.addresses.includes(target))) bad('descriptor target outside signed deployment');
  if (native > 0n) spent.set(ZeroAddress, native);
  for (const [index, rule] of policy.execution.sequence.entries()) {
    const call = calls[index]!;
    if (rule.kind === 'erc20-approval') {
      const asset = address(resolve(rule.asset, context, parameters), true), spender = address(resolve(rule.spender, context, parameters), true);
      const amount = uint(resolve(rule.amount, context, parameters)), key = asset + ':' + spender;
      if (!targets.includes(spender) || !approvalLimits.has(key)) bad('unselected approval target');
      if (call.to !== asset || call.value !== '0' || call.data !== approvalAbi.encodeFunctionData('approve', [spender, amount]).toLowerCase()) bad('approval calldata mismatch');
      // Only an optional zero-reset followed by one bounded approval is supported.
      if (approved.has(key) && (approved.get(key) !== 0n || amount === '0')) bad('repeated approval');
      addAmount(approved, key, BigInt(amount));
      if (approved.get(key)! > approvalLimits.get(key)! || approved.get(key)! > (selected.get(asset) ?? 0n)) bad('approval exceeds selection');
      continue;
    }
    const target = address(resolve(rule.target, context, parameters), true), value = uint(resolve(rule.value, context, parameters));
    if (!targets.includes(target) || call.to !== target || call.value !== value) bad('operation target or native value mismatch');
    const { fragment, abi } = method(rule.method), args = fragment.inputs.map((type, index) => resolveArgument(type, rule.args[index]!, context));
    if (call.data !== abi.encodeFunctionData(fragment, args).toLowerCase()) bad('noncanonical or changed operation calldata');
    const recipient = rule.recipient.kind === 'sender' ? address(context.owner) : address(at(args, rule.recipient.path));
    if (recipient !== address(context.recipient)) bad('recipient mismatch');
    for (const [entries, totals, isSpend] of [[rule.spends, spent, true], [rule.minimumReceives, received, false]] as const) {
      unique(entries.map(entry => entry.amount.join('.')));
      for (const entry of entries) {
        const asset = address(resolve(entry.asset, context, parameters));
        if (isSpend && asset === ZeroAddress) bad('native spending must use transaction value');
        addAmount(totals, asset, BigInt(uint(at(args, entry.amount))));
      }
    }
    if (rule.deadline) {
      const deadline = BigInt(uint(at(args, rule.deadline.path)));
      if (deadline <= BigInt(context.nowSeconds) || deadline > BigInt(context.nowSeconds) + BigInt(rule.deadline.maxDelaySeconds)
        || deadline < BigInt(context.expiresAt)) bad('deadline outside reviewed window');
    }
  }
  for (const [asset, amount] of spent) if (amount > (selected.get(asset) ?? 0n) || amount > (spendLimits.get(asset) ?? 0n)) bad('cumulative token spend exceeds selection');
  for (const [key, amount] of approved) if (amount > (spent.get(key.split(':')[0]!) ?? 0n)) bad('approval exceeds actual operation spend');
  if (received.size !== receiveLimits.size) bad('minimum receive assets changed');
  for (const [asset, minimum] of receiveLimits) if ((received.get(asset) ?? -1n) < minimum) bad('minimum receipt below selection');
  return freeze({ ...commitments, status: 'authorized', spends: amountList(spent),
    approvals: [...approved].sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([key, amount]) => {
      const [asset, spender] = key.split(':'); return { asset: asset!, spender: spender!, amountRaw: amount.toString() };
    }), minimumReceives: amountList(received) });
}
