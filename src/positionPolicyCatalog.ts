import { ZeroAddress, getAddress } from 'ethers';
import { canonicalPositionPolicyJson, parsePositionActionPolicyCatalog, type PositionActionPolicy, type PositionActionPolicyCatalog,
  type PositionPolicyDescriptor, type PositionPolicyInput, type PositionPolicyIntegrity } from './positionActionPolicy.ts';

/** Unsigned, operator-reviewed recipes only. This module does not read an API,
 * discover deployments, attest code, sign, publish, or manufacture integrity pins. */
export type InitialPositionPolicyDeployments = {
  carbon: readonly { chainId: 1 | 2632500; controller: string; voucher: string;
    integrity: Readonly<Record<string, PositionPolicyIntegrity>> }[];
  cipherdex?: { chainId: 2632500; publicBook: string; privateBook: string; liquidityRouter: string; marketPresentationRevision: string };
};
export const INITIAL_POSITION_POLICY_STATE_KEYS = Object.freeze({
  carbon: Object.freeze(['baseToken', 'quoteToken', 'baseDecimals', 'quoteDecimals', 'buyBudgetRaw', 'sellBudgetRaw', 'buyFundMaxRaw', 'sellFundMaxRaw']),
  cipherdexLiquidity: Object.freeze(['token0Address', 'token1Address', 'token0Decimals', 'token1Decimals', 'lpTokenAddress', 'availableSharesRaw']),
  cipherdexOrderAmendment: Object.freeze(['baseAsset', 'quoteAsset', 'expiryRaw']),
  // The reviewed market revision is a signed literal, not a runtime state binding.
  cipherdexPublicOrderAmendment: Object.freeze([]),
  cipherdexCredit: Object.freeze(['creditKind']),
});
const UINT_MAX = ((1n << 256n) - 1n).toString(), UINT128_MAX = ((1n << 128n) - 1n).toString();
const state = (key: string) => ({ source: 'state' as const, key });
const context = (key: string) => ({ source: 'context' as const, key });
const localDeployment = { kind: 'local' as const, capability: 'cipherdex-deployment-v1' as const };
function deploymentAddress(value: string): string {
  const address = getAddress(value).toLowerCase();
  if (address === ZeroAddress) throw new Error('A reviewed deployment address is required.');
  return address;
}
function base(execution: PositionPolicyDescriptor['execution'], family: PositionPolicyDescriptor['family'], label: string,
  title: string, icon: PositionPolicyDescriptor['icon'], group: PositionPolicyDescriptor['group'], order: number): PositionPolicyDescriptor {
  return { execution, family, label, title, icon, group, order, inputs: [], defaults: {}, spend: [] };
}
export function carbonPositionPolicyId(chainId: number, actionId: string): string { return `carbon-${chainId}-${actionId}-v1`; }
export function cipherDexOrderPositionPolicyId(chainId: number, book: 'public' | 'private', actionId: string): string {
  return `cipherdex-${chainId}-${book}-${actionId}-v1`;
}
export function cipherDexLiquidityPositionPolicyId(chainId: number, mode: 0 | 1 | 2 | 3, actionId: string): string {
  return `cipherdex-${chainId}-mode${mode}-${actionId}-v1`;
}
function carbonPolicies(deployment: InitialPositionPolicyDeployments['carbon'][number]): PositionActionPolicy[] {
  if (![1, 2632500].includes(deployment.chainId) || Object.keys(deployment).some(key => !['chainId', 'controller', 'voucher', 'integrity'].includes(key))) {
    throw new Error('Unsupported Carbon native capability deployment.');
  }
  const controller = deploymentAddress(deployment.controller), voucher = deploymentAddress(deployment.voucher);
  if (controller === voucher) throw new Error('Controller and voucher identities must differ.');
  const descriptors: [string, PositionPolicyDescriptor][] = [
    ['update-strategy', base('api', 'update', 'Edit ranges', 'Update strategy ranges', 'edit', 'manage', 10)],
    ['fund-strategy', base('api', 'fund', 'Add funds', 'Fund strategy', 'add', 'funds', 20)],
    ['withdraw-strategy', base('api', 'withdraw', 'Withdraw', 'Withdraw strategy funds', 'download', 'funds', 30)],
    ['close-strategy', base('api', 'cancel', 'Close strategy', 'Close strategy and withdraw', 'close', 'manage', 40)],
  ];
  for (const [actionId, descriptor] of descriptors) {
    if (actionId === 'update-strategy') {
      // Current prices can be outside the editable precision/range. Optional UI
      // suggestions must not make an otherwise valid price update unavailable.
      descriptor.inputs = (['buy', 'sell'] as const).flatMap(side => (['Low', 'High'] as const).map(end => ({
        key: `${side}Price${end}`, label: `${side === 'buy' ? 'Buy' : 'Sell'} ${end.toLowerCase()} (quote/base)`,
        type: 'decimal' as const, decimals: 128, min: '0', max: '999999999999999999999999999999999999',
        unit: { baseAsset: state('baseToken'), quoteAsset: state('quoteToken') },
      })));
    } else if (actionId === 'fund-strategy' || actionId === 'withdraw-strategy') {
      descriptor.inputs = (['buy', 'sell'] as const).map(side => ({ key: `${side}AmountRaw`,
        label: side === 'buy' ? 'Buy budget (quote)' : 'Sell budget (base)', type: 'amount' as const,
        asset: state(side === 'buy' ? 'quoteToken' : 'baseToken'), decimals: state(side === 'buy' ? 'quoteDecimals' : 'baseDecimals'),
        min: '0', max: state(`${side}${actionId === 'fund-strategy' ? 'FundMaxRaw' : 'BudgetRaw'}`), value: '0' }));
      if (actionId === 'fund-strategy') descriptor.spend = [
        { asset: state('quoteToken'), amountField: 'buyAmountRaw' }, { asset: state('baseToken'), amountField: 'sellAmountRaw' },
      ];
    }
  }
  return descriptors.map(([actionId, descriptor]) => ({ schemaVersion: 1, id: carbonPositionPolicyId(deployment.chainId, actionId),
    chainId: deployment.chainId, protocolId: 'carbon', actionId, descriptor,
    deployment: { kind: 'fixed', addresses: [controller], contracts: { controller, voucher }, integrity: { ...deployment.integrity } },
    execution: { kind: 'local', capability: 'carbon-strategy-v1' } }));
}
function orderPolicies(deployment: NonNullable<InitialPositionPolicyDeployments['cipherdex']>, book: 'public' | 'private'): PositionActionPolicy[] {
  const privateBook = book === 'private', execution = privateBook ? 'local' : 'api';
  const bookAddress = deploymentAddress(privateBook ? deployment.privateBook : deployment.publicBook);
  const descriptors: [string, PositionPolicyDescriptor][] = [
    ['cancel-order', base(execution, 'cancel', 'Cancel', 'Cancel order', 'close', 'manage', 40)],
    ['amend-order', base(execution, 'update', 'Update', 'Update order', 'edit', 'manage', 20)],
    ['add-reward', base(execution, 'tip', 'Add tip', 'Add matching tip', 'add', 'funds', 10)],
    ['claim-credit', base(execution, 'claim', 'Claim', 'Claim credit', 'download', 'funds', 10)],
  ];
  if (privateBook) descriptors.push(['reveal-order', base('local', 'reveal', 'Reveal', 'Reveal order', 'eye', 'read', 0)]);
  for (const [actionId, descriptor] of descriptors) {
    descriptor.targets = [bookAddress];
    if (actionId === 'amend-order') {
      descriptor.preview = execution; descriptor.requiresLocalAmounts = privateBook;
      descriptor.defaults = privateBook ? {} : { marketPresentationRevision: deployment.marketPresentationRevision };
      descriptor.inputs = [
        { key: 'limitPrice', label: 'Limit price', type: 'decimal', decimals: 78, min: '0.' + '0'.repeat(77) + '1', max: UINT_MAX,
          unit: { baseAsset: state('baseAsset'), quoteAsset: state('quoteAsset') } },
        { key: 'expiryRaw', label: 'Expiry', type: 'timestamp', min: '0', max: '253402300799', allowNoExpiry: true },
      ];
    } else if (actionId === 'add-reward') {
      descriptor.inputs = [{ key: 'amountRaw', label: 'Matching tip', type: 'amount', asset: ZeroAddress, decimals: 18, min: '1', max: UINT_MAX }];
      descriptor.spend = [{ asset: ZeroAddress, amountField: 'amountRaw' }];
    } else if (actionId === 'claim-credit') descriptor.defaults = { kind: state('creditKind') };
  }
  return descriptors.map(([actionId, descriptor]) => ({ schemaVersion: 1, id: cipherDexOrderPositionPolicyId(deployment.chainId, book, actionId),
    chainId: deployment.chainId, protocolId: 'cipherdex', actionId, descriptor,
    deployment: { ...localDeployment, scope: { kind: 'order', book } }, execution: { kind: 'local', capability: 'cipherdex-order-v1' } }));
}
function liquidityPolicies(deployment: NonNullable<InitialPositionPolicyDeployments['cipherdex']>, mode: 0 | 1 | 2 | 3): PositionActionPolicy[] {
  const execution = mode === 0 ? 'api' : 'local', localAmounts = mode === 1 || mode === 2;
  const router = deploymentAddress(deployment.liquidityRouter);
  const slippage: PositionPolicyInput = { key: 'slippageBps', label: 'Slippage (bps)', type: 'decimal', decimals: 0, min: '0', max: '1000', value: '50' };
  const descriptors: [string, PositionPolicyDescriptor][] = [
    ['add-liquidity', base(execution, 'fund', 'Add', 'Add liquidity', 'add', 'funds', 20)],
    ['remove-liquidity', base(execution, 'withdraw', 'Withdraw', 'Withdraw liquidity', 'download', 'funds', 30)],
    ['claim-fees', base('local', 'claim', 'Claim', 'Claim fees', 'download', 'funds', 10)],
  ];
  if (localAmounts) descriptors.push(
    ['reveal-position', base('local', 'reveal', 'Reveal', 'Reveal position', 'eye', 'read', 0)],
    ['reveal-accounting', base('local', 'reveal', 'Accounting', 'Reveal accounting', 'refresh', 'read', 1)],
  );
  for (const [actionId, descriptor] of descriptors) {
    // These existing SDK-authorized local workflows have no amount form or preview.
    if (actionId === 'reveal-position' || actionId === 'reveal-accounting') continue;
    descriptor.requiresLocalAmounts = actionId === 'add-liquidity' ? false : localAmounts;
    descriptor.targets = [mode === 0 && actionId !== 'claim-fees' ? router : context('managementAddress')];
    if (actionId === 'claim-fees') continue;
    descriptor.preview = execution;
    if (actionId === 'add-liquidity') {
      descriptor.inputs = [0, 1].map(index => ({ key: `amount${index}Raw`, label: `Token ${index + 1}`, type: 'amount' as const,
        asset: state(`token${index}Address`), decimals: state(`token${index}Decimals`), min: '1', max: UINT128_MAX }));
      descriptor.spend = [0, 1].map(index => ({ asset: state(`token${index}Address`), amountField: `amount${index}Raw` }));
    } else {
      descriptor.inputs = [{ key: 'sharesRaw', label: 'Amount', type: 'amount', asset: state('lpTokenAddress'), decimals: 18,
        min: '1', max: localAmounts ? UINT128_MAX : state('availableSharesRaw'), display: 'percentage' }];
      descriptor.spend = [{ asset: state('lpTokenAddress'), amountField: 'sharesRaw' }];
    }
    descriptor.inputs.push(slippage);
  }
  return descriptors.map(([actionId, descriptor]) => ({ schemaVersion: 1, id: cipherDexLiquidityPositionPolicyId(deployment.chainId, mode, actionId),
    chainId: deployment.chainId, protocolId: 'cipherdex', actionId, descriptor,
    deployment: { ...localDeployment, scope: { kind: 'liquidity', mode } }, execution: { kind: 'local', capability: 'cipherdex-liquidity-v1' } }));
}

/** Produce a detached, immutable UNSIGNED catalog for the normal publication
 * review workflow. Integrity hashes are mandatory actual operator input. */
export function createInitialPositionActionPolicyCatalog(deployments: InitialPositionPolicyDeployments): PositionActionPolicyCatalog {
  canonicalPositionPolicyJson(deployments);
  if (!deployments || !Array.isArray(deployments.carbon) || deployments.carbon.length > 2
    || Object.keys(deployments).some(key => !['carbon', 'cipherdex'].includes(key))) throw new Error('Invalid reviewed deployments.');
  const policies = deployments.carbon.flatMap(carbonPolicies);
  if (deployments.cipherdex) {
    const deployment = deployments.cipherdex;
    if (deployment.chainId !== 2632500 || Object.keys(deployment).some(key => !['chainId', 'publicBook', 'privateBook', 'liquidityRouter', 'marketPresentationRevision'].includes(key))) {
      throw new Error('Unsupported reviewed CipherDEX deployment.');
    }
    const revision = deployment.marketPresentationRevision;
    if (typeof revision !== 'string' || !revision || revision !== revision.trim() || revision.length > 256
      || /[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/.test(revision)) throw new Error('A reviewed market presentation revision is required.');
    if (new Set([deployment.publicBook, deployment.privateBook, deployment.liquidityRouter].map(deploymentAddress)).size !== 3) {
      throw new Error('CipherDEX deployment roots must differ.');
    }
    policies.push(...orderPolicies(deployment, 'public'), ...orderPolicies(deployment, 'private'));
    for (const mode of [0, 1, 2, 3] as const) policies.push(...liquidityPolicies(deployment, mode));
  }
  return parsePositionActionPolicyCatalog({ schemaVersion: 1, policies });
}
