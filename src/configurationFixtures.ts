import { NETWORK_CHAIN_SCOPES, networkConfigScope } from './protocol.ts';
import type { Candidate } from './publisher.ts';

export function emptyConfigurationFixture(): Candidate[] {
  const payloads = {
    tokens: { chainId: 1, defaults: [], verified: [], tokens: [] },
    'privacy-bridges': { chainId: 1, bridges: [] },
    'token-families': { version: 1, chainId: 1, families: [] },
    'trusted-nfts': { chainId: 1, nfts: [] },
  };
  return [
    { kind: 'networks', scope: 'chains', payload: { '1': { name: 'Ethereum', nativeSymbol: 'ETH', rpcUrl: 'https://rpc.example.com', swapRoutes: [],
      appContracts: { chatGCAddress: null, cipherDataGcAddress: null, memoGcAddress: null } } } },
    { kind: 'domains', scope: 'domains', payload: { patterns: [] } },
    { kind: 'networks', scope: 'coti-bridge-routes', payload: { version: 1, routes: [] } },
    ...NETWORK_CHAIN_SCOPES.map(section => ({ kind: 'networks' as const, scope: networkConfigScope(section, 1), payload: payloads[section] })),
  ];
}
