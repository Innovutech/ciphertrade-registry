import {
  validateConfigurationPublication, type PublicNetworkPayload, type DomainPayload,
  type TokenCatalogPayload, type PrivacyBridgesPayload, type TrustedNftsPayload,
} from './protocol.ts';
import type { Candidate } from './publisher.ts';

export function configurationFallbacks(records: readonly Candidate[]): Map<string, unknown> {
  validateConfigurationPublication(records);
  const payloads = new Map(records.map(row => [`${row.kind}:${row.scope}`, row.payload]));
  const chains = payloads.get('networks:chains') as PublicNetworkPayload;
  const ordered = Object.entries(chains).map(([chainId, row]) => ({ chainId: Number(chainId), ...row }))
    .sort((a, b) => (a.displayOrder ?? Number.MAX_SAFE_INTEGER) - (b.displayOrder ?? Number.MAX_SAFE_INTEGER) || a.chainId - b.chainId);
  const files = new Map<string, unknown>([
    ['chains.json', ordered],
    ['verified_domains.json', (payloads.get('domains:domains') as DomainPayload).patterns],
    ['coti_bridge.routes.json', payloads.get('networks:coti-bridge-routes')],
  ]);
  for (const chain of ordered) {
    const tokens = payloads.get(`networks:tokens:${chain.chainId}`) as TokenCatalogPayload;
    files.set(`default_tokens.${chain.chainId}.json`, tokens.defaults);
    files.set(`verified_tokens.${chain.chainId}.json`, tokens.verified);
    files.set(`tokens.${chain.chainId}.json`, tokens.tokens);
    files.set(`privacy_bridges.${chain.chainId}.json`, (payloads.get(`networks:privacy-bridges:${chain.chainId}`) as PrivacyBridgesPayload).bridges);
    files.set(`token_families.${chain.chainId}.json`, payloads.get(`networks:token-families:${chain.chainId}`));
    files.set(`trusted_nfts.${chain.chainId}.json`, (payloads.get(`networks:trusted-nfts:${chain.chainId}`) as TrustedNftsPayload).nfts);
    files.set(`bundledMemoConfig.${chain.chainId}.json`, {
      walletAddress: '', chainId: chain.chainId, rpcUrl: chain.rpcUrl, rpcWsUrl: chain.rpcWsUrl ?? null,
      nativeSymbol: chain.nativeSymbol, ...chain.appContracts, chatFeeWei: null, memoFeeWei: null,
      explorerTxUrl: chain.explorerTxUrl ?? null, chainName: chain.name,
    });
  }
  return files;
}
