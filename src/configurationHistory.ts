import { ethers } from 'ethers';
import { freezeMetadata, metadataDigest, object, signatureDigest, validatePublicNetworkPayload,
  type Evidence, type SignedRecord, type MetadataVerifier } from './protocol.ts';

// Old records can bind change review, but never become active policy or renew automatically.
export function isConfigurationHistory(kind: string, scope: string, payload: unknown): boolean {
  if (kind === 'domains' && scope === 'domains') return !!payload && typeof payload === 'object' && Object.hasOwn(payload, 'origins');
  if (kind !== 'networks' || scope !== 'chains' || !payload || typeof payload !== 'object') return false;
  const rows = Object.values(payload);
  return rows.length > 0 && rows.every(row => !!row && typeof row === 'object' && !Object.hasOwn(row, 'swapRoutes') && !Object.hasOwn(row, 'appContracts'));
}

export function verifyConfigurationHistory(payload: unknown, evidence: Evidence, verifier: MetadataVerifier): SignedRecord {
  const trust = verifier.currentTrust;
  if (!trust) throw new Error('No authenticated historical trust policy');
  const statement = object(evidence.statement);
  const fields = ['schema', 'kind', 'scope', 'keyId', 'sequence', 'issuedAt', 'expiresAt', 'digest'];
  if (Object.keys(statement).length !== fields.length || fields.some(key => !Object.hasOwn(statement, key))
    || statement.schema !== 1 || !isConfigurationHistory(String(statement.kind), String(statement.scope), payload)) throw new Error('Unsupported historical configuration');
  for (const key of ['sequence', 'issuedAt', 'expiresAt']) {
    if (!Number.isSafeInteger(statement[key]) || Number(statement[key]) <= 0) throw new Error('Invalid historical configuration version');
  }
  const kind = statement.kind as 'networks' | 'domains';
  const lifetime = (kind === 'domains' ? 7 : 30) * 86400000;
  if (Number(statement.expiresAt) <= Number(statement.issuedAt) || Number(statement.expiresAt) - Number(statement.issuedAt) > lifetime
    || Number(statement.sequence) < trust.payload.minimumSequences[kind]) throw new Error('Invalid historical validity period');
  if (kind === 'networks') {
    const chains = object(payload);
    validatePublicNetworkPayload(Object.fromEntries(Object.entries(chains).map(([id, value]) => {
      const row = object(value);
      if (row.supportsSwap !== undefined && typeof row.supportsSwap !== 'boolean') throw new Error('Invalid historical chain flag');
      // History has no route authorization; validate the old flag separately from current consistency rules.
      return [id, { ...row, supportsSwap: false, swapRoutes: [],
        appContracts: { chatGCAddress: null, cipherDataGcAddress: null, memoGcAddress: null } }];
    })));
  } else {
    const domains = object(payload);
    if (Object.keys(domains).length !== 1 || !Array.isArray(domains.origins) || domains.origins.length > 64) throw new Error('Invalid historical domains');
    for (const origin of domains.origins) {
      if (typeof origin !== 'string' || origin.length > 256) throw new Error('Invalid historical origin');
      const url = new URL(origin);
      if (url.protocol !== 'https:' || url.origin !== origin || url.username || url.password) throw new Error('Invalid historical origin');
    }
  }
  const digest = metadataDigest(payload);
  if (digest !== statement.digest || trust.payload.revokedDigests.includes(digest)) throw new Error('Historical digest revoked or mismatched');
  const key = trust.payload.keys.find(key => key.id === statement.keyId && key.kinds.includes(kind));
  if (!key || key.notBefore > Number(statement.issuedAt) || (key.expiresAt !== null && key.expiresAt < Number(statement.expiresAt))) throw new Error('Historical publishing key not authorized');
  if (!/^0x[0-9a-fA-F]{128}$/.test(evidence.signature)) throw new Error('Invalid historical signature');
  const recovered = ethers.SigningKey.computePublicKey(ethers.SigningKey.recoverPublicKey(signatureDigest('record', statement), evidence.signature), true);
  if (recovered !== ethers.SigningKey.computePublicKey(key.publicKey, true)) throw new Error('Historical signature mismatch');
  return freezeMetadata(JSON.parse(JSON.stringify({ payload, statement, signature: evidence.signature })) as SignedRecord);
}
