import { performance } from 'node:perf_hooks';
import { ethers } from 'ethers';
import { MetadataVerifier, KINDS, metadataDigest, signatureDigest } from '../src/protocol.ts';
import { signTrust } from '../src/publisher.ts';

const root = ethers.Wallet.createRandom();
const delegate = ethers.Wallet.createRandom();
const now = Date.now();
const roots = [{ id: 'benchmark', publicKey: root.signingKey.compressedPublicKey }];
const trust = signTrust({ schema: 1, sequence: 1, issuedAt: now - 1000, expiresAt: now + 86400000,
  keys: [{ id: 'token', publicKey: delegate.signingKey.compressedPublicKey, kinds: ['token'], notBefore: now - 1000, expiresAt: now + 86400000 }],
  revokedDigests: [], minimumSequences: Object.fromEntries(KINDS.map(kind => [kind, 1])),
}, roots[0].id, root.privateKey);
const payload = { chainId: 1, address: '0x' + '44'.repeat(20), symbol: 'EXAMPLE', decimals: 6, source: 'trustwallet', revision: 'a'.repeat(40) };
const scope = `1:${payload.address}`;
const statement = { schema: 1, kind: 'token', scope, keyId: 'token', sequence: 1, issuedAt: now, expiresAt: now + 3600000, digest: metadataDigest(payload) };
const evidence = { statement, signature: delegate.signingKey.sign(signatureDigest('record', statement)).compactSerialized };
const samples = [];
for (let i = 0; i < 50; i++) {
  const start = performance.now();
  const verifier = new MetadataVerifier(roots);
  verifier.acceptTrust(trust);
  verifier.verify(payload, evidence, 'token', scope);
  samples.push(performance.now() - start);
}
samples.sort((a, b) => a - b);
const verifier = new MetadataVerifier(roots);
verifier.acceptTrust(trust);
const accepted = verifier.verify(payload, evidence, 'token', scope);
const start = performance.now();
for (let i = 0; i < 10000; i++) verifier.verify(accepted.payload, { statement: accepted.statement, signature: accepted.signature }, 'token', scope);
console.log(JSON.stringify({ platform: process.platform, node: process.version, coldTrials: samples.length,
  coldMedianMs: samples[25], coldP95Ms: samples[47], warmMeanMs: (performance.now() - start) / 10000,
  excludes: ['network', 'native storage', 'device UI'],
}, null, 2));
