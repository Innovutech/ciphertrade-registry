// Run only on the offline/root administration machine, never in API or CI jobs.
import fs from 'node:fs/promises';
import { ethers } from 'ethers';
import { MetadataVerifier } from '../src/protocol.ts';
import { signTrust } from '../src/publisher.ts';
import { assertPublishingRoles } from '../src/publishingPolicy.ts';

const [mode, input, output] = process.argv.slice(2);
let key;
try { key = new ethers.SigningKey(process.env.METADATA_ROOT_KEY ?? ''); }
catch { throw new Error('Set the offline METADATA_ROOT_KEY securely; its value is never printed.'); }
if (mode === 'public-key') {
  console.log(key.compressedPublicKey);
} else if (mode === 'sign' && input && output) {
  const config = JSON.parse(await fs.readFile(input, 'utf8'));
  const roots = JSON.parse(await fs.readFile('trust/roots.json', 'utf8'));
  const signed = signTrust(config.payload, config.rootId, key.privateKey);
  new MetadataVerifier(roots.keys).acceptTrust(signed);
  assertPublishingRoles(signed.payload);
  await fs.writeFile(output, JSON.stringify(signed, null, 2), { flag: 'wx' });
  console.log('Root-signed public policy written. No private key was written.');
} else throw new Error('Usage: node scripts/trust-policy.mjs public-key | sign <public-policy-input.json> <new-policy.json>');
