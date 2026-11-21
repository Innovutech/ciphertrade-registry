import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const output = fs.readFileSync(path.join(root, 'src', 'positionActionPolicy.ts'), 'utf8').replace(/\r\n/g, '\n');
const destinations = [
  '../cipher-wallet-api/src/services/positionActionPolicy.ts',
  '../cipher-wallet-rn/src/features/positionPolicies/contract.ts',
];
for (const relative of destinations) {
  const destination = path.resolve(root, relative);
  if (process.argv.includes('--write')) {
    fs.mkdirSync(path.dirname(destination), { recursive: true });
    fs.writeFileSync(destination, output);
  } else if (!fs.existsSync(destination) || fs.readFileSync(destination, 'utf8').replace(/\r\n/g, '\n') !== output) {
    throw Error(`Position policy copy differs: ${relative}`);
  }
}
