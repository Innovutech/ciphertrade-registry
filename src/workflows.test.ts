import fs from 'node:fs/promises';
import test from 'node:test';
import assert from 'node:assert/strict';

test('change approval and renewal are independent entry points with one serialized writer', async () => {
  const read = (name: string) => fs.readFile(new URL(`../.github/workflows/${name}.yml`, import.meta.url), 'utf8');
  const publish = await read('publish');
  const renew = await read('renew');
  const sign = await read('sign-publication');
  assert.match(publish, /environment: metadata-review/);
  assert.match(publish, /needs: \[prepare, review\]/);
  assert.match(publish, /if: needs\.review\.result == 'success'/);
  assert.match(publish, /mode: changes/);
  assert.match(renew, /vars\.METADATA_AUTORENEW_ENABLED == 'true'/);
  assert.match(renew, /mode: renewal/);
  assert.doesNotMatch(renew, /trustwallet|registryDirectory|prepared-metadata|METADATA_SIGNING_KEYS/);
  assert.match(sign, /group: metadata-publication-write/);
  assert.match(sign, /cancel-in-progress: false/);
  assert.match(sign, /if: inputs\.mode == 'changes'/);
  assert.match(sign, /node scripts\/workflow\.mjs finalize/);
  assert.match(sign, /environment: metadata-\$\{\{ matrix\.role \}\}/);
  assert.doesNotMatch(sign, /secrets\.METADATA_ROOT_KEY/);
  assert.doesNotMatch(publish + renew, /group: metadata-publication-write/);
});
