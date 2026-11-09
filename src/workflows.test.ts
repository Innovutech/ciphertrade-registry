import fs from 'node:fs/promises';
import test from 'node:test';
import assert from 'node:assert/strict';

test('every publisher Node workflow uses the approved runtime', async () => {
  const directory = new URL('../.github/workflows/', import.meta.url);
  let pins = 0;
  for (const name of await fs.readdir(directory)) {
    if (!name.endsWith('.yml')) continue;
    const source = await fs.readFile(new URL(name, directory), 'utf8');
    for (const match of source.matchAll(/node-version:\s*['"]?([^'"\s]+)/g)) {
      assert.equal(match[1], '24.22.1', name);
      pins++;
    }
  }
  assert.equal(pins, 8);
});

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
  assert.doesNotMatch(renew, /trustwallet|registryDirectory|prepared-metadata/);
  assert.match(sign, /group: metadata-publication-write/);
  assert.match(sign, /cancel-in-progress: false/);
  assert.match(sign, /if: inputs\.mode == 'changes'/);
  assert.match(sign, /node scripts\/workflow\.mjs finalize/);
  assert.match(sign, /environment: metadata-\$\{\{ matrix\.role \}\}/);
  assert.doesNotMatch(sign, /secrets\.METADATA_ROOT_KEY/);
  assert.doesNotMatch(publish + renew, /group: metadata-publication-write/);
  // Supersession is scoped to unsigned work; it must not cancel a signed writer.
  assert.doesNotMatch(publish, /^concurrency:/m);
  assert.match(publish, /group: metadata-change-prepare\r?\n      cancel-in-progress: true/);
  assert.equal((publish.match(/group: metadata-change-review-gate/g) ?? []).length, 2);
  assert.match(publish, /needs: \[prepare, notify\]/);
  assert.match(publish, /node scripts\/approval-notification\.mjs ready/);
  assert.match(publish, /node scripts\/approval-notification\.mjs finish/);
  assert.match(publish, /needs\.publish\.outputs\.sequence/);
});

test('reusable signing explicitly declares its secret without inheriting unrelated secrets', async () => {
  const read = (name: string) => fs.readFile(new URL(`../.github/workflows/${name}.yml`, import.meta.url), 'utf8');
  const sign = await read('sign-publication');
  assert.match(sign, /\n    secrets:\r?\n      METADATA_SIGNING_KEYS:\r?\n/);
  assert.match(sign, /environment: metadata-\$\{\{ matrix\.role \}\}/);
  for (const name of ['publish', 'renew']) {
    const workflow = await read(name);
    assert.match(workflow, /uses: \.\/\.github\/workflows\/sign-publication\.yml\r?\n    secrets:\r?\n      METADATA_SIGNING_KEYS: \$\{\{ secrets\.METADATA_SIGNING_KEYS \}\}/);
    assert.doesNotMatch(workflow, /secrets: inherit/);
  }
});

test('delivery monitoring has its own schedule and reviewer notifications but cannot sign or approve', async () => {
  const workflow = await fs.readFile(new URL('../.github/workflows/monitor-delivery.yml', import.meta.url), 'utf8');
  assert.match(workflow, /cron: '17 \*\/6 \* \* \*'/);
  assert.match(workflow, /group: metadata-delivery-monitor/);
  assert.match(workflow, /issues: write/);
  assert.match(workflow, /contents: read/);
  assert.match(workflow, /node scripts\/delivery-monitor\.mjs/);
  assert.match(workflow, /node-version: '24\.22\.1'/);
  assert.doesNotMatch(workflow, /contents: write|environment:|sign-publication|approval-notification\.mjs|METADATA_SIGNING_KEYS|METADATA_ROOT_KEY|secrets:|push:/);
  const script = await fs.readFile(new URL('../scripts/workflow.mjs', import.meta.url), 'utf8');
  assert.match(script, /expiresAt: issuedAt \+ PUBLICATION_LIFETIME/);
  assert.match(script, /assertRecordPublication\(record.statement, prepared, trust.payload\)/);
  assert.doesNotMatch(script, /record.statement.expiresAt !== prepared.expiresAt/);
});
