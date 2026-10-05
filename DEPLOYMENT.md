# First Deployment and Metro Testing

Prepared 2026-10-05. This guide describes operator setup, not an already completed deployment.

## Repository and cost

Recommended public repository: `CipherTrade-Wallet/cipher-metadata-publisher`.
It matches the existing local directory and covers descriptors, token metadata and
public configuration, not just ERC-7730. Use `main` for this new repository; the
existing wallet app and API use `master`.

Standard GitHub-hosted runner execution is free for public repositories. This is
not unlimited infrastructure: storage, concurrency, execution and service limits
still apply, and larger runners are charged. The workflow uses standard Ubuntu
runners. Public repositories also support required environment reviewers on GitHub
Free; Actions secrets do not become public merely because the repository is public.

Sources: [Actions billing](https://docs.github.com/en/billing/concepts/product-billing/github-actions),
[environment protection](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments),
[Actions limits](https://docs.github.com/en/actions/reference/limits).

## 1. Establish the repositories

1. Review the app/API commits on `master`. Merging source does not deploy the API.
2. Create the recommended publisher repository as an EMPTY public repository: do
   not initialize a second README/history. Review `catalog/` and public RPC URLs
   before making the initial push. Do not publish `.env`, keys, `work/`, `sources/`
   or `node_modules/`; they are excluded by the publisher ignore rules.
3. From the existing local publisher directory, connect and push the chosen remote:

   ```powershell
   git remote add origin https://github.com/CipherTrade-Wallet/cipher-metadata-publisher.git
   git push -u origin main
   ```

   These are instructions, not commands already run. Adjust the URL if choosing a
   different owner/name. The source is locally committed; no publisher remote was
   created by the wallet merge operation.
4. Protect `main` against force pushes/deletion and unreviewed workflow changes.
   Keep workflow execution disabled until setup is complete, or expect the
   scheduled setup check to fail safely while roots/reviewers are empty.

## 2. Configure approval environments

Under repository Settings -> Environments, create all three environments:

| Environment | Allowed record kinds | Suggested delegated key ID |
| --- | --- | --- |
| `metadata-tokens` | `token`, `asset` | `tokens-2026-01` |
| `metadata-descriptors` | `descriptor` | `descriptors-2026-01` |
| `metadata-configuration` | `networks`, `domains`, `classification` | `configuration-2026-01` |

Require your approved GitHub user account(s) as reviewers in EACH environment.
Restrict deployments to protected branches; the workflow additionally selects
`main`. Disable administrative bypass where your configuration permits it.
Do not put publishing secrets at repository scope or in the preparation job.

Record those reviewers' stable numeric GitHub user IDs in `trust/reviewers.json`:

```json
{"userIds":[12345678]}
```

Replace the illustrative ID with the real account ID. Obtain it from the account's
GitHub API profile, for example `gh api users/YOUR_LOGIN --jq .id` after authenticating
GitHub CLI. Never substitute the username string for the numeric ID.

If you enable "Prevent self-review", another approved person must approve manually
triggered runs. With one operator, leave that option off or arrange a second reviewer;
required approval still applies. Require 2FA for accounts with administration/signing
approval rights. The code verifies the reviewer allowlist and protected-branch gate.

## 3. Provision keys on a trusted administration machine

Generate FOUR distinct secp256k1 key pairs using a trusted offline key utility or
secret manager: one root and the three delegated publishing keys above. Do not
reuse a wallet key or any fixture key from the tests.

- Root private key: offline encrypted storage, with a recovery backup. Never in CI,
  the API, the mobile app, Git, chat or command-line history.
- Delegated private keys: encrypted backup plus their OWN GitHub environment secret.
- Public keys and signed policy: safe to commit. Use ethers-compatible compressed
  public keys (`0x` plus 66 hexadecimal characters).

Install the identical public root ID/key list in these three files:

```text
publisher: trust/roots.json
API:       data/metadata-trust-roots.json
app:       src/data/metadataTrustRoots.json
```

Their shape is `{"schema":1,"keys":[{"id":"root-2026-01","publicKey":"0x..."}]}`.
The checked-in lists are intentionally empty. A test key is not a deployment shortcut.

In each environment create `METADATA_SIGNING_KEYS` as JSON containing ONLY that
environment's delegated private key, keyed by its public-policy ID. Example shape:
`{"tokens-2026-01":"0xPRIVATE_KEY"}`. This is secret input, not a file to commit.

## 4. Authorize delegates with the offline root

On the trusted administration machine, prepare public input JSON with `rootId`
and a `payload` matching `TrustPayload` in `src/protocol.ts`:

- `schema: 1`, an increasing `sequence` (start at 1), integer millisecond `issuedAt`
  and `expiresAt`. Start with a 30-day policy and schedule renewal before expiry.
- `keys`: each delegate's `id`, `publicKey`, `kinds`, `notBefore`, `expiresAt`.
  All three roles must be current, and their validity must cover published records.
- `revokedDigests: []` initially.
- `minimumSequences`: all six record kinds mapped to `1` initially.

Load the root privately through your secret-management mechanism into the process
environment variable `METADATA_ROOT_KEY`. It must not be hardcoded in a command or
checked-in file. From the publisher project, with reviewed dependencies installed:

```powershell
node scripts/trust-policy.mjs public-key
node scripts/trust-policy.mjs sign policy-input.json new-policy.json
```

The first prints the PUBLIC key only. The second validates and signs the public
policy, refuses to overwrite its output and never writes the root private key.
Inspect its output, then use it as `trust/policy.json`. Clear the root environment
variable/end that process afterwards. Commit only the public roots, public delegate
policy and reviewer IDs. Root signing does not happen in GitHub Actions.

## 5. Validate and publish the first catalog

On a supported Node 24 installation in the publisher project:

```powershell
npm ci --ignore-scripts
npm test
node scripts/workflow.mjs check-setup
```

The local setup check verifies keys/policy/reviewer configuration. The Actions run
also verifies the actual GitHub environment protection settings. Then:

1. Enable Actions and manually run **Publish signed metadata** on `main`.
2. Wait for **prepare**. It fetches data-only source snapshots, validates public
   inputs and produces an exact digest plus `prepared-metadata` artifacts.
3. Inspect `review.json`, source commits and `prepared.json`. For the first release,
   all scopes are additions. Check network endpoints, curated badges, token decimals
   and meaningful descriptor changes; do not approve merely because parsing passed.
4. Approve the three signing environments. No upstream script is run with keys.
5. Confirm the publish job creates a `metadata-N` release with `publication.json`
   and `publication.sha256`. This first real full-inventory build is a release gate;
   it was not run with production keys during local development.

The checksum checks downloaded bytes; application signatures establish trust. A
successful GitHub release does NOT install the artifact on the wallet API.

## 6. Install on the API

Deploy the merged API code plus the public roots. Keep server `data/chains.json`
private; do not replace it with, or copy it into, publisher `catalog/`.

Download the reviewed release artifact into a staging path accessible to the API
host. From the deployed API directory, using its normal supported Node/toolchain:

```text
npm ci --ignore-scripts
npm run build
node scripts/check-metadata-publication.mjs /staging/publication.json
```

Use an absolute path appropriate for your server. Existing production dependency
installation/deployment requirements still apply; these commands describe the added
metadata check, not a replacement for the API's normal deployment procedure.

After validation:

1. Install the file with atomic replacement on the same filesystem, retaining the
   prior artifact for recovery. Do not edit the active JSON in place.
2. Set `METADATA_PUBLICATION_FILE` to its installed absolute path. Give the API user
   read access, but no signing credentials. Keep it outside disposable release dirs
   unless your deploy process explicitly restores it.
3. Restart the API for the code/root/environment change. Later artifact replacements
   are picked up by its background check within roughly 60 seconds.
4. Use your existing deploy process or a restricted deployment job to deliver future
   release artifacts. The implemented publisher does NOT auto-install them on your
   server. Delivery needs no signing key.
5. Through the real production proxy/CDN, check `/chains`, `/tokens/metadata` and a
   covered `/metadata/descriptor?chainId=...&address=...&selector=...` response for
   `Cipher-Metadata` and `Cipher-Metadata-Trust`. Preserve body/header cache pairing,
   allow the additional 6 KiB of headers and expose them through CORS for web users.

Use the same normal authentication as existing token-metadata requests. There is
no new signature-authentication requirement for old apps or other consumers.
Large token batches may carry partial evidence while preserving their whole JSON.
Descriptor 404 is an ordinary supported fallback, not a reason to disable checks.

## 7. Test through Metro

No native rebuild is required for THIS refactor. App runtime dependencies/native
modules did not change. Use the existing native development build connected to Metro;
this does not make Expo Go a replacement for the app's existing dev build.

1. Update the app public root file to match the publisher/API and point the app at
   the intended API through its existing configuration.
2. Do a FULL JavaScript reload from the developer menu, not only Fast Refresh, so
   root/verifier singletons are recreated. Restart Metro with its cache cleared only
   if ordinary reload fails to pick up changed files. Do not erase wallet storage.
3. Verify network configuration and ordinary balances/logos before transaction review.
4. Check one curated token and one Trust Wallet-only token absent from local lists:
   metadata should resolve, but the latter must remain unverified/non-default.
5. Review bundled WETH/WCOTI wrapping, public swap approvals (zero, finite and maximum
   where applicable), a registry-covered route and nested/multiple calls. Confirm
   exact quantities, recipients, warnings, provenance and complete raw detail access.
6. Exercise Browser, WalletConnect, WalletConnect Pay, unknown contracts and public
   swaps with no descriptor. Fallback review must remain usable and honest.
7. Check private swaps/COTI SDK and CipherDEX flows remain unchanged. No descriptor
   should replace protocol verification or decrypted SDK handling.
8. Test offline/warm cache and cold lookup timeout. For invalid signatures, wrong
   scopes, expiry/revocation during an open review and stripped headers, use a
   controlled staging setup/separate test roots. Do not revoke production keys merely
   to test. Signing must require a new review after a bound dependency becomes invalid.
9. Start with review/cancel only. Perform any broadcast test explicitly on a supported
   test network or with a separately funded low-value test wallet.

Before roots/artifact setup, Metro can test bundled/fallback behavior only. Empty
root lists deliberately disable authenticated remote lookup. Do not mistake that
for successful testing of the publication path.

## 8. Acceptance and ongoing operations

Run on BOTH Android and iOS before production app release, including an older app
against the updated API. Device QA was not done in the local implementation pass.
Production users still need the new JS through your normal approved release/update
channel; a local Metro reload does not update installed production apps.

The publisher prepares on Monday/Thursday at 08:00 UTC, with seven-day record
lifetimes. Approval and artifact delivery are still needed. Monitor release age,
failed runs, API artifact validation and root/delegate expiry; do not wait until
records expire to approve updates. Rotate delegates through a higher-sequence
root-signed public policy. Publish rollback content with a NEW higher publication
sequence rather than lowering floors or turning verification off.

Explicit badge removals belong in `catalog/classification-overrides.json`; retain
them while old bundled classifications can exist. Reinstall/eviction and distributor
withholding limitations are documented in the implementation report. Review trust
changes and update bundled compatibility data on normal app releases.
