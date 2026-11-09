# CipherTrade Registry

Signed public configuration, token metadata and ERC-7730 Clear Signing descriptors for CipherTrade.

- `catalog/`: curated assets, networks and domain records.
- `src/`: source importers, validation and signing.
- `trust/`: public keys, trust policy and reviewer configuration.
- `.github/workflows/`: CI and approved publication.

Sources include CipherTrade's curated catalog, Trust Wallet assets and the ERC-7730 registry.
External token metadata does not grant verified status.

## dApp directory

`catalog/dapps.json` is a separate curated directory. Preparation discovers PNG
logos from the pinned Trust Wallet `dapps/` tree; those entries have hostname-only
names, no descriptions, and are unverified. Explicit curated fields override
discovery and can add apps absent from Trust Wallet. `verified: true` is a reviewed
identity assertion, not a contract audit or a browser security-check bypass.

Each entry has a canonical `host`; optional `name`, `description`, `canonicalUrl`,
`logoUrl`, `verified`, `enabled`, `domainAliases`, and `searchAliases` customize it.
Canonical URLs must be HTTPS on that host. Domain aliases explicitly merge
discovered identities; search aliases are keywords only. Keep disabled entries as
`enabled: false, verified: false` to suppress upstream rediscovery. Duplicate or
conflicting identities fail preparation. Invalid external asset names are reported
and skipped. Curated SVG/PNG logos may use public HTTPS URLs; discovered logo URLs
are pinned to the exact Trust Wallet source commit.

Records use `domains` / `dapp:<host>` under the existing configuration signing
role, without changing the `domains` trusted-site pattern scope. They do not belong
in chain configuration or bundled network files. Publish updated API/schema support
before introducing these scopes. Existing review, signature expiry, monotonic
publication versions, and content-preserving renewal apply unchanged.

## Development

Requires Node.js 24 or later.

```sh
npm ci --ignore-scripts
npm test
```

### Configuration tests

The catalog is the source of truth for configurable values. Tests against it
must validate schemas, completeness, signatures, size limits and faithful
signed/release output, not pin current RPC providers, explorer URLs, contract
addresses, network membership, ordering, asset lists or record counts.
Use isolated synthetic catalogs for specific values and behavioral edge cases,
including valid additions, replacements and removals. A valid catalog update
within the protocol's limits must not require matching edits to test constants.

## Publishing

Catalog changes require reviewer approval. A separate scheduled workflow renews
the last approved catalog without importing upstream changes. Both use the same
serialized signer. Consumers verify short-lived records using trusted public keys;
root-authorized publishing keys can have non-expiring authorization.
Private keys belong in protected signing environments, never in this repository.

### Record validity and renewal

New signed records use these publisher lifetimes, within the existing consumer
verifier ceilings; the public release and statement schemas are unchanged:

| Kind | Issued validity | Existing verifier ceiling |
| --- | --- | --- |
| `networks` (chains and all per-chain configuration, including token catalogs) | 30 days | 30 days |
| `token`, `asset` (identity and presentation) | 30 days | 90 days |
| `classification`, `descriptor` | 30 days | 30 days |
| `domains` (trusted-site patterns and every `dapp:*` record) | 7 days | 7 days |

Each record is also capped by the prepared upper deadline, its actual signing
key's authorization expiry, and the signed trust policy expiry. A short-lived key
or domain record does not shorten unrelated records. Non-expiring authorization
never makes a record non-expiring. The existing `preparedDigest` format still
binds payloads, sources, scopes, sequence, issue time, deadline and catalog base;
descriptor artifact compaction does not change that digest. Assembly verifies
the exact per-record deadline, not a global expiry shared by all signing roles.

Renewal authenticates the last published catalog at its original issue times,
even after those records expire, then rechecks current root-authorized policy,
key identity/roles, revocations and sequence floors. It renews only those approved
payloads. It cannot import pending additions, substitute a prepared review, or
bootstrap a first publication without review. An awaiting change batch and its
approval digest stay untouched; identical-content renewals do not supersede its
catalog base. Historical verification is for renewal/review only, not permission
for consumers to use expired records.

Activation is separate from delivery:

- A code-only push runs CI, not publication. `publish.yml` reacts to `catalog/**`
  pushes on `main`, explicit dispatch, or Monday/Thursday at 08:00 UTC. It prepares
  a batch; changed content still requires `metadata-review` approval.
- `renew.yml` runs Monday/Thursday at 09:00 UTC or by explicit dispatch, only on
  `main` with `METADATA_AUTORENEW_ENABLED=true`. Its next run on this code issues
  the new lifetimes without approving pending changes. A push alone does not
  re-sign an existing release; dispatch is needed only to activate before the
  next enabled schedule. Both paths use the same serialized signing writer.
- Installing an already-published approved renewal does not change its signed
  validity. The API downloader must separately validate, install and serve it.
  A successful GitHub auto-renewal can coexist with failed VPS delivery, as in
  the observed delivery incident. Do not resolve that failure by approving an
  unrelated waiting batch. Consumer cache/startup scope isolation is separate
  from this publisher's issuance policy.

### Delivery and expiry alerts

`monitor-delivery.yml` checks production at minute 17 every six hours UTC, or by
explicit dispatch. It has no signing secrets, approval environment, release-write
permission or workflow-dispatch calls. A push does not run the check immediately;
its schedule becomes available when the workflow reaches the default branch.

The actual public endpoint is
`https://api.ciphertrade.org/chains?configuration=static`: the body is the signed
`networks:chains` payload and `Cipher-Metadata` also carries the complete signed
`domains:domains` trusted-site pattern catalog. There is no separate public
`/domains` endpoint. `Cipher-Metadata-Trust` authenticates the response policy.
Plain `/chains` may contain runtime availability, so it is not used for this check.
The API header packer may omit an additional domain record when the combined
header budget is exceeded. Publisher signing/assembly already rejects a chains
and domains pair that exceeds that budget; the monitor still treats missing
domains as a delivery failure, never a healthy chains-only response. Tests cover
both the current domain catalog and an oversized, omitted domain payload.
The monitor validates each required scope independently, including current trust
revocations/authority, and compares its signed sequence with the newest published
`metadata-*` GitHub release. It fetches only this bounded response and release
metadata, not a full descriptor catalog. Optional authenticated dApp search is not
an exhaustive delivery probe; dApp record expiry remains seven days.

Alerts cover HTTP/network failures, missing/invalid/expired proofs, mixed serving
versions, release lag beyond a two-hour delivery grace period, validity remaining
at or below 48 hours (including finite authority), incomplete/unreadable releases,
and no release for five days. Chains can remain healthy while domains alert.
Strict validation of every record in a new release remains the API updater's job.

The monitor creates/reopens **Metadata delivery or expiry needs attention**, a
separate bot-owned issue assigned to the existing allowlisted `metadata-review`
reviewers. New problems and daily UTC reminders post fresh mentions; retries are
deduplicated. Recovery comments and closes only that monitor issue. Pending
approval issues are never modified, approved or closed by this check. GitHub
inbox, email and mobile notifications still depend on each reviewer's settings.
If GitHub or reviewer lookup itself is unavailable, the workflow fails visibly;
it cannot deliver an issue notification through an unavailable GitHub service.

CI, preparation, notification, signing and delivery monitoring all pin the
API-approved Node `24.22.1`. Workflow tests reject a mismatched runtime pin.

### Focused verification

Use synthetic keys only. Run these suites sequentially on the verification host;
neither command approves, signs a production release or dispatches a workflow:

```sh
node --test --test-concurrency=1 src/publicationValidity.test.ts src/publicationLifecycle.test.ts src/publisher.test.ts src/deliveryMonitor.test.ts src/approvalNotification.test.ts src/workflows.test.ts
node --test --test-concurrency=1 src/*.test.ts
```

Every curated public network must declare boolean `isTestnet`, including `false`
for mainnets. Historical records without it remain verifiable; new preparation
requires explicit classification. Deploy updated consumers before publishing a
catalog with a new field, since older consumers reject unknown network fields.

### Reviewing a change

After preparation, one GitHub issue assigned to the configured reviewers links to
the exact batch, source comparisons and before/after report. A new candidate
updates that issue and posts a fresh mention; publication closes it. Enable GitHub
and email notifications for participating conversations in your personal settings
to receive these alerts. Workflow completion notifications alone do not cover a
job that is still waiting for approval.
Preparation failures also alert the reviewers, including failures before a report
can be created; an earlier valid approval request remains available.

New preparations supersede older unsigned preparations and unapproved review jobs.
Every comparison is against the last published catalog, so still-needed changes
remain visible in the latest batch. Already approved signing is serialized
separately and is not cancelled by a newer review request. A failed preparation
leaves the previous approval request available. Snapshots and reports are retained
for 35 days, beyond GitHub's 30-day environment approval wait limit.

Merging a catalog edit automatically prepares a batch and requests approval when
its contents differ from the published catalog. **Publish signed metadata → Run
workflow** can also prepare a batch manually. Scheduled preparations check upstream
sources even when the curated catalog has not changed.

The prepare job's Actions summary links to the baseline release and exact source
comparisons, counts exact logo URL edits and groups descriptor documents,
and shows before/after field values. Download the `prepared-metadata` artifact
for `review.md` (readable report), `review.json` (complete values and scopes), and
`prepared.json` (the snapshot bound to approval).

Every logo URL edit shows the complete old and new URLs and remains subject to
the existing manual approval gate. Signing and verification continue to bind the
exact URL. Image content is not compared or used to suppress URL changes.
Schema-reference edits remain visible and also require approval.

Descriptor documents are stored once and referenced by digest in prepared and
signed-role artifacts, as they already are in published releases. Review JSON
uses `descriptorPayloads` for descriptor additions/removals and `documents` for
shared field changes; every affected scope remains listed. These references do
not change approval digests, signed statements, or the public release format.
Review notes warn when a descriptor reaches 90% of the existing 192 KiB canonical
record limit. Formatted input files have a separate bounded 1 MiB read allowance.

Releases also retain `review-provenance.json` for future source comparisons. It is
informational and is matched to the verified catalog digest; consumers continue
to use `publication.json` and `publication.sha256` without a protocol change.
