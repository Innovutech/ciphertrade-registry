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

Every curated public network must declare boolean `isTestnet`, including `false`
for mainnets. Historical records without it remain verifiable; new preparation
requires explicit classification. Deploy updated consumers before publishing a
catalog with a new field, since older consumers reject unknown network fields.

### Reviewing a change

The prepare job's Actions summary links to the baseline release and exact source
comparisons, counts exact logo URL edits and groups descriptor documents,
and shows before/after field values. Download the `prepared-metadata` artifact
for `review.md` (readable report), `review.json` (complete values and scopes), and
`prepared.json` (the snapshot bound to approval).

Every logo URL edit shows the complete old and new URLs and remains subject to
the existing manual approval gate. Signing and verification continue to bind the
exact URL. Image content is not compared or used to suppress URL changes.
Schema-reference edits remain visible and also require approval.

Releases also retain `review-provenance.json` for future source comparisons. It is
informational and is matched to the verified catalog digest; consumers continue
to use `publication.json` and `publication.sha256` without a protocol change.
