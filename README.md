# CipherTrade Registry

Signed public configuration, token metadata and ERC-7730 Clear Signing descriptors for CipherTrade.

- `catalog/`: curated assets, networks and domain records.
- `src/`: source importers, validation and signing.
- `trust/`: public keys, trust policy and reviewer configuration.
- `.github/workflows/`: CI and approved publication.

Sources include CipherTrade's curated catalog, Trust Wallet assets and the ERC-7730 registry.
External token metadata does not grant verified status.

## Development

Requires Node.js 24 or later.

```sh
npm ci --ignore-scripts
npm test
```

## Publishing

Catalog changes require reviewer approval. A separate scheduled workflow renews
the last approved catalog without importing upstream changes. Both use the same
serialized signer. Consumers verify short-lived records using trusted public keys;
root-authorized publishing keys can have non-expiring authorization.
Private keys belong in protected signing environments, never in this repository.

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
