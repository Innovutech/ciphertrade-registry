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

The publication workflow prepares a versioned snapshot, requires reviewer approval,
and releases signed artifacts. Consumers verify them using trusted public keys.
Private keys belong in protected signing environments, never in this repository.
