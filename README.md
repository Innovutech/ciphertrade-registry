# CipherTrade Registry

Public repository: [Innovutech/ciphertrade-registry](https://github.com/Innovutech/ciphertrade-registry).
Maintains signed public configuration, asset metadata and Clear Signing descriptors.

This is an independent publication project, not an API service. It has no HTTP
signing endpoint. The wallet API has no publisher key or signing permission.

For the first setup, follow [DEPLOYMENT.md](DEPLOYMENT.md) in order, including Metro
testing and production release gates.

## Deployment gate

Production setup is intentionally incomplete until the operator provisions the
GitHub repository, required reviewers and keys. `trust/roots.json` has no trusted
keys; there is deliberately no production `trust/policy.json` or test-key fallback.
`node scripts/workflow.mjs check-setup` must pass before publication/release.

1. Put this project in the chosen dedicated repository, with protected `main`.
2. Configure `metadata-tokens`, `metadata-descriptors` and `metadata-configuration`
   environments. Restrict them to protected branches (the workflow only runs on
   protected `main`), require the authorized reviewers
   and disallow unreviewed workflow changes. Each environment has ONLY its own
   `METADATA_SIGNING_KEYS` JSON secret (`{"key-id":"0x..."}`). Do not share signing
   credentials across environments or with the API.
   Record the reviewers' stable numeric GitHub account IDs in `trust/reviewers.json`.
   CI verifies required reviewers and branch protection settings before preparation;
   an absent or unverifiable approval gate fails publication.
3. Keep an offline root identity. Install its public key/id in `trust/roots.json`,
   API `data/metadata-trust-roots.json`, and app `src/data/metadataTrustRoots.json`.
   Create a root-signed `trust/policy.json` with `signTrust` from `src/publisher.ts`.
   The policy authorizes separate `token/asset`, `descriptor`, and
   `networks/domains/classification` publishing keys, with lifetimes and minimum
   publication sequences. Only the root can authorize new keys or revocations.
4. Validate the root policy before committing it. Never commit private keys. A
   GitHub environment approval authorizes a signing job; it is not the signature
   that clients verify. Root recovery requires another already provisioned root
   or a reviewed app update; a compromised root cannot securely revoke itself.
5. Review the prepare job's exact digest, source revisions and artifact changes
   before approving the signing environments. Preparation has no signing secrets;
   signing jobs never check out or execute upstream code. The final job verifies
   all independently signed role outputs before publishing immutable release assets.
6. Deliver the release `publication.json` to the API's `METADATA_PUBLICATION_FILE`
   using an atomic file replacement. The API validates the entire snapshot before
   installing it and checks for updates in the background, not during requests.
   The accompanying SHA-256 is a transport check, NOT the trust anchor.

Repository admins/workflow maintainers and approved upstream content remain trusted.
Schema checks and signatures do not establish contract semantics or token safety.

## Sources and ownership

`catalog/` is the canonical public source, seeded from existing curated token and
public network data. Private/server RPC config must never be copied here. The
existing API/client JSON files are compatibility fallbacks, not a second place
to edit new live publications. Regenerate fallbacks deliberately for app releases.

Trust Wallet ingestion covers every available asset under supported chain folders,
not only curated assets. It uses the checked-out exact revision; imported identities
remain unverified/non-default. Curated metadata wins. Statuses other than `active`
are not published as active token identities. Logo hashes bind fetched image bytes;
the app downloads images directly and checks hashes through its existing cache.
Image authenticity is separate from a verified-token badge.

COTI list imports and the old `tokens.ciphertrade.org` consumer are retired in the
wallet API. Accepted metadata must be preserved in our own catalog. Do not remove
the old public website/repository without checking other consumers.

Future community/project metadata belongs in a separately reviewed source adapter.
Project-authored metadata must not grant official/verified/default classifications.
Automatic deployment of reviewed community changes is not automatic publication
approval unless explicitly configured as the accepted review policy.

## Format and compatibility

Protocol v1 uses domain-separated secp256k1 ECDSA with canonical JSON and compact
EIP-2098 signatures, implemented using the existing ethers library. It is a wallet
publication protocol, not a claim of ERC-7730 wire-format/signature conformance.
Descriptors themselves retain their supported ERC-7730 format.

Each signature binds schema, kind, scope, signer id, sequence, issue/expiry times
and payload digest. Roots authorize roles and global minimum sequences. Record
scope binds chain/address and, for descriptors, the function selector. Unsupported
formats retain legacy decoding; encrypted SDK and execution protections are separate.

Existing token metadata and network endpoints retain JSON structures. Additive
detached evidence headers are bounded to 6 KiB together. Large batches may have
partial evidence, but never truncated legacy bodies or implied full authentication.
Only descriptor lookup needs a new endpoint. Apps cache requested records only.

Expiry is checked even on verified cache hits. Signatures are rechecked after disk
restore, and trust version checkpoints resist rollback while retained. Fresh
installations/cache loss cannot know every historical publication, and a malicious
distributor can withhold new revocations until accepted policy expiry. An expired
policy cannot authenticate cached records. Offline bundled/raw fallbacks remain.

The workflow prepares updates twice weekly with seven-day record lifetimes; review and publish before
expiry, or adjust the schedule/lifetimes together within protocol bounds. Trust
policy/delegate renewal is an operator responsibility. No indefinite freshness is
inferred from an unrelated token-cache refresh.

## Local commands

- `npm ci --ignore-scripts`
- `npm test`
- `node src/cli.ts prepare config.json work/prepared.json`
- `node src/cli.ts sign sign-config.json dist/publication.json`

Keep the app, API and publisher protocol copies byte-identical using the API's
`scripts/sync-metadata-protocol.mjs`. No new native mobile dependency is needed.

The local checkout may still be named `cipher-metadata-publisher`; this does not
change the GitHub repository name or workflow behavior.

## Root administration and operational checks

On the offline administration machine only, set `METADATA_ROOT_KEY` through your
secret-management mechanism. `node scripts/trust-policy.mjs public-key` prints only
its public key. Put that public key and a stable ID into the three root files.
Create an input JSON containing `rootId` and `payload` matching the `TrustPayload`
type in `src/protocol.ts`: schema 1, increasing sequence, integer millisecond issue
and expiry times, separate delegated public keys, revoked payload digests and
positive minimum sequences for every kind (`token`, `asset`, `descriptor`,
`networks`, `domains`, `classification`). Each delegate needs `id`, `publicKey`,
`kinds`, `notBefore` and `expiresAt`. Give keys time to cover the full publication
validity interval. Keep the root policy at or below 90 days.

Run `node scripts/trust-policy.mjs sign policy-input.json new-policy.json`.
Review that public output before replacing `trust/policy.json`. The script will
not overwrite a file or log private keys. Keep the root private key offline;
delegate private keys go only into their corresponding GitHub environment secret.
Do not put root keys in Actions, the API, app configuration, chat or shell history.

Run the API build, then `node scripts/check-metadata-publication.mjs <artifact>`
before replacing its active artifact. This command verifies current signatures,
expiry, the public network schema and server chain applicability without serving
requests or signing anything. Set `METADATA_PUBLICATION_FILE` to the installed
absolute path and keep the previous artifact for recovery. Atomically replace the
file rather than editing it in place. Check for both `Cipher-Metadata` and
`Cipher-Metadata-Trust` in `/chains`, `/tokens/metadata` and a covered descriptor
response through the actual production proxy/CDN. Configure response-header limits
to allow the additional 6 KiB, expose those headers to web consumers, and preserve
body/header pairing in every cache. Do not cache descriptor 404s for long periods.

Classification removal is explicit: add an entry to
`catalog/classification-overrides.json` with `chainId`, `address`, `default:false`,
`verified:false`, `verification:"unverified"`. Removing a token from a curated file
alone is not a signed revocation. Keep removals published while supported clients
can retain the old bundled classification. The bounded client cache can forget
records after eviction/cache loss; update bundled classifications in app releases
as well. Token identity authenticity is never a safety/verification badge.

`work/review.json` lists added, materially changed and removed scopes relative to
the preceding authenticated release. Mere source-revision or identical-image-hash
renewals are excluded from that change list, but remain bound into the approved
snapshot digest. Review source commits and the full prepared artifact as well.

Shared ERC-7730 includes are resolved from the checked-out source tree before
signing, with cycle/path/size limits; no remote include or source script runs in
signing jobs. Final artifacts deduplicate descriptor bodies; per-scope statements
still bind their full resolved digest. The optional RN `scripts/audit-erc7730.mjs`
checks a real registry checkout. Unsupported encrypted/factory/packed semantics
retain explicit fallback, not guessed formatting.

Expiry uses the device/server clock. Version floors protect retained state but
are not a secure hardware clock, complete TUF implementation or immediate global
revocation system. Monitor successful publication/expiry and renew ahead of time.
The API retains a last-good snapshot in memory; durable artifact retention and
atomic delivery are deployment responsibilities. For rollback, publish the prior
reviewed content with a NEW sequence; do not lower version floors or disable checks.
