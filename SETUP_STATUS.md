# Registry Setup

Repository: `Innovutech/ciphertrade-registry` (public, `main`).
Reviewer: `iamsstef`, GitHub user ID `115187950`.

## Intended GitHub configuration

- CI check `Registry checks` runs the publisher tests without signing secrets.
- `main` requires pull requests and the current CI check; force pushes/deletion are
  disabled. Zero additional PR approvals accommodates a single operator. This is
  distinct from signing approval, which is mandatory in every signing environment.
- `metadata-tokens`, `metadata-descriptors`, `metadata-configuration` require
  `iamsstef` approval and accept protected branches only.
- Self-review is permitted so this sole operator can approve manually triggered
  signing runs. Add another reviewer before enabling prevention of self-review.
- Workflow token defaults are read-only and cannot approve pull requests.
- `Publish signed metadata` remains disabled until key provisioning is complete.

Remote settings must be read back after setup; source files alone do not enforce
GitHub environment/branch settings. The setup completion message records the
actual verified result and links the first CI run.

## Remaining operator steps

1. Generate the offline root and three distinct delegated key pairs on a trusted
   administration machine. The root private key must stay offline; none was
   generated or stored during GitHub repository setup.
2. Install the same PUBLIC root list in publisher `trust/roots.json`, wallet API
   `data/metadata-trust-roots.json`, and app `src/data/metadataTrustRoots.json`.
3. Create the root-signed public `trust/policy.json` as documented in DEPLOYMENT.md.
   Put each delegate's private key into `METADATA_SIGNING_KEYS` only in its own
   environment. Never add the root private key as a GitHub secret.
4. Submit the public configuration as a pull request; wait for Registry checks and
   merge. Do not attempt a direct push to protected `main`.
5. Enable Publish signed metadata, run it manually, review the exact prepared
   snapshot/digest and approve the three environments. This performs the first
   production-key/full-inventory publication, which is not yet verified.
6. Validate and install its release artifact on the wallet API, set
   `METADATA_PUBLICATION_FILE`, restart for code/root/environment changes, and
   verify the evidence headers through the real proxy/CDN. No automatic API-server
   delivery is configured by repository setup.
7. Full Metro reload with the matching public roots, then Android/iOS acceptance
   tests. No native rebuild is needed specifically for this refactor.

Root lists intentionally remain empty until the key ceremony. Bundled/fallback
behavior is available, but authenticated remote coverage is not active yet.
See DEPLOYMENT.md for commands, safety checks, expiry and renewal requirements.
