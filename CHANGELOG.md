# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Releases are published automatically by `.github/workflows/release.yml` when the `version` in `package.json` is bumped and merged into `main` (contributor PRs go to `develop`).

## [Unreleased]

### Removed

- **Breaking:** the `zk-multisig` primitive and its `zk-smart-account-kit-sdk/zk-multisig` subpath export, along with its root re-exports (`generateMultiSigProof`, `buildMultiSigCircuitInput`, `encodeMultiSigInitData`, etc.), following its removal from zk-smart-account-kit.

### Changed

- Upgraded the optional peer dependencies to `@noir-lang/noir_js` `1.0.0-beta.22` and `@aztec/bb.js` `5.0.0-nightly.20260522`; circuits must be compiled with Nargo `1.0.0-beta.22` (zk-smart-account-kit).
- **Breaking:** Merkle path direction bits (`merkle_proof_indices`, `proof_index`, `proof_indices`) are now `boolean[]` instead of `number[]`, matching the `bool` circuit inputs of the upgraded circuits.
- `LICENSE` and README now state Apache-2.0, matching `package.json` and the npm package (previously an MIT `LICENSE`).
- Repository `version` aligned with the version published on npm (`0.1.5`; the published build is identical to the repository source).
- Standardised on `pnpm` (removed `package-lock.json`).

### Added

- GitHub Actions CI (typecheck and build on Node 18/20/22) and release workflow (GitHub Release and npm publish with provenance).
- `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, `NOTICE`, issue and pull request templates, README badges.

## [0.1.5], [0.1.4]

Published to npm; no source differences from the code tagged as `v0.1.5`.

## [0.1.3]

- Added `zk-scope` and `zk-signer` documentation; fixed build errors.

## [0.1.0]

Initial release: `zk-label`, `zk-signer`, `zk-scope` and `zk-multisig` primitives.
