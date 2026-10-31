# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Releases are published automatically by `.github/workflows/release.yml` when the `version` in `package.json` is bumped and merged into `main` (contributor PRs go to `develop`).

## [Unreleased]

### Changed

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
