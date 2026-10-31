# Contributing to zk-smart-account-kit-sdk

Thank you for your interest in contributing! This SDK provides TypeScript helpers (tree builders, circuit input builders, ABI encoders and proof generation) for the ZK primitives in [zk-smart-account-kit](https://github.com/MicrochainLabs/zk-smart-account-kit) and [microchain-zk-signers](https://github.com/MicrochainLabs/microchain-zk-signers).

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Prerequisites](#prerequisites)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Making Changes](#making-changes)
- [Branching Model](#branching-model)
- [Submitting a Pull Request](#submitting-a-pull-request)
- [Releases](#releases)

---

## Code of Conduct

This project follows the [Contributor Covenant](./CODE_OF_CONDUCT.md). By participating you agree to uphold it. Report unacceptable behavior to the maintainers at **security@microchainlabs.xyz**.

---

## Prerequisites

| Tool | Version |
|---|---|
| [Node.js](https://nodejs.org/) | 20+ for development (the published package supports 18+) |
| [pnpm](https://pnpm.io/) | 10 |
| Git | any |

---

## Development Setup

```bash
git clone https://github.com/MicrochainLabs/zk-smart-account-kit-sdk.git
cd zk-smart-account-kit-sdk
pnpm install
pnpm verify
```

`pnpm verify` runs everything CI runs: typecheck, lint, format check, the full test suite with coverage thresholds, the ESM + CJS build, package lint (`publint`, `are-the-types-wrong`), the API docs build and an install/import smoke test. A pre-commit hook (husky + lint-staged) formats and lints staged files.

Useful scripts:

| Script | Purpose |
|---|---|
| `pnpm test` / `pnpm test:unit` / `pnpm test:e2e` | all tests / fast unit tests / end-to-end proof tests |
| `pnpm test:coverage` | tests with coverage thresholds (what CI runs) |
| `pnpm sync-circuits [path]` | refresh `test/fixtures/circuits` from a compiled zk-smart-account-kit checkout |
| `pnpm docs:api` | generate API docs into `docs/api` |
| `pnpm audit:deps` | dependency audit |

`@noir-lang/noir_js` and `@aztec/bb.js` are optional peer dependencies used only for proof generation. They are pinned to the versions the circuits are compiled with (`1.0.0-beta.22` and `5.0.0-nightly.20260522`); install the same versions if you work on `prove.ts` files.

---

## Project Structure

```
src/
  zk-label/       Private label registry
  zk-signer/      Single-signer ECDSA proofs
  zk-scope/       Scope policy tree and rules
  internal/       Shared, non-public code: validation, Merkle tree, prover, Poseidon facade
  errors.ts       Typed errors
  index.ts        Root re-exports
test/             Unit tests; test/e2e runs the real circuits; test/fixtures/circuits holds compiled artifacts
examples/         Runnable examples (executed by the test suite)
docs/             Threat model, compatibility, versioning policy
scripts/          Build, circuit sync, install smoke test
```

Each primitive follows the same layout: `types.ts`, `tree.ts`, `circuit.ts`, `abi.ts`, `prove.ts`, `index.ts`.

---

## Making Changes

- The SDK is strict TypeScript, built for both ESM and CommonJS; match the surrounding style (Prettier and ESLint enforce it).
- Tree, leaf and hash logic **must** stay byte-for-byte compatible with the Noir circuits. Any change here is potentially breaking and needs a discussion issue first.
- Tree builders, circuit input builders and ABI helpers must stay browser-safe: do not import Node.js-only modules in them. Only `prove.ts` files may depend on the optional peer dependencies.
- Adding a new primitive: create `src/<name>/` with the layout above, re-export it from `src/index.ts` and add a `"./<name>"` entry to `exports` in `package.json`.
- Validate every public input at runtime and throw a typed error from `src/errors.ts` (never a bare `Error`).
- Update the README and `CHANGELOG.md` (under `[Unreleased]`) for user-facing changes.

### Tests

- Every change needs tests. Coverage thresholds are enforced in `vitest.config.ts` and must not be lowered.
- Anything that affects a leaf, root, circuit input or calldata byte needs an **end-to-end test** in `test/e2e` proving the real circuit still accepts the SDK's output, plus a golden vector where one exists in the circuit tests.
- After recompiling circuits, run `pnpm sync-circuits` and review the `manifest.json` diff.
- Follow [docs/VERSIONING.md](docs/VERSIONING.md) when deciding the version bump and deprecations.

---

## Branching Model

| Branch | Purpose |
|---|---|
| `main` | Latest released code. Every release is a tagged commit (`vX.Y.Z`) published to npm. Protected: no direct pushes. |
| `develop` | Integration branch for the next release. **All contributor PRs target this branch.** Protected: PR-only, CI and review required. |

Short-lived branches:

- `feat/*`, `fix/*`, `docs/*`, `test/*`, `chore/*`: branch from `develop`, merge back into `develop` via PR (squash-merge).
- `hotfix/*` (maintainers): branch from `main` for urgent fixes (e.g. security), merge into `main`, then merge back into `develop`.

Security issues must **not** be reported through public PRs; see [SECURITY.md](./SECURITY.md).

---

## Submitting a Pull Request

1. **Fork** the repository and create a branch from `develop`:
   ```bash
   git checkout -b feat/your-feature-name
   ```
2. Make your changes with clear commit messages (`feat:`, `fix:`, `docs:`, `test:`, `chore:`).
3. Make sure `pnpm verify` passes (CI runs the same checks, with tests on Node 20, 22 and 24 and a package smoke test on Node 18–24).
4. Open a PR against `develop` and fill in the pull request template.
5. A maintainer will review and may request changes.

---

## Releases

Releases are automated. To release, merge `develop` into `main` with a `version` bump in `package.json`. When CI passes on `main`, the release workflow:

1. creates the `v<version>` git tag and GitHub Release,
2. publishes the package to npm with provenance (skipped if that version already exists).

Maintainers: follow [Semantic Versioning](https://semver.org/) and move the `[Unreleased]` entries in `CHANGELOG.md` under the new version.
