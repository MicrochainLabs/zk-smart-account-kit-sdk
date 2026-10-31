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
| [Node.js](https://nodejs.org/) | 18+ |
| [pnpm](https://pnpm.io/) | 10 |
| Git | any |

---

## Development Setup

```bash
git clone https://github.com/MicrochainLabs/zk-smart-account-kit-sdk.git
cd zk-smart-account-kit-sdk
pnpm install
pnpm typecheck
pnpm build
```

`@noir-lang/noir_js` and `@aztec/bb.js` are optional peer dependencies used only for proof generation. They are pinned to the versions the circuits are compiled with (`1.0.0-beta.22` and `5.0.0-nightly.20260522`); install the same versions if you work on `prove.ts` files.

---

## Project Structure

```
src/
  zk-label/       Private label registry
  zk-signer/      Single-signer ECDSA proofs
  zk-scope/       Scope policy tree and rules
  index.ts        Root re-exports
  ambient.d.ts    Type stubs for optional peer dependencies
```

Each primitive follows the same layout: `types.ts`, `tree.ts`, `circuit.ts`, `abi.ts`, `prove.ts`, `index.ts`.

---

## Making Changes

- The SDK is ESM-only and strict TypeScript; match the surrounding style.
- Tree, leaf and hash logic **must** stay byte-for-byte compatible with the Noir circuits. Any change here is potentially breaking and needs a discussion issue first.
- Tree builders, circuit input builders and ABI helpers must stay browser-safe: do not import Node.js-only modules in them. Only `prove.ts` files may depend on the optional peer dependencies.
- Adding a new primitive: create `src/<name>/` with the layout above, re-export it from `src/index.ts` and add a `"./<name>"` entry to `exports` in `package.json`.
- Update the README and `CHANGELOG.md` (under `[Unreleased]`) for user-facing changes.

There is no automated test suite yet — adding unit tests for the tree and encoding helpers is a very welcome contribution.

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
3. Make sure `pnpm typecheck` and `pnpm build` pass (CI runs both on Node 18, 20 and 22).
4. Open a PR against `develop` and fill in the pull request template.
5. A maintainer will review and may request changes.

---

## Releases

Releases are automated. To release, merge `develop` into `main` with a `version` bump in `package.json`. When CI passes on `main`, the release workflow:

1. creates the `v<version>` git tag and GitHub Release,
2. publishes the package to npm with provenance (skipped if that version already exists).

Maintainers: follow [Semantic Versioning](https://semver.org/) and move the `[Unreleased]` entries in `CHANGELOG.md` under the new version.
