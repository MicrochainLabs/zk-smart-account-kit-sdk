# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Releases are published automatically by `.github/workflows/release.yml` when the `version` in `package.json` is bumped and merged into `main` (contributor PRs go to `develop`).

## [Unreleased]

### Fixed

- **`generateZKSignerProof` and `generateScopeProof` could not produce a proof** with the pinned `@aztec/bb.js`: they constructed `UltraHonkBackend` without the required Barretenberg instance (the hand-written type stub in `src/ambient.d.ts` hid this). All three provers now share one tested pipeline (`src/internal/prover.ts`) verified end to end against the real circuits.
- Barretenberg instances (worker threads/WASM) were never released, keeping Node processes alive after proving; they are now destroyed unless supplied by the caller.
- `removeLabel` could leave a stale entry behind when the address casing differed from the one used at insertion, and `addLabel`/`removeLabel` could leave the registry half-updated on error; updates are now atomic and compare by leaf.
- An empty signer/label/scope set produced an `undefined` root; it is now rejected.
- A tree with more entries than the circuit depth supports (more than 16 signers/labels or 64 scope rules) used to produce a root that could never be proven, and its Merkle proofs were silently truncated to the circuit depth; it is now rejected (`TreeCapacityError`).
- `selectorToField` silently zero-padded short selectors and truncated longer input (e.g. full calldata); `padConstraints`/`padParamValues` silently dropped extra entries.

### Security

- Removed the runtime dependency on `@zk-kit/lean-imt` (→ `@zk-kit/utils` → `ethers` → `ws`, which `npm audit` flagged as 2 high + 1 moderate in every consumer). The SDK now ships a small in-repo LeanIMT, pinned to the upstream implementation by differential tests. `pnpm audit --prod` is clean (gated in CI).
- Strict runtime validation of every public input (addresses incl. EIP-55 checksum, byte lengths and ranges, BN254 field range, `u128` bounds the circuit compares) before any hashing or proving.
- `zk_signers`: `buildZKSignerCircuitInput` verifies that the public key derives to the signer and that the signature is a valid low-S ECDSA signature of the hash before proving.
- `zk_scope_validation`: the transaction is checked against the matching rule (target, selector, value cap, parameter constraints) before proving.
- Provers verify the compiled circuit is the one they expect (`InvalidCircuitError`) and that the public-input count matches.

### Added

- Typed errors (`ZKSdkError` and subclasses with stable `code`s), exported from the root and from the new `zk-smart-account-kit-sdk/errors` subpath.
- CommonJS build alongside ESM, with correct types for both (`require` and `import` conditions); verified with `publint` and `are-the-types-wrong`.
- `ProveOptions.barretenberg` to reuse one Barretenberg instance across proofs; `MerkleTreeLike`, `LeanIMT`, `CompiledCircuit` types.
- Test suite: unit tests with coverage thresholds, golden vectors from the Noir tests, differential tests against `@zk-kit/lean-imt`, and end-to-end tests that run the real compiled circuits (witness, prove, verify) for every primitive.
- ESLint (type-aware), Prettier, husky + lint-staged pre-commit hook, TypeDoc API docs, runnable `examples/`.
- CI: lint, format, tests with coverage on Node 20/22/24, build + package lint, install/import smoke test on Node 18/20/22/24, dependency audit, CodeQL, informational compatibility job against the latest stable `@aztec/bb.js`; Dependabot; CODEOWNERS; CycloneDX SBOM attached to every GitHub Release.
- `docs/`: threat model, compatibility matrix, versioning and deprecation policy.
- GitHub Actions release workflow (GitHub Release and npm publish with provenance).
- `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, `NOTICE`, issue and pull request templates, README badges.

### Changed

- **Breaking:** invalid input now throws `InvalidArgumentError` (a `ZKSdkError`) instead of `RangeError`/`Error`/`SyntaxError`; not-found conditions throw `NotFoundError`.
- **Breaking:** `selectorToField` (and every function taking a selector) requires exactly `0x` + 8 hex digits.
- **Breaking:** `buildSignersTree`, `buildLabelsTree`, `buildScopeTree` and `createZKLabels` reject empty and over-capacity inputs; `removeLabel` refuses to remove the last label (an empty registry has no root).
- **Breaking:** `parseSignature` accepts exactly 64 or 65 bytes (previously any length ≥ 64); `padConstraints`/`padParamValues` throw on more than 4 entries; `computeRuleLeaf` rejects `valueMax`/range bounds above `2^128 − 1`.
- **Breaking:** `generate*Proof` take `circuit: unknown` (validated) plus an optional trailing `options`; `createZKLabels(labels, circuit, options?)`.
- **Breaking:** `package.json` `exports` now point to `dist/esm` / `dist/cjs`; deep imports of `dist/*` no longer work.
- Removed the `@zk-kit/lean-imt` dependency (see Security); `@noble/curves` is now a direct dependency (signature pre-flight).
- `@aztec/bb.js` and `@noir-lang/noir_js` are also dev dependencies, so the real typings and the end-to-end tests are used; `src/ambient.d.ts` is removed.
- Upgraded the optional peer dependencies to `@noir-lang/noir_js` `1.0.0-beta.22` and `@aztec/bb.js` `5.0.0-nightly.20260522`; circuits must be compiled with Nargo `1.0.0-beta.22` (zk-smart-account-kit).
- **Breaking:** Merkle path direction bits (`merkle_proof_indices`, `proof_index`, `proof_indices`) are now `boolean[]` instead of `number[]`, matching the `bool` circuit inputs of the upgraded circuits.
- `LICENSE` and README now state Apache-2.0, matching `package.json` and the npm package (previously an MIT `LICENSE`).
- Repository `version` aligned with the version published on npm (`0.1.5`; the published build is identical to the repository source).
- Standardised on `pnpm` (removed `package-lock.json`).

### Removed

- **Breaking:** the `zk-multisig` primitive and its `zk-smart-account-kit-sdk/zk-multisig` subpath export, along with its root re-exports (`generateMultiSigProof`, `buildMultiSigCircuitInput`, `encodeMultiSigInitData`, etc.), following its removal from zk-smart-account-kit.

## [0.1.5], [0.1.4]

Published to npm; no source differences from the code tagged as `v0.1.5`.

## [0.1.3]

- Added `zk-scope` and `zk-signer` documentation; fixed build errors.

## [0.1.0]

Initial release: `zk-label`, `zk-signer`, `zk-scope` and `zk-multisig` primitives.
