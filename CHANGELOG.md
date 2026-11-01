# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Releases are published automatically by `.github/workflows/release.yml` when the `version` in `package.json` is bumped and merged into `main` (contributor PRs go to `develop`).

## [Unreleased]

### Added

- **`zk-smart-account-kit-sdk/zk-multisig`** — the private M-of-N multisig of [microchain-zk-signers](https://github.com/MicrochainLabs/microchain-zk-signers): salted state root (`computeStateRoot`, `generateSalt`, `parseSalt`), signers tree (`buildMultiSigTree`), private-state derivation and backup (`createMultiSigState`, `serializeMultiSigState`, `parseMultiSigState`), circuit inputs from raw signatures (`buildMultiSigCircuitInput`, `recoverMultiSigSigner`), public-input encoding, and `generateMultiSigProof` / `generateStateValidationProof`.
- **`zk-smart-account-kit-sdk/zk-multisig/safe`** — viem-only Safe integration (no Safe SDK, no Hardhat): offline Safe transaction hash (equal to the Safe's own `getTransactionHash`), `signSafeTransaction`, `encodeSafeSignatures` (ZK signer next to ordinary owners), `generateSafeTransactionProof`, ZK signer factory (`createZKSigner`, `computeZKSignerAddress`, `isValidZKSignature`), Safe deployment (`encodeSafeSetup`, `encodeCreateSafeProxy`, `predictSafeAddress`).
- **`zk-smart-account-kit-sdk/zk-multisig/nexus`** — viem-only Nexus / ERC-7579 integration for EntryPoint v0.7: account factory (`createNexusAccount`, `computeNexusAccountAddress`), validator state (`getNexusAccountStatus`), `prepareNexusUserOperation`, `generateNexusUserOperationProof`, `sendNexusUserOperation` with `AAxx` error explanations, validator calls (`encodeInstallValidatorCall`, `encodeUpdateStateRootCall`).
- `createBarretenberg()` (every subpath) and `ProveOptions.verifierTarget` / `ProveOptions.verify`.
- `ChainStateError` and `UnsupportedEnvironmentError`.
- Tests that run the SDK against the real contracts: unit tests with an in-memory chain, `test/onchain` (Anvil + the generated Honk verifiers, ERC-8039 adapters, ZK signer factory and Nexus validator, from `test/fixtures/contracts`), and `test/integration` (real Safe v1.4.1, Nexus, ZK validator factory and EntryPoint v0.7 built by `scripts/build-integration-contracts.mjs`). New CI jobs run them.
- `scripts/sync-contracts.mjs`, `scripts/build-integration-contracts.mjs`; `sync-circuits` also copies the multisig circuits.
- Examples `examples/zk-multisig-safe.ts` and `examples/zk-multisig-nexus.ts`, executed by the integration tests.
- Typed errors (`ZKSdkError` and subclasses with stable `code`s), exported from the root and from the new `zk-smart-account-kit-sdk/errors` subpath.
- CommonJS build alongside ESM, with correct types for both (`require` and `import` conditions); verified with `publint` and `are-the-types-wrong`.
- `ProveOptions.barretenberg` to reuse one Barretenberg instance across proofs; `MerkleTreeLike`, `LeanIMT`, `CompiledCircuit` types.
- Test suite: unit tests with coverage thresholds, golden vectors from the Noir tests, differential tests against `@zk-kit/lean-imt`, and end-to-end tests that run the real compiled circuits (witness, prove, verify) for every primitive.
- ESLint (type-aware), Prettier, husky + lint-staged pre-commit hook, TypeDoc API docs, runnable `examples/`.
- CI: lint, format, tests with coverage on Node 20/22/24, build + package lint, install/import smoke test on Node 20/22/24, dependency audit, CodeQL, informational compatibility job against the latest stable `@aztec/bb.js`; Dependabot; CODEOWNERS; CycloneDX SBOM attached to every GitHub Release.
- `docs/`: threat model, compatibility matrix, versioning and deprecation policy.
- GitHub Actions release workflow (GitHub Release and npm publish with provenance).
- `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, `NOTICE`, issue and pull request templates, README badges.

### Fixed

- **Proofs could not be verified on-chain.** Every prover generated the default Barretenberg proof flavour, but the Solidity `HonkVerifier` contracts only accept the EVM one (`verifierTarget: "evm"`, keccak transcript, zero-knowledge) that the microchain-zk-signers and zk-smart-account-kit tooling use. Proofs are now generated for the EVM by default and verified locally before being returned (`ProveOptions.verify`). The previous end-to-end tests verified with the default flavour and therefore did not catch this; they now verify with the EVM flavour, and the multisig proofs are additionally verified by the real contracts on-chain.
- A Barretenberg instance could silently die: the native backend connects to its prover process lazily and gives up after five seconds if the event loop is blocked, which witness generation does for the larger circuits ("Timeout connecting to bb socket"). Witness generation now runs before the instance is created, and `createBarretenberg()` returns a connected instance for sharing.
- `encodeSafeSignatures` accepted an invalid owner address when given a single signature.
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

### Changed

- **Breaking (behaviour):** proofs from every `generate*Proof` are now EVM-flavoured by default (see Fixed). Anything that verified proofs off-chain with the default Barretenberg flavour must pass `{ verifierTarget: "..." }` explicitly.
- The `zk-multisig` subpath is back with a new design — salted state root, private threshold, Safe and Nexus integrations — matching microchain-zk-signers. It is not compatible with the unsalted `zk-multisig` removed above.
- `proveCircuit` generates the witness before it creates a Barretenberg instance, and `generate*Proof` verify the proof locally before returning it.
- **Breaking:** invalid input now throws `InvalidArgumentError` (a `ZKSdkError`) instead of `RangeError`/`Error`/`SyntaxError`; not-found conditions throw `NotFoundError`.
- **Breaking:** `selectorToField` (and every function taking a selector) requires exactly `0x` + 8 hex digits.
- **Breaking:** `buildSignersTree`, `buildLabelsTree`, `buildScopeTree` and `createZKLabels` reject empty and over-capacity inputs; `removeLabel` refuses to remove the last label (an empty registry has no root).
- **Breaking:** `parseSignature` accepts exactly 64 or 65 bytes (previously any length ≥ 64); `padConstraints`/`padParamValues` throw on more than 4 entries; `computeRuleLeaf` rejects `valueMax`/range bounds above `2^128 − 1`.
- **Breaking:** `generate*Proof` take `circuit: unknown` (validated) plus an optional trailing `options`; `createZKLabels(labels, circuit, options?)`.
- **Breaking:** `engines.node` is now `>=20.19.0`. Node 18 never worked for the ESM build (`@iden3/js-crypto` throws on import, and `@noble/hashes@2` requires Node ≥ 20.19); the previous `>=18` was incorrect.
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
