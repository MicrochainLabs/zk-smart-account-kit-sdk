# Versioning and deprecation policy

The SDK follows [Semantic Versioning](https://semver.org/).

## What counts as the public API

- Everything exported from `zk-smart-account-kit-sdk`, `/zk-signer`, `/zk-label`, `/zk-scope`, `/zk-multisig`, `/zk-multisig/safe`, `/zk-multisig/nexus` and `/errors`, with the behaviour documented in the generated API docs (`pnpm docs:api`).
- The `code` of every `ZKSdkError` (`INVALID_ARGUMENT`, `NOT_FOUND`, `TREE_CAPACITY_EXCEEDED`, `INVALID_CIRCUIT`, `MISSING_PEER_DEPENDENCY`, `PROOF_GENERATION_FAILED`, `CHAIN_STATE_MISMATCH`, `UNSUPPORTED_ENVIRONMENT`). Error **messages** are not API.
- The byte-level outputs that must match the circuits and contracts: leaf and root values, circuit input field names, ABI layouts, the state-root construction, and the Safe signature and Nexus nonce layouts.
- The `abi` constants exported by `/zk-multisig/safe` and `/zk-multisig/nexus` follow the deployed contracts; they change only when the contracts do.

Not public: anything under `src/internal`, and any module path not listed in `package.json` `exports`.

## Version bumps

| Change | Bump |
|---|---|
| Bug fix with no change to leaf/root/ABI outputs | patch |
| New exports, new optional parameters, new error subclasses | minor |
| Removing or renaming exports; tightening validation so that previously accepted input is rejected; changing an error `code` | major |
| Anything that changes a leaf, root, circuit input or calldata byte for the same input | major, and requires a circuits/contracts compatibility note in the changelog |
| Changing the pinned circuit toolchain (`@noir-lang/noir_js`, `@aztec/bb.js`) | major (it forces a circuit and verifier redeploy) |

While the version is `0.x`, the same rules apply with **minor** taking the role of major and **patch** the role of minor; breaking changes are always listed under **Breaking** in `CHANGELOG.md`.

## Deprecation

1. The API is marked `@deprecated` in TSDoc with the replacement and the version it will be removed in.
2. It keeps working for at least one minor release (≥ 90 days once the SDK is ≥ 1.0).
3. The removal is listed in `CHANGELOG.md` under **Breaking** in the next major.

Security fixes may shorten this window; they are announced through a GitHub Security Advisory.

## Supported versions

Security fixes go to the latest release (see [SECURITY.md](../SECURITY.md)). From 1.0 the previous major will receive security fixes for 12 months.
