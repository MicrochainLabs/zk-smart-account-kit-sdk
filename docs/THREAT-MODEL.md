# Threat model

Scope: `zk-smart-account-kit-sdk` — the off-chain TypeScript layer between an application and the Noir circuits / ERC-7579 validators from [zk-smart-account-kit](https://github.com/MicrochainLabs/zk-smart-account-kit). It is not a substitute for an audit of the circuits and contracts, where proof soundness actually lives.

## What the SDK does

1. Computes Poseidon leaves and Merkle roots that must be **bit-identical** to the circuits' (`lib/zk_signer`, `lib/zk_labels`, `lib/zk_scope`).
2. Builds the private/public circuit inputs, including padded Merkle paths.
3. Runs witness execution and UltraHonk proving in-process (optional peers `@noir-lang/noir_js`, `@aztec/bb.js`).
4. ABI-encodes init data, public inputs and proof calldata for the on-chain validators.

## Assets and trust boundaries

| Asset | Where it lives | SDK behaviour |
|---|---|---|
| Signer private keys | Wallet / HSM / caller | **Never accepted.** The SDK only receives the public key and a finished signature. |
| Private witness (signer identities, label names, scope rules, Merkle paths) | Caller process memory | Used in-process only. The SDK performs no I/O, networking, logging or telemetry. |
| Compiled circuit artifacts | Supplied by the caller | Shape-checked (bytecode present, ABI parameters match the expected circuit exactly). **Not authenticated** — see "Circuit provenance". |
| Roots / proofs / calldata | Public | Validated before encoding (32-byte words, field range). |

Proving runs in the caller's process: a compromised host or a malicious dependency can read witnesses. Run proving on a trusted host and keep dependencies pinned (`pnpm-lock.yaml`, provenance-signed releases).

## Threats and mitigations

| # | Threat | Mitigation in the SDK | Residual risk |
|---|---|---|---|
| T1 | SDK and circuit disagree on a leaf/root, so a valid account root is unprovable or a wrong root gets installed | Golden vectors from the Noir tests; end-to-end tests run the real circuits on SDK output for every tree/path shape (`test/e2e`) | Drift after a circuit change → re-run `pnpm sync-circuits` and the E2E suite on every circuit upgrade |
| T2 | Tree larger than the circuit depth (e.g. 17 signers) → root installed on-chain that **no one can ever prove against** (account bricked) | `TreeCapacityError` at build time (16 signers/labels, 64 scope rules) and at proof time | None for SDK users; raw root computation by other tools is unprotected |
| T3 | Empty registry produces an `undefined` root | `InvalidArgumentError` instead | — |
| T4 | Malformed input silently truncated or wrapped (e.g. full calldata passed as selector, >4 params/constraints, out-of-field values, wrong-length hashes) | Strict runtime validation on every public entry point; typed `ZKSdkError`s | — |
| T5 | Wrong circuit file passed to a prover | `InvalidCircuitError` (ABI parameter names must match exactly) | A *malicious* artifact with the right ABI is not detected |
| T6 | Wasted proving work / confusing failures on bad signatures, wrong signer, rule violations | Off-circuit pre-flight: pubkey→address, low-S, ECDSA verification, tx-vs-rule checks | The pre-flight is a UX aid, **not a security control**; the circuit remains the authority |
| T7 | Resource leaks / hung processes after proving | Barretenberg instance is destroyed in `finally` unless the caller supplied it | Caller-owned instances are the caller's to destroy |
| T8 | Vulnerable transitive dependency reaching consumers | Merkle tree implemented in-repo (no `@zk-kit/lean-imt` → `ethers` → `ws` chain); `pnpm audit --prod` is clean and gated in CI; Dependabot; SBOM per release | Upstream advisories in `viem`, `@noble/curves`, `@iden3/js-crypto` |
| T9 | Tampered release | npm provenance (`--provenance`), tag/Release created only after CI passes on `main`, CycloneDX SBOM attached to each GitHub Release | Trust in GitHub Actions and the npm registry |

## Privacy properties and limits

- A proof reveals only its public inputs: `txn_hash` + `signers_root` (signer), `registry_root` + `label_commitment` (label), target/selector/value/`calldata_hash` + `scope_root` (scope).
- The anonymity set of a signer proof is the set of signers under the root (at most 16). Small sets give weak anonymity; the on-chain root itself is public, and root updates are visible.
- `label_commitment` is deterministic per (label, address): the same pair is linkable across proofs.
- Proof timing, transaction metadata and the public `txn_hash` are visible on-chain.

## Out of scope (not enforced here)

- **Replay protection and freshness** — handled by the validator contract / account nonce, not the SDK.
- **Circuit and contract soundness** — see [zk-smart-account-kit](https://github.com/MicrochainLabs/zk-smart-account-kit) and the contracts audit.
- **Circuit provenance** — the SDK cannot tell whether a `zk_signers.json` was compiled from audited sources. Pin the artifact hash that matches your deployed verifier (the `sha256` values in `test/fixtures/circuits/manifest.json` show the pattern).
- **Key management and signing UX.**

## Findings for the circuit repository (discovered while writing the E2E suite)

These are in `zk-smart-account-kit`, not in this SDK. The SDK rejects the affected inputs defensively, but a malicious prover can bypass any SDK check, so they must be fixed in the circuit.

1. **`zk_scope_validation` truncates to `u128` instead of range-checking.** `txn_value as u128`, `rule_value_max as u128` and range-constraint comparisons cast a `Field` to `u128`, which wraps modulo 2^128. Verified against the compiled circuit: a range-constrained parameter of `2^128 + 5` satisfies `rangeMax(100)`, and `txn_value = 2^128 + 1` satisfies a small `valueMax`. Recommended fix: assert the operands are `< 2^128` (e.g. `assert_max_bit_size::<128>()`) before comparing.

## Reporting

See [SECURITY.md](../SECURITY.md).
