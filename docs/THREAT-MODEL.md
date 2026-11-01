# Threat model

Scope: `zk-smart-account-kit-sdk` — the off-chain TypeScript layer between an application and the Noir circuits and ERC-7579 / Safe contracts from [zk-smart-account-kit](https://github.com/MicrochainLabs/zk-smart-account-kit) and [microchain-zk-signers](https://github.com/MicrochainLabs/microchain-zk-signers). It is not a substitute for an audit of the circuits and contracts, where proof soundness actually lives.

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
| **ZK MultiSig private configuration** — signer list, threshold, salt | The operator's storage (`serializeMultiSigState`) | Never logged or sent anywhere. Raw state objects hold `bigint`s, so `JSON.stringify` on them throws instead of leaking. The backup is the only serialisation and is a secret. |

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

## ZK MultiSig: salt, threshold and state root

The on-chain state root is `Poseidon3(signers_root, Poseidon1(threshold), salt)`. The signer addresses and the threshold are low-entropy, so the root is hiding only thanks to the salt.

| Event | Consequence | SDK behaviour |
|---|---|---|
| **Salt lost** | No proof can ever be generated for that state root: the account is dead (a Safe can still be rescued by its other owners; a Nexus account only by another installed validator). | `serializeMultiSigState` / `parseMultiSigState` produce and verify a backup (the root is recomputed on restore, so a corrupted backup is caught at restore time, not when a proof is needed). Keep it with the signer list, encrypted, in more than one place. |
| **Salt leaked alone** | Nothing: it authorises nothing and reveals nothing by itself. | — |
| **Salt + signer list leaked** | De-anonymisation and cross-account linkability; signatures stay secure, no funds at risk. | The backup is as sensitive as the signer list. |
| **Salt generated poorly** | Dictionary attack on the root. | `generateSalt` uses the platform CSPRNG (`crypto.getRandomValues`, 248 bits), never returns zero, and throws `UnsupportedEnvironmentError` rather than falling back to a weak source. |
| **Unprovable configuration installed** (e.g. threshold above the signer count) | The account is bricked once the root is installed. | `createMultiSigState` rejects `threshold > signers`, duplicates and more than 5 signers before any root exists. |
| **Wrong values at proving time** | An opaque failure after proving work. | `buildMultiSigCircuitInput` checks the configuration against the on-chain root first (`ChainStateError`), and signatures (count, duplicates, membership, low-S). |

Additional threats specific to the integrations:

| # | Threat | Mitigation | Residual risk |
|---|---|---|---|
| M1 | Replay of a proof on another transaction, chain or account | The proof's public inputs are the signed hash and the state root; the Safe hash binds chain, Safe address and nonce, and the UserOperation hash binds sender, nonce, EntryPoint and chain. Tested: a proof for one transaction is rejected for another, on-chain. | Two accounts with the *same* state root accept each other's hashes only if the hash is the same, which it is not. Reusing one configuration (same salt) for several accounts makes them linkable. |
| M2 | A proof generated for the wrong verifier flavour is rejected on-chain after the work is done | Proofs are EVM-flavoured by default and verified locally; tested against the real generated verifiers. | — |
| M3 | Safe signature layout mistakes (offsets, ordering) | `encodeSafeSignatures` sorts owners and computes offsets; tested against a parser written from Safe's `checkNSignatures` semantics, and executed by real Safe contracts, including ZK signer + EOA owners. | Safe versions below 1.3.0 (no `chainId` in the EIP-712 domain) are not supported. |
| M4 | Nexus nonce/validator routing mistakes | The nonce key equals the validator address (validation mode 0); tested against a real Nexus account and EntryPoint v0.7. | Other Nexus validation modes (module enable, PREP) are not built by this SDK. |
| M5 | A bundler or RPC returns a different UserOperation hash | The hash is computed offline and tested equal to the EntryPoint's `getUserOpHash`; signers sign the offline value. | — |
| M6 | State-root rotation by an attacker | `updateStateRoot` is callable only by the account itself, i.e. through a UserOperation authorised by the *current* configuration; the new root needs a valid state-validation proof. | Compromise of ≥ threshold current signers. |

## Privacy properties and limits

- A proof reveals only its public inputs: `txn_hash` + `signers_root` (signer), `registry_root` + `label_commitment` (label), target/selector/value/`calldata_hash` + `scope_root` (scope).
- The anonymity set of a signer proof is the set of signers under the root (at most 16). For ZK MultiSig it is the private signer set (at most 5) and the threshold is hidden as well; an observer learns only the state root, the transaction hash and that *some* authorised quorum signed. Small sets give weak anonymity; the on-chain root itself is public, and root updates are visible.
- `label_commitment` is deterministic per (label, address): the same pair is linkable across proofs.
- Proof timing, transaction metadata and the public `txn_hash` are visible on-chain.

## Out of scope (not enforced here)

- **Replay protection and freshness** — handled by the validator contract / account nonce, not the SDK.
- **Circuit and contract soundness** — see [zk-smart-account-kit](https://github.com/MicrochainLabs/zk-smart-account-kit) and the contracts audit.
- **Circuit provenance** — the SDK cannot tell whether a `zk_signers.json` was compiled from audited sources. Pin the artifact hash that matches your deployed verifier (the `sha256` values in `test/fixtures/circuits/manifest.json` show the pattern).
- **Key management and signing UX.**

## Findings for the circuit and contract repositories

Discovered while writing the end-to-end suites. They are not in this SDK; the SDK rejects the affected inputs defensively, but a malicious prover can bypass any SDK check, so the root causes belong there.

1. **zk-smart-account-kit — `zk_scope_validation` truncates to `u128` instead of range-checking.** `txn_value as u128`, `rule_value_max as u128` and range-constraint comparisons cast a `Field` to `u128`, which wraps modulo 2^128. Verified against the compiled circuit: a range-constrained parameter of `2^128 + 5` satisfies `rangeMax(100)`, and `txn_value = 2^128 + 1` satisfies a small `valueMax`. Recommended fix: assert the operands are `< 2^128` (e.g. `assert_max_bit_size::<128>()`) before comparing.
2. **microchain-zk-signers — `zksafe/zksafe.ts` orders signatures with `localeCompare` on checksummed addresses.** The circuit and Safe require strictly increasing *numeric* addresses; mixed-case strings do not sort numerically, so some signer sets would fail. (`zknexus` lower-cases first.) The SDK sorts numerically. Found by reading, not by reproducing a failing set.
3. **microchain-zk-signers — `ZKNexusHelper.installValidator` calls `installModule` from an EOA.** Nexus restricts `installModule` to the EntryPoint or the account itself (`onlyEntryPointOrSelf`), so the call reverts. The SDK exposes `encodeInstallValidatorCall`, to be executed by the account.
4. **Nexus requires the installed validator to differ from its default validator.** `NexusBootstrap.initNexusWithSingleValidatorNoRegistry` documents "should not be the default validator". Relevant when choosing the implementation used with `ZKMultiSigValidatorFactory`.

## Reporting

See [SECURITY.md](../SECURITY.md).
