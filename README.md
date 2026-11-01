# zk-smart-account-kit-sdk

[![CI](https://github.com/MicrochainLabs/zk-smart-account-kit-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/MicrochainLabs/zk-smart-account-kit-sdk/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/zk-smart-account-kit-sdk.svg)](https://www.npmjs.com/package/zk-smart-account-kit-sdk)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

TypeScript SDK for integrating smart account ZK primitives built with Noir — **ZK Label**, **ZK Scope**, **ZK Signer** and **ZK MultiSig** (a private M-of-N multisig for **Safe** and **Nexus / ERC-7579** accounts) — in one package.

## Installation

```bash
pnpm add zk-smart-account-kit-sdk
```

The package ships ESM and CommonJS builds with types for both. Node.js **20.19+** is required (`@iden3/js-crypto` and `@noble/hashes` do not load on Node 18) — see [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md).

### Optional peer dependencies (Node.js proof generation)

```bash
pnpm add @aztec/bb.js@5.0.0-nightly.20260522 @noir-lang/noir_js@1.0.0-beta.22
```

These are only required when calling proof generation functions (`generateLabelBindingProof`, `generateZKSignerProof`, `generateScopeProof`, `generateMultiSigProof`, `generateStateValidationProof`, or `proveLabelMembership` on `createZKLabels`). All tree builders, circuit input builders, and ABI helpers are browser-safe and work without peer deps. If a peer is missing, proving throws a `MissingPeerDependencyError` that tells you what to install.

### Circuits

The compiled circuit JSON files used in the examples below (for example `zk_label_binding.json`) are not bundled with this package: compile them with `nargo`, using Nargo `1.0.0-beta.22`, from [zk-smart-account-kit](https://github.com/MicrochainLabs/zk-smart-account-kit) (`zk_signers`, `zk_label_binding`, `zk_scope_validation`) and [microchain-zk-signers](https://github.com/MicrochainLabs/microchain-zk-signers) (`zk_multi_sig_ecdsa`, `zk_multi_sig_ecdsa_private_state_validation`). Every prover checks that the artifact you pass is the circuit it expects and throws `InvalidCircuitError` otherwise.

Proofs are generated for the EVM by default (keccak transcript, zero-knowledge) — the flavour the Solidity `HonkVerifier` contracts accept — and verified locally before they are returned.

Runnable, tested examples: [zk-signer](examples/zk-signer.ts), [zk-label](examples/zk-label.ts), [zk-scope](examples/zk-scope.ts), [zk-multisig on Safe](examples/zk-multisig-safe.ts), [zk-multisig on Nexus](examples/zk-multisig-nexus.ts).

---

## Primitives

| Module        | Subpath import                                    | Description |
|---------------|---------------------------------------------------|-------------|
| `zk-label`    | `zk-smart-account-kit-sdk/zk-label`    | Private label registry: Merkle tree, circuit inputs, ABI encoding, proof generation |
| `zk-signer`   | `zk-smart-account-kit-sdk/zk-signer`   | Single-signer ECDSA ZK proofs: signers tree, circuit inputs, ABI encoding, proof generation |
| `zk-scope`    | `zk-smart-account-kit-sdk/zk-scope`    | Scope policy tree: rule encoding, circuit inputs, ABI encoding, proof generation |
| `zk-multisig` | `zk-smart-account-kit-sdk/zk-multisig` | Private M-of-N multisig: hiding state root, signers tree, circuit inputs, proof generation |
| `zk-multisig/safe` | `zk-smart-account-kit-sdk/zk-multisig/safe` | Safe integration: transaction hash, signatures, ZK signer factory, Safe deployment |
| `zk-multisig/nexus` | `zk-smart-account-kit-sdk/zk-multisig/nexus` | Nexus (ERC-7579) integration: account factory, UserOperations, EntryPoint v0.7 |

---

## ZK Label

### Concepts

A **label** is a (name, address) pair committed as a leaf in a Poseidon Merkle tree. A user can prove label membership without revealing their signer identifier such as address or the label name on-chain.

```
leaf = Poseidon2(Poseidon1(label_name_field), Poseidon1(address_field))
root = LeanIMT root over all leaves
```

### High-level API (`createZKLabels`)

```ts
import circuit from "./noir/zk_label_binding/target/zk_label_binding.json" with { type: "json" };
import { createZKLabels, type LabelEntry, type ZKLabels } from "zk-smart-account-kit-sdk/zk-label";

const labels: LabelEntry[] = [
  { labelName: "admin",  signer: "0xABCDef…" },
  { labelName: "member", signer: "0x1234AB…" },
];

// Synchronous — tree is built immediately
const zkLabels: ZKLabels = createZKLabels(labels, circuit);

console.log("Registry root:", zkLabels.registryRoot);
console.log("Has admin?",     zkLabels.hasLabel("admin", "0xABCDef…"));

const proofData = await zkLabels.proveLabelMembership("admin", "0xABCDef…");
console.log("Proof:", proofData.proof);

// Add / remove labels at runtime
const newRoot = zkLabels.addLabel({ labelName: "viewer", signer: "0xDEAD…" });
const updRoot = zkLabels.removeLabel({ labelName: "viewer", signer: "0xDEAD…" });
```

### Low-level API

```ts
import {
  buildLabelsTree,
  buildLabelBindingCircuitInput,
  generateLabelBindingProof,
  encodeLabelsInitData,
  encodeLabelBindingPublicInputs,
} from "zk-smart-account-kit-sdk/zk-label";

// 1. Build the registry Merkle tree
const labelsTree = buildLabelsTree(labels);

// 2. Build circuit input (browser-safe)
const circuitInput = buildLabelBindingCircuitInput(
  "admin",
  "0xABCDef…",
  labelsTree.tree,
  labelsTree.registryRoot,
);

// 3. Generate proof (Node.js only — requires @aztec/bb.js + @noir-lang/noir_js)
const proofData = await generateLabelBindingProof("admin", "0xABCDef…", labelsTree, circuit);

// 4. Encode for on-chain calls
const initData     = encodeLabelsInitData(labelsTree.registryRoot);
const publicInputs = encodeLabelBindingPublicInputs(
  proofData.registryRoot,
  proofData.labelCommitment,
);
```

---

## ZK Signer

Proves in zero-knowledge that the prover knows the ECDSA key that signed a transaction hash **and** that the derived address is a member of a privately committed signers set.

### Concepts

```
signer_leaf  = Poseidon1([address_to_field(signer)])
signersRoot  = LeanIMT root over all signer leaves
```

### API

```ts
import circuit from "./target/zk_signers.json" with { type: "json" };
import {
  buildSignersTree,
  generateZKSignerProof,
  encodeSignersInitData,
  encodeZKSignerProofCalldata,
  parsePubKey,
  parseSignature,
  type SignerEntry,
  type PubKey,
} from "zk-smart-account-kit-sdk/zk-signer";

// 1. Build the signers Merkle tree
const signers: SignerEntry[] = [
  { signer: "0xABCDef…" },
  { signer: "0x1234AB…" },
];
const signersTree = buildSignersTree(signers);

// 2. Parse key material
const pubKey: PubKey = parsePubKey(uncompressedBytes);   // 0x04 || x(32) || y(32)
const sig            = [...parseSignature(rawBytes).r, ...parseSignature(rawBytes).s]; // 64 bytes

// 3. Encode init data for module installation
const initData = encodeSignersInitData(signersTree.signersRoot);

// 4. Generate proof (Node.js only)
const proofData = await generateZKSignerProof(
  pubKey, sig, "0xABCDef…", signersTree, txnHashBytes, circuit,
);

// 5. Encode for on-chain submission
const calldata = encodeZKSignerProofCalldata(proofData);
```

---

## ZK Scope

Restricts which transactions a smart account can approve — privately. The owner commits a set of scope rules on-chain as a Poseidon Merkle root; a transaction is approved when it matches at least one rule.

### Concepts

```
params_hash = Poseidon commitment over all parameter constraints
rule_leaf   = Poseidon4([target, selector, valueMax, params_hash])
scopeRoot   = LeanIMT root over all rule leaves
```

### API

```ts
import circuit from "./target/zk_scope_validation.json" with { type: "json" };
import {
  buildScopeTree,
  generateScopeProof,
  encodeScopeInitData,
  encodeScopeProofCalldata,
  padConstraints,
  exactMatch,
  rangeMax,
  type ScopeRule,
} from "zk-smart-account-kit-sdk/zk-scope";

// 1. Define scope rules
const rules: ScopeRule[] = [
  {
    target:      "0xUniswapRouter…",
    selector:    "0xd0e30db0",
    valueMax:    0n,
    constraints: padConstraints([
      exactMatch(0xA0b8n),   // tokenIn must be USDC
      rangeMax(1_000_000n),  // amount <= 1 USDC
    ]),
  },
];

// 2. Build scope tree
const scopeTree = buildScopeTree(rules);

// 3. Encode init data for module installation
const initData = encodeScopeInitData(scopeTree.scopeRoot);

// 4. Generate proof (Node.js only)
const proofData = await generateScopeProof(
  "0xUniswapRouter…",  // txnTarget
  "0xd0e30db0",         // txnSelector
  0n,                    // txnValue
  [0xA0b8n, 500_000n, 0n, 0n], // decoded calldata params
  rules[0],              // matching rule (private)
  scopeTree,
  circuit,
);

// 5. Encode for on-chain submission
const calldata = encodeScopeProofCalldata(proofData);
```

---

## ZK MultiSig

A private **M-of-N multisig** for Safe and Nexus accounts, mirroring [microchain-zk-signers](https://github.com/MicrochainLabs/microchain-zk-signers). Up to 5 ECDSA signers and the threshold stay private: only a hiding commitment is on-chain, and a ZK proof — not the signatures — authorises each transaction, revealing neither who signed nor who the other members are.

### Concepts

```
signers_root = LeanIMT root over Poseidon1(address), signers sorted ascending
state_root   = Poseidon3(signers_root, Poseidon1(threshold), salt)     // the only on-chain value
```

- **The private configuration** is `{ signers, threshold, salt }`. The salt (248 random bits) is what makes the commitment hiding.
- ⚠️ **Back up the salt together with the signer list.** Without it no proof can ever be generated for that state root and the account is lost. Leaking it alone reveals nothing; leaking it with the signer list de-anonymises the account (signatures stay safe). `serializeMultiSigState` produces the backup; treat it as a secret and store it encrypted. See [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).
- A **state-validation proof** shows the state root commits to a valid configuration; it is required to create an account or to rotate its state root.
- A **transaction proof** shows that at least `threshold` signers of the private set signed a hash (a Safe transaction hash or a UserOperation hash) and that the configuration matches the on-chain state root.

### Private configuration and proofs

```ts
import circuit from "./target/zk_multi_sig_ecdsa.json" with { type: "json" };
import stateCircuit from "./target/zk_multi_sig_ecdsa_private_state_validation.json" with { type: "json" };
import {
  createMultiSigState, serializeMultiSigState, parseMultiSigState,
  generateStateValidationProof, generateMultiSigProof, createBarretenberg,
} from "zk-smart-account-kit-sdk/zk-multisig";

// 1. Derive the commitment. A fresh random salt is generated unless you pass one.
const state = createMultiSigState({ signers: ["0xAAA…", "0xBBB…", "0xCCC…"], threshold: 2 });
state.stateRoot;                              // the public commitment
const backup = serializeMultiSigState(state); // SECRET — encrypt and store it with the account's recovery material
const config = parseMultiSigState(backup);    // later: restore (the root is re-derived and checked)

const barretenberg = await createBarretenberg(); // share one instance across proofs

// 2. Prove the commitment is valid (account creation, state-root rotation).
const stateProof = await generateStateValidationProof(config, stateCircuit, { barretenberg });

// 3. Prove a transaction: ≥ threshold signers signed `hash` (65-byte signatures over the raw 32-byte hash).
const proof = await generateMultiSigProof(config, hash, signatures, onChainStateRoot, circuit, { barretenberg });
proof.proof; // submit as the Safe contract signature or the UserOperation signature

await barretenberg.destroy();
```

`createMultiSigState` rejects what the circuit could never satisfy (`threshold > signers`, duplicates, more than 5 signers). `buildMultiSigCircuitInput` recovers the signers, orders them as the circuit requires, builds the Merkle paths, and fails early with a precise message on too few, duplicate or foreign signatures, high-S signatures, or a configuration that does not match `onChainStateRoot` (`ChainStateError`).

### Safe

A Safe is owned by a **ZK signer** — a minimal proxy created by `ZKMultiSigEcdsaFactory` that verifies the proof as an ERC-1271 signature. Built on viem only; works with any viem client.

```ts
import {
  createZKSigner, encodeSafeSetup, encodeCreateSafeProxy, predictSafeAddress, parseSafeProxyCreation,
  buildSafeTransaction, signSafeTransaction, generateSafeTransactionProof, encodeExecTransaction,
} from "zk-smart-account-kit-sdk/zk-multisig/safe";

// Deploy the ZK signer for the state root, then a Safe owned by it.
const { signer: zkSigner } = await createZKSigner(walletClient, { factory, stateRoot: state.stateRoot, verifier, stateValidationProof: stateProof.proof });
const initializer = encodeSafeSetup({ owners: [zkSigner], threshold: 1 });
const safe = await predictSafeAddress(client, { initializer, saltNonce: 1n });
//   …send encodeCreateSafeProxy({ initializer, saltNonce: 1n }) and check parseSafeProxyCreation(receipt.logs) === safe

// A transaction: private signers sign its EIP-712 hash, a proof replaces their signatures.
const transaction = buildSafeTransaction({ to, value, data, nonce });
const signatures = await Promise.all(signerAccounts.map((a) => signSafeTransaction(a, chainId, safe, transaction)));
const { signatures: safeSignatures } = await generateSafeTransactionProof(client, {
  safe, zkSigner, transaction, signatures, config, circuit, options: { barretenberg },
});
await walletClient.sendTransaction({ to: safe, data: encodeExecTransaction(transaction, safeSignatures) });
```

`encodeSafeSignatures` packs several owners' signatures — ordinary ECDSA and contract signatures — in the layout Safe requires, so the ZK signer can sit next to regular owners.

### Nexus (ERC-7579)

A Nexus account uses `ZKMultiSigValidator`; the UserOperation signature is the proof. ERC-4337 EntryPoint v0.7.

```ts
import {
  createNexusAccount, prepareNexusUserOperation, generateNexusUserOperationProof, sendNexusUserOperation,
  encodeUpdateStateRootCall, getNexusAccountStatus,
} from "zk-smart-account-kit-sdk/zk-multisig/nexus";

const { account } = await createNexusAccount(walletClient, { factory, stateRoot: state.stateRoot, stateValidationProof: stateProof.proof });

// Prepare the operation; private signers sign its hash with `account.sign({ hash })` (raw, no message prefix).
const { userOperation, userOperationHash } = await prepareNexusUserOperation(client, { account, validator, call: { to, value, data } });
const signatures = await Promise.all(signerAccounts.map((a) => a.sign({ hash: userOperationHash })));

// The proof becomes the UserOperation signature. Submit to the EntryPoint or hand it to a bundler.
const proven = await generateNexusUserOperationProof(client, { userOperation, validator, signatures, config, circuit, options: { barretenberg } });
const result = await sendNexusUserOperation(walletClient, { userOperation: proven.userOperation });
```

Rotating signers, threshold or salt is a UserOperation that calls `encodeUpdateStateRootCall({ validator, newStateRoot, stateValidationProof })`, authorised by the *current* configuration. EntryPoint failures are reported with their `AAxx` code and meaning (`describeEntryPointError`). Verifying a proof on-chain costs about 3M gas, so the default `verificationGasLimit` is 10M (`DEFAULT_GAS`); lower it if your bundler allows.

---

## Validation and errors

Every public function validates its input at runtime and fails early with a typed error. All errors extend `ZKSdkError` and carry a stable `code`:

| Class | `code` | Typical cause |
|---|---|---|
| `InvalidArgumentError` | `INVALID_ARGUMENT` | Bad address / checksum, wrong byte length, value outside the BN254 field, a selector that is not exactly 4 bytes, more than 4 params or constraints, empty registry, signature not valid for the signer |
| `NotFoundError` | `NOT_FOUND` | Signer / label / rule not in the tree |
| `TreeCapacityError` | `TREE_CAPACITY_EXCEEDED` | More than 16 signers or labels, or 64 scope rules — the circuit could never prove such a root |
| `InvalidCircuitError` | `INVALID_CIRCUIT` | Wrong or malformed circuit artifact |
| `MissingPeerDependencyError` | `MISSING_PEER_DEPENDENCY` | `@aztec/bb.js` / `@noir-lang/noir_js` not installed |
| `ProofGenerationError` | `PROOF_GENERATION_FAILED` | Witness constraint not satisfied, or proving failed (`error.cause` has the original) |
| `ChainStateError` | `CHAIN_STATE_MISMATCH` | On-chain state differs from what you hold: the configuration does not match the state root, the validator is not installed, the EntryPoint rejected an operation (`AAxx`) |
| `UnsupportedEnvironmentError` | `UNSUPPORTED_ENVIRONMENT` | No secure random source to generate a salt |

```ts
import { ZKSdkError } from "zk-smart-account-kit-sdk/errors";

try {
  await generateZKSignerProof(/* … */);
} catch (error) {
  if (error instanceof ZKSdkError && error.code === "NOT_FOUND") { /* signer was removed */ }
  else throw error;
}
```

Before proving, the SDK runs cheap off-circuit checks (the public key derives to the signer, the signature is a valid low-S ECDSA signature of the hash, the transaction satisfies the scope rule) so mistakes fail in milliseconds with a precise message. These checks are a convenience, not a security control: the circuit is the authority.

### Reusing Barretenberg across proofs

Creating a Barretenberg instance is expensive. By default each proof creates and destroys its own; long-running services should share one, created with `createBarretenberg()` (exported by every subpath):

```ts
import { createBarretenberg } from "zk-smart-account-kit-sdk/zk-signer";

const barretenberg = await createBarretenberg();
const proof = await generateZKSignerProof(pubKey, sig, signer, tree, hash, circuit, { barretenberg });
// …
await barretenberg.destroy(); // you own the instance you pass in
```

Use `createBarretenberg()` rather than `Barretenberg.new()` from `@aztec/bb.js`: the native backend connects to its prover process lazily and gives up after five seconds if the event loop is blocked meanwhile — which witness generation does for the larger circuits — leaving a dead instance. `createBarretenberg()` completes the connection before returning.

---

## Documentation

- API reference: `pnpm docs:api` (generated into `docs/api`).
- [Threat model](docs/THREAT-MODEL.md) · [Compatibility](docs/COMPATIBILITY.md) · [Versioning & deprecation](docs/VERSIONING.md) · [Security policy](SECURITY.md)

---

## Development

```bash
pnpm install
pnpm verify        # typecheck, lint, format check, tests + coverage, build, package lint, docs, install smoke test
pnpm test          # everything below that can run on your machine (~2 min)
pnpm test:unit     # fast unit tests only
pnpm test:e2e      # real circuits: witness, EVM proof, verification
pnpm test:onchain  # SDK proofs verified by the real Microchain contracts on Anvil (needs Foundry)
pnpm test:integration  # real Safe, Nexus and EntryPoint v0.7 (needs built contracts, see CONTRIBUTING.md)
```

See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## Adding a new primitive

1. Create `src/<primitive-name>/types.ts`, `src/<primitive-name>/index.ts`, and any implementation files.
2. Re-export from `src/index.ts`.
3. Add a `"./primitive-name"` entry (with `import` and `require` conditions, as for the existing ones) to `exports` in `package.json`.
4. Add unit tests, an end-to-end proof test against the compiled circuit, and an example.

---

## License

Apache-2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).

## Contributing & Security

See [CONTRIBUTING.md](CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md). Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md). Release history is in [CHANGELOG.md](CHANGELOG.md).

---