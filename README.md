# zk-smart-account-kit-sdk

[![CI](https://github.com/MicrochainLabs/zk-smart-account-kit-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/MicrochainLabs/zk-smart-account-kit-sdk/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/zk-smart-account-kit-sdk.svg)](https://www.npmjs.com/package/zk-smart-account-kit-sdk)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

TypeScript SDK for integrating smart account ZK primitives built with Noir — **ZK Label**, **ZK Scope**, **ZK Signer**, and future modules.

## Installation

```bash
pnpm add zk-smart-account-kit-sdk
```

### Optional peer dependencies (Node.js proof generation)

```bash
pnpm add @aztec/bb.js @noir-lang/noir_js
```

These are only required when calling proof generation functions (`generateLabelBindingProof`, `generateZKSignerProof`, `generateScopeProof`). All tree builders, circuit input builders, and ABI helpers are browser-safe and work without peer deps.

The compiled circuit JSON files used in the examples below (for example `zk_label_binding.json`) are not bundled with this package: compile them with `nargo` from [zk-smart-account-kit](https://github.com/MicrochainLabs/zk-smart-account-kit), using Nargo `1.0.0-beta.22`.

---

## Primitives

| Module        | Subpath import                                    | Description |
|---------------|---------------------------------------------------|-------------|
| `zk-label`    | `zk-smart-account-kit-sdk/zk-label`    | Private label registry: Merkle tree, circuit inputs, ABI encoding, proof generation |
| `zk-signer`   | `zk-smart-account-kit-sdk/zk-signer`   | Single-signer ECDSA ZK proofs: signers tree, circuit inputs, ABI encoding, proof generation |
| `zk-scope`    | `zk-smart-account-kit-sdk/zk-scope`    | Scope policy tree: rule encoding, circuit inputs, ABI encoding, proof generation |

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
import circuit from "./noir/zk_label_binding/target/zk_label_binding.json" assert { type: "json" };
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
import circuit from "./target/zk_signers.json" assert { type: "json" };
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
import circuit from "./target/zk_scope_validation.json" assert { type: "json" };
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

## Adding a new primitive

1. Create `src/<primitive-name>/types.ts`, `src/<primitive-name>/index.ts`, and any implementation files.
2. Re-export from `src/index.ts`.
3. Add a `"./primitive-name"` entry to `exports` in `package.json`.

---

## License

Apache-2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).

## Contributing & Security

See [CONTRIBUTING.md](CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md). Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md). Release history is in [CHANGELOG.md](CHANGELOG.md).

---