# @microchain/zk-sdk

TypeScript SDK for integrating Microchain ZK primitives — **ZK Label**, **ZK Signer**, and future modules — into the Microchain stack.

## Installation

```bash
pnpm add @microchain/zk-sdk
```

### Optional peer dependencies (Node.js proof generation)

```bash
pnpm add @aztec/bb.js @noir-lang/noir_js
```

These are only required when calling `generateLabelBindingProof`. Browser utilities (`buildLabelsTree`, `buildLabelBindingCircuitInput`, `encodeLabelBindingPublicInputs`, etc.) work without them.

---

## Primitives

| Module              | Subpath import           | Description                                              |
|---------------------|--------------------------|----------------------------------------------------------|
| `zk-label`          | `@microchain/zk-sdk/zk-label`  | Private label registry: Merkle tree, circuit inputs, ABI encoding, proof generation |
| `zk-scope`          | `@microchain/zk-sdk/zk-scope`  | Scope policy tree: rule encoding, circuit inputs, ABI encoding, proof generation |
| `zk-signer`         | `@microchain/zk-sdk/zk-signer` | ECDSA-based ZK signer types and encoding helpers |
| `zk-multisig`       | `@microchain/zk-sdk/zk-multisig` | M-of-N ECDSA multi-sig: signers tree, state root, circuit inputs, proof generation |

---

## ZK Label

### Concepts

A **label** is a (name, address) pair committed as a leaf in a Poseidon Merkle tree. A user can prove label membership without revealing their address or the label name on-chain.

```
leaf = Poseidon2(Poseidon1(label_name_field), Poseidon1(address_field))
root = LeanIMT root over all leaves
```

### High-level API (`createZKLabels`)

```ts
import circuit from "./noir/zk_label_binding/target/zk_label_binding.json" assert { type: "json" };
import { createZKLabels, type LabelEntry, type ZKLabels } from "@microchain/zk-sdk/zk-label";

const labels: LabelEntry[] = [
  { labelName: "admin",  address: "0xABCDef…" },
  { labelName: "signer", address: "0x1234AB…" },
];

// Synchronous — tree is built immediately
const zkLabels: ZKLabels = createZKLabels(labels, circuit);

console.log("Registry root:", zkLabels.registryRoot);
console.log("Has admin?",     zkLabels.hasLabel("admin", "0xABCDef…"));

const proofData = await zkLabels.proveLabelMembership("admin", "0xABCDef…");
console.log("Proof:", proofData.proof);
```

### Low-level API

```ts
import {
  buildLabelsTree,
  buildLabelBindingCircuitInput,
  generateLabelBindingProof,
  encodeLabelsInitData,
  encodeLabelBindingPublicInputs,
} from "@microchain/zk-sdk/zk-label";

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

```ts
import { parsePubKey, parseSignature, type PubKey } from "@microchain/zk-sdk/zk-signer";

const pubkey: PubKey = parsePubKey(uncompressedBytes);   // 0x04 || x(32) || y(32)
const sig             = parseSignature(rawBytes);         // r(32) || s(32)
```

---

## ZK MultiSig

### Concepts

An M-of-N threshold scheme where a set of ECDSA signers is committed privately
as a Poseidon Merkle tree. The on-chain state root commits to both the signer
tree root and the threshold:

```
signer_leaf     = Poseidon1([address_as_field])
signers_root    = LeanIMT root over all signer leaves
threshold_hash  = Poseidon1([threshold])
on_chain_state_root = Poseidon2([signers_root, threshold_hash])
```

### Low-level API

```ts
import multiSigCircuit    from "./zk_multi_sig_ecdsa.json" assert { type: "json" };
import validationCircuit  from "./zk_multi_sig_ecdsa_private_state_validation.json" assert { type: "json" };
import {
  buildSignersTree,
  computeOnChainStateRoot,
  buildMultiSigCircuitInput,
  generateMultiSigProof,
  generatePrivateStateValidationProof,
  encodeMultiSigInitData,
  encodeMultiSigPublicInputs,
  type SignerEntry,
  type ActiveSigner,
} from "@microchain/zk-sdk/zk-multisig";

// 1. Build the private signers Merkle tree
const signers: SignerEntry[] = [
  { address: "0xABCDef…" },
  { address: "0x1234AB…" },
];
const signersTree = buildSignersTree(signers);
const threshold = 2;

// 2. Compute the on-chain state root (public commitment)
const stateRoot = computeOnChainStateRoot(signersTree.signersRoot, threshold);
console.log("State root:", stateRoot);

// 3. Encode init data for module installation
const initData = encodeMultiSigInitData(stateRoot);

// 4. Generate a multi-sig proof (Node.js only)
//    activeSigners MUST be sorted by address ascending
const activeSigners: ActiveSigner[] = [
  { pubKey: pubKey1, signature: sig1, address: "0xABCDef…" },
  { pubKey: pubKey2, signature: sig2, address: "0x1234AB…" },
];
const proofData = await generateMultiSigProof(
  activeSigners, threshold, signersTree, txnHashBytes, multiSigCircuit,
);

// 5. Encode for on-chain submission
const publicInputs = encodeMultiSigPublicInputs(proofData.txnHash, proofData.onChainStateRoot);

// 6. Prove state root validity without signature verification
const validationProof = await generatePrivateStateValidationProof(
  signersTree.signersRoot, threshold, validationCircuit,
);
```

### NIL signer padding

The circuit has `MAX_SIGNERS = 5` fixed slots. Inactive slots are automatically
padded with the `NIL_PUBKEY` sentinel (secp256k1 generator point G) by
`buildMultiSigCircuitInput`. You only need to provide the active signers.

---

## Adding a new primitive

1. Create `src/<primitive-name>/types.ts`, `src/<primitive-name>/index.ts`, and any implementation files.
2. Re-export from `src/index.ts`.
3. Add a `"./primitive-name"` entry to `exports` in `package.json`.

---

## Environment compatibility

| Feature                             | Browser | Node.js |
|-------------------------------------|---------|---------|
| `buildLabelsTree`                   | ✅      | ✅      |
| `buildLabelBindingCircuitInput`     | ✅      | ✅      |
| `encodeLabelBindingPublicInputs`    | ✅      | ✅      |
| `generateLabelBindingProof`         | ❌      | ✅      |
| `generateScopeProof`                | ❌      | ✅      |
| `generateMultiSigProof`             | ❌      | ✅      |
| `generatePrivateStateValidationProof` | ❌    | ✅      |
| `client.proveLabelMembership`       | ❌      | ✅      |

---

## License

Apache-2.0
