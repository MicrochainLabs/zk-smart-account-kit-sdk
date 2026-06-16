/**
 * @microchain/zk-sdk — zk-label subpath
 *
 * Tree utilities and circuit input builders are browser-safe.
 * Import `./prove.js` separately when proof generation is needed (Node.js only).
 */

// Constants & types
export {
    LABELS_MAX_DEPTH,
    LABEL_NAME_BYTES,
    type LabelEntry,
    type LabelsTree,
    type LabelMerkleProof,
    type LabelBindingCircuitInput,
    type LabelBindingProofData,
} from "./types.js";

// Leaf encoding & hashing
export {
    labelNameToBytes,
    labelBytesToField,
    labelNameToField,
    addressToField,
    addressToBytes,
    computeLabelLeaf,
    labelsHash,
} from "./leaf.js";

// Merkle tree
export { buildLabelsTree, getLabelMerkleProof } from "./tree.js";

// Circuit input builder (browser-safe)
export {
    computeLabelCommitment,
    buildLabelBindingCircuitInput,
    buildLabelBindingCircuitInputFromProof,
} from "./circuit.js";

// ABI encoding (browser-safe)
export {
    encodeLabelBindingPublicInputs,
    encodeLabelsInitData,
    encodeUpdateRegistryRootData,
    encodeLabelProofCalldata,
} from "./abi.js";

// Proof generation (Node.js, requires peer deps)
export { generateLabelBindingProof } from "./prove.js";

// High-level factory (viem-style)
export { createZKLabels, type ZKLabels } from "./ZKLabelsHelper.js";
