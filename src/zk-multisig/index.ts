/**
 * @microchain/zk-sdk — zk-multisig subpath
 *
 * M-of-N ECDSA multi-signature ZK primitives.
 *
 * Tree utilities, circuit input builders, and ABI helpers are browser-safe.
 * Import `./prove.js` separately when proof generation is needed (Node.js only).
 */

// Constants & types
export {
    MAX_SIGNERS,
    MAX_THRESHOLD,
    SECP256K1_G_X,
    SECP256K1_G_Y,
    NIL_PUBKEY,
    NIL_SIGNATURE,
    type PubKey,
    type ECDSASignature,
    type SignerEntry,
    type SignersTree,
    type SignerMerkleProof,
    type ActiveSigner,
    type MultiSigCircuitInput,
    type PrivateStateValidationCircuitInput,
    type MultiSigProofData,
    type PrivateStateValidationProofData,
} from "./types.js";

// Leaf encoding & hashing
export {
    computeSignerLeaf,
    signersHash,
} from "./leaf.js";

// Merkle tree
export { buildSignersTree, getSignerMerkleProof } from "./tree.js";

// Circuit input builders (browser-safe)
export {
    computeOnChainStateRoot,
    buildMultiSigCircuitInput,
    buildPrivateStateValidationCircuitInput,
} from "./circuit.js";

// ABI encoding (browser-safe)
export {
    encodeMultiSigInitData,
    encodeMultiSigPublicInputs,
    encodeUpdateStateRootData,
    encodeMultiSigProofCalldata,
    encodePrivateStateValidationProofCalldata,
} from "./abi.js";

// Proof generation (Node.js, requires peer deps)
export { generateMultiSigProof, generatePrivateStateValidationProof } from "./prove.js";
