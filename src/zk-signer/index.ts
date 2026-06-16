/**
 * @microchain/zk-sdk — zk-signer subpath
 *
 * Tree utilities and circuit input builders are browser-safe.
 * Import `./prove.js` separately when proof generation is needed (Node.js only).
 */

// Constants & types
export {
    SIGNERS_MAX_DEPTH,
    PUBKEY_BYTES,
    SIGNATURE_BYTES,
    HASH_BYTES,
    ADDRESS_BYTES,
    NIL_PUBKEY,
    type PubKey,
    type ECDSASignature,
    type MessageHash,
    type SignerEntry,
    type SignersTree,
    type SignerMerkleProof,
    type ZKSignerCircuitInput,
    type ZKSignerProofData,
    // Encoding helpers
    parsePubKey,
    parseSignature,
} from "./types.js";

// Leaf encoding & hashing
export { signerToField, computeSignerLeaf, signersHash } from "./leaf.js";

// Merkle tree
export { buildSignersTree, getSignerMerkleProof } from "./tree.js";

// Circuit input builder (browser-safe)
export { buildZKSignerCircuitInput, buildZKSignerCircuitInputFromProof } from "./circuit.js";

// ABI encoding (browser-safe)
export {
    encodeSignersInitData,
    encodeZKSignerPublicInputs,
    encodeZKSignerProofCalldata,
} from "./abi.js";

// Proof generation (Node.js, requires peer deps)
export { generateZKSignerProof } from "./prove.js";
