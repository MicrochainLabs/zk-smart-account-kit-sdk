/**
 * zk-smart-account-kit-sdk — zk-multisig subpath
 *
 * Private M-of-N ECDSA multisig: a hiding commitment to a private signer set and threshold, and ZK
 * proofs that authorise transactions for Safe (`zk-multisig/safe`) and ERC-7579 Nexus accounts
 * (`zk-multisig/nexus`). Mirrors microchain-zk-signers.
 *
 * State, tree, circuit-input and ABI helpers are browser-safe. Proof generation (`./prove.js`) is Node.js only.
 */

// Constants & types
export {
    MAX_SIGNERS,
    MAX_THRESHOLD,
    MULTISIG_PUBLIC_INPUTS,
    NIL_SIGNATURE,
    type SignersFormat,
    type MultiSigConfig,
    type MultiSigTree,
    type MultiSigState,
    type MultiSigCircuitInput,
    type StateValidationCircuitInput,
    type MultiSigProofData,
    type StateValidationProofData,
} from "./types.js";

// State root & salt
export { computeStateRoot, generateSalt, parseSalt, saltToHex, fieldToBytes32 } from "./state-root.js";

// Signers tree
export { sortSigners, buildMultiSigTree, getMultiSigMerkleProof } from "./tree.js";

// Private configuration: derivation and backup
export { createMultiSigState, serializeMultiSigState, parseMultiSigState, type MultiSigStateInput } from "./state.js";

// Circuit input builders (browser-safe)
export {
    recoverMultiSigSigner,
    buildMultiSigCircuitInput,
    buildStateValidationCircuitInput,
    type RecoveredSigner,
    type HashInput,
} from "./circuit.js";

// Public inputs encoding (browser-safe)
export {
    buildMultiSigPublicInputs,
    encodeMultiSigPublicInputs,
    buildStateValidationPublicInputs,
    encodeStateValidationPublicInputs,
} from "./abi.js";

// Proof generation (Node.js, requires peer deps)
export {
    generateMultiSigProof,
    generateStateValidationProof,
    ZK_MULTISIG_CIRCUIT_PARAMS,
    ZK_MULTISIG_STATE_VALIDATION_CIRCUIT_PARAMS,
} from "./prove.js";
export { createBarretenberg } from "../internal/prover.js";
export type { ProveOptions, BarretenbergLike, VerifierTarget } from "../internal/prover.js";
