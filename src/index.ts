/**
 * @microchain/zk-sdk
 *
 * Unified TypeScript SDK for Microchain ZK primitives.
 *
 * Subpath imports give tree-shakeable, granular access:
 *
 *   import { buildLabelsTree, ZKLabelsHelper } from "@microchain/zk-sdk/zk-label";
 *   import { parsePubKey, type PubKey }        from "@microchain/zk-sdk/zk-signer";
 *
 * The root import re-exports every primitive for convenience:
 *
 *   import { buildLabelsTree, parsePubKey } from "@microchain/zk-sdk";
 */

export * from "./zk-label/index.js";
export * from "./zk-signer/index.js";
export * from "./zk-scope/index.js";

// zk-multisig: only export members that are not already exported by zk-signer
export {
    MAX_SIGNERS,
    MAX_THRESHOLD,
    SECP256K1_G_X,
    SECP256K1_G_Y,
    NIL_SIGNATURE,
    type ActiveSigner,
    type MultiSigCircuitInput,
    type PrivateStateValidationCircuitInput,
    type MultiSigProofData,
    type PrivateStateValidationProofData,
    computeOnChainStateRoot,
    buildMultiSigCircuitInput,
    buildPrivateStateValidationCircuitInput,
    encodeMultiSigInitData,
    encodeMultiSigPublicInputs,
    encodeUpdateStateRootData,
    encodeMultiSigProofCalldata,
    encodePrivateStateValidationProofCalldata,
    generateMultiSigProof,
    generatePrivateStateValidationProof,
} from "./zk-multisig/index.js";
