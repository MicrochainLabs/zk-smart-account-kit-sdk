/**
 * ABI encoding helpers for on-chain interactions with ZK MultiSig validators.
 *
 * These match the calldata layout expected by ZKMultiSigEcdsaSingleton and
 * ZKMultiSigValidator (ERC-7579). Browser-safe: no proving deps required.
 */

import {
    encodeAbiParameters,
    parseAbiParameters,
    toHex,
    type Hex,
} from "viem";
import type { MultiSigProofData, PrivateStateValidationProofData } from "./types.js";

// ─── Initialization ──────────────────────────────────────────────────────────

/**
 * Encode the initialisation calldata passed to the validator during module
 * installation (e.g. ZKMultiSigValidator.onInstall / initData).
 *
 * Layout: abi.encode(bytes32 onChainStateRoot)
 */
export function encodeMultiSigInitData(onChainStateRoot: bigint | Hex): Hex {
    const root = typeof onChainStateRoot === "bigint"
        ? onChainStateRoot
        : BigInt(onChainStateRoot);
    return encodeAbiParameters(
        parseAbiParameters("bytes32"),
        [toHex(root, { size: 32 })],
    );
}

// ─── Public inputs ───────────────────────────────────────────────────────────

/**
 * Encode the two semantic public inputs (txnHash, onChainStateRoot) for a
 * ZK MultiSig proof as ABI-encoded bytes32 values.
 *
 * Used by the on-chain verifier to confirm which transaction and state root
 * the proof was generated against.
 *
 * @param txnHash         - 32-byte transaction hash (keccak256 of signed payload).
 * @param onChainStateRoot - Poseidon commitment of (signersRoot, threshold_hash).
 */
export function encodeMultiSigPublicInputs(
    txnHash:          Hex | number[],
    onChainStateRoot: bigint | Hex,
): Hex {
    const hashHex = Array.isArray(txnHash)
        ? (toHex(new Uint8Array(txnHash)) as Hex)
        : txnHash;
    const root = typeof onChainStateRoot === "bigint"
        ? onChainStateRoot
        : BigInt(onChainStateRoot);

    return encodeAbiParameters(
        parseAbiParameters("bytes32, bytes32"),
        [hashHex as `0x${string}`, toHex(root, { size: 32 })],
    );
}

// ─── State root update ───────────────────────────────────────────────────────

/**
 * Encode the calldata for updating the on-chain state root.
 *
 * A new state root is submitted together with a ZK proof (either
 * zk_multi_sig_ecdsa or zk_multi_sig_ecdsa_private_state_validation) that
 * authorises the update.
 *
 * Layout: abi.encode(bytes32 newStateRoot, bytes proof)
 */
export function encodeUpdateStateRootData(
    newStateRoot: bigint | Hex,
    proof:        Hex,
): Hex {
    const root = typeof newStateRoot === "bigint" ? newStateRoot : BigInt(newStateRoot);
    return encodeAbiParameters(
        parseAbiParameters("bytes32, bytes"),
        [toHex(root, { size: 32 }), proof],
    );
}

// ─── Proof submission ────────────────────────────────────────────────────────

/**
 * Convenience wrapper: encode the calldata to submit a multi-sig proof for
 * transaction approval.
 *
 * Layout: abi.encode(bytes proof, bytes32 txnHash, bytes32 onChainStateRoot)
 */
export function encodeMultiSigProofCalldata(proofData: MultiSigProofData): Hex {
    return encodeAbiParameters(
        parseAbiParameters("bytes, bytes32, bytes32"),
        [proofData.proof, proofData.txnHash as `0x${string}`, proofData.onChainStateRoot as `0x${string}`],
    );
}

/**
 * Convenience wrapper: encode the calldata to submit a private state
 * validation proof (e.g. for state root migration / re-keying flows).
 *
 * Layout: abi.encode(bytes proof, bytes32 onChainStateRoot)
 */
export function encodePrivateStateValidationProofCalldata(
    proofData: PrivateStateValidationProofData,
): Hex {
    return encodeAbiParameters(
        parseAbiParameters("bytes, bytes32"),
        [proofData.proof, proofData.onChainStateRoot as `0x${string}`],
    );
}
