/**
 * ABI encoding helpers for on-chain interactions with ZK Signer validators.
 *
 * These match the calldata layout expected by ZKSignerValidator (ERC-7579).
 * Browser-safe: no proving deps required.
 */

import {
    encodeAbiParameters,
    parseAbiParameters,
    toHex,
    type Hex,
} from "viem";
import type { ZKSignerProofData } from "./types.js";

/**
 * Encode the initialisation calldata passed to the validator during module
 * installation (e.g. ZKSignerValidator.onInstall / initData).
 *
 * Layout: abi.encode(bytes32 signersRoot)
 */
export function encodeSignersInitData(signersRoot: bigint | Hex): Hex {
    const root = typeof signersRoot === "bigint" ? signersRoot : BigInt(signersRoot);
    return encodeAbiParameters(
        parseAbiParameters("bytes32"),
        [toHex(root, { size: 32 })],
    );
}

/**
 * Encode the two public inputs (txnHash, signersRoot) for a ZK Signer proof
 * as ABI-encoded bytes32 values.
 *
 * Used by the on-chain verifier to confirm which transaction and signers root
 * the proof was generated against.
 *
 * @param txnHash     - 32-byte transaction hash.
 * @param signersRoot - Merkle root of the authorized signers tree.
 */
export function encodeZKSignerPublicInputs(
    txnHash:     Hex | number[],
    signersRoot: bigint | Hex,
): Hex {
    const hashHex = Array.isArray(txnHash)
        ? (toHex(new Uint8Array(txnHash)) as Hex)
        : txnHash;
    const root = typeof signersRoot === "bigint" ? signersRoot : BigInt(signersRoot);

    return encodeAbiParameters(
        parseAbiParameters("bytes32, bytes32"),
        [hashHex as `0x${string}`, toHex(root, { size: 32 })],
    );
}

/**
 * Convenience wrapper: encode the full calldata to submit a ZK Signer proof
 * for transaction approval.
 *
 * Layout: abi.encode(bytes proof, bytes32 txnHash, bytes32 signersRoot)
 */
export function encodeZKSignerProofCalldata(proofData: ZKSignerProofData): Hex {
    return encodeAbiParameters(
        parseAbiParameters("bytes, bytes32, bytes32"),
        [
            proofData.proof,
            proofData.txnHash  as `0x${string}`,
            proofData.signersRoot as `0x${string}`,
        ],
    );
}
