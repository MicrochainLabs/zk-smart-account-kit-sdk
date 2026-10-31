/**
 * ABI encoding helpers for on-chain interactions with ZK Signer validators.
 *
 * These match the calldata layout expected by ZKSignerValidator (ERC-7579).
 * Browser-safe: no proving deps required.
 */

import { bytesToHex, encodeAbiParameters, parseAbiParameters, toHex, type Hex } from "viem";
import { assertBytes, assertHex, assertHexBytes, toFieldElement } from "../internal/validation.js";
import { HASH_BYTES, type ZKSignerProofData } from "./types.js";

/**
 * Encode the initialisation calldata passed to the validator during module
 * installation (e.g. ZKSignerValidator.onInstall / initData).
 *
 * Layout: abi.encode(bytes32 signersRoot)
 *
 * @throws {InvalidArgumentError} if the root is not a BN254 field element.
 */
export function encodeSignersInitData(signersRoot: bigint | Hex): Hex {
    const root = toFieldElement(signersRoot, "signersRoot");
    return encodeAbiParameters(parseAbiParameters("bytes32"), [toHex(root, { size: 32 })]);
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
 * @throws {InvalidArgumentError} if the hash is not 32 bytes or the root is not a field element.
 */
export function encodeZKSignerPublicInputs(txnHash: Hex | number[], signersRoot: bigint | Hex): Hex {
    const hashHex = Array.isArray(txnHash)
        ? bytesToHex(Uint8Array.from(assertBytes(txnHash, HASH_BYTES, "txnHash")))
        : assertHexBytes(txnHash, HASH_BYTES, "txnHash");
    const root = toFieldElement(signersRoot, "signersRoot");

    return encodeAbiParameters(parseAbiParameters("bytes32, bytes32"), [hashHex, toHex(root, { size: 32 })]);
}

/**
 * Convenience wrapper: encode the full calldata to submit a ZK Signer proof
 * for transaction approval.
 *
 * Layout: abi.encode(bytes proof, bytes32 txnHash, bytes32 signersRoot)
 *
 * @throws {InvalidArgumentError} if `txnHash` or `signersRoot` is not a 32-byte hex string.
 */
export function encodeZKSignerProofCalldata(proofData: ZKSignerProofData): Hex {
    return encodeAbiParameters(parseAbiParameters("bytes, bytes32, bytes32"), [
        assertHex(proofData.proof, "proofData.proof"),
        assertHexBytes(proofData.txnHash, HASH_BYTES, "proofData.txnHash"),
        assertHexBytes(proofData.signersRoot, 32, "proofData.signersRoot"),
    ]);
}
