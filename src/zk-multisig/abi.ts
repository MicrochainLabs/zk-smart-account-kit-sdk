/**
 * Public-input encoding of the ZK MultiSig circuits, in the layout the on-chain ERC-8039 verifier
 * adapters and the Safe/Nexus contracts use. Browser-safe.
 */

import { encodeAbiParameters, parseAbiParameters, toHex, type Hex } from "viem";
import { toFieldElement } from "../internal/validation.js";
import { normalizeHash, type HashInput } from "./circuit.js";

/**
 * The 33 public inputs of `zk_multi_sig_ecdsa` as `bytes32` words: one word per byte of the
 * transaction hash, then the state root. This is the array the contracts pass to the verifier and
 * equals the `publicInputs` of a generated proof.
 *
 * @throws {InvalidArgumentError} if the hash is not 32 bytes or the root is not a field element.
 */
export function buildMultiSigPublicInputs(txnHash: HashInput, stateRoot: bigint | Hex): Hex[] {
    const hash = normalizeHash(txnHash);
    const root = toFieldElement(stateRoot, "stateRoot");
    return [...hash.map((byte) => toHex(byte, { size: 32 })), toHex(root, { size: 32 })];
}

/** `abi.encode(bytes32[33])` as dynamic array, the `publicInputs` argument of `IERC8039.verifyProof`. */
export function encodeMultiSigPublicInputs(txnHash: HashInput, stateRoot: bigint | Hex): Hex {
    return encodeAbiParameters(parseAbiParameters("bytes32[]"), [buildMultiSigPublicInputs(txnHash, stateRoot)]);
}

/** The single public input of the state-validation circuit: the state root. */
export function buildStateValidationPublicInputs(stateRoot: bigint | Hex): Hex[] {
    return [toHex(toFieldElement(stateRoot, "stateRoot"), { size: 32 })];
}

/** `abi.encode(bytes32[1])` as dynamic array, the `publicInputs` argument of the state-validation verifier. */
export function encodeStateValidationPublicInputs(stateRoot: bigint | Hex): Hex {
    return encodeAbiParameters(parseAbiParameters("bytes32[]"), [buildStateValidationPublicInputs(stateRoot)]);
}
