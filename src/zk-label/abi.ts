/**
 * ABI encoding helpers for on-chain interactions with ZK Label validators.
 *
 * These match the calldata layout expected by the ZK Label validator (ERC-7579).
 * Browser-safe: no proving deps required.
 */

import { encodeAbiParameters, parseAbiParameters, toHex, type Hex } from "viem";
import { assertHex, assertHexBytes, toFieldElement } from "../internal/validation.js";
import type { LabelBindingProofData } from "./types.js";

/**
 * Encode the two public inputs (registryRoot, labelCommitment) for a
 * ZK Label proof as ABI-encoded bytes32 values.
 *
 * Used by the validator to verify which registry root and label commitment
 * the proof was generated against.
 */
export function encodeLabelBindingPublicInputs(registryRoot: bigint | Hex, labelCommitment: bigint | Hex): Hex {
    const root = toFieldElement(registryRoot, "registryRoot");
    const comm = toFieldElement(labelCommitment, "labelCommitment");

    return encodeAbiParameters(parseAbiParameters("bytes32, bytes32"), [
        toHex(root, { size: 32 }),
        toHex(comm, { size: 32 }),
    ]);
}

/**
 * Encode the initialisation calldata passed to the validator during module
 * installation (ZK Label validator onInstall / initData).
 *
 * Layout: abi.encode(bytes32 registryRoot)
 */
export function encodeLabelsInitData(registryRoot: bigint | Hex): Hex {
    const root = toFieldElement(registryRoot, "registryRoot");
    return encodeAbiParameters(parseAbiParameters("bytes32"), [toHex(root, { size: 32 })]);
}

/**
 * Encode the calldata for updating the on-chain registry root.
 *
 * Layout: abi.encode(bytes32 newRoot, bytes32 labelCommitment, bytes proof)
 */
export function encodeUpdateRegistryRootData(newRoot: bigint | Hex, labelCommitment: bigint | Hex, proof: Hex): Hex {
    const root = toFieldElement(newRoot, "newRoot");
    const comm = toFieldElement(labelCommitment, "labelCommitment");
    assertHex(proof, "proof");

    return encodeAbiParameters(parseAbiParameters("bytes32, bytes32, bytes"), [
        toHex(root, { size: 32 }),
        toHex(comm, { size: 32 }),
        proof,
    ]);
}

/**
 * Convenience wrapper: encode the calldata to submit a label proof for
 * transaction approval.
 *
 * Layout: abi.encode(bytes proof, bytes32 registryRoot, bytes32 labelCommitment)
 */
export function encodeLabelProofCalldata(proofData: LabelBindingProofData): Hex {
    return encodeAbiParameters(parseAbiParameters("bytes, bytes32, bytes32"), [
        assertHex(proofData.proof, "proofData.proof"),
        assertHexBytes(proofData.registryRoot, 32, "proofData.registryRoot"),
        assertHexBytes(proofData.labelCommitment, 32, "proofData.labelCommitment"),
    ]);
}
