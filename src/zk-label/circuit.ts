/**
 * Builds the full private-input object for the zk_label_binding Noir circuit.
 *
 * This module is browser-safe (no Node.js builtins, no heavy proving deps).
 * Import `./prove.js` for actual proof generation.
 */

import { poseidon } from "@iden3/js-crypto";
import { toHex, type Hex, type Address } from "viem";
import { LeanIMT } from "@zk-kit/lean-imt";
import {
    labelNameToBytes,
    labelNameToField,
    addressToField,
    addressToBytes,
} from "./leaf.js";
import { getLabelMerkleProof } from "./tree.js";
import type { LabelBindingCircuitInput, LabelMerkleProof } from "./types.js";

/**
 * Compute the label commitment (public input #2).
 *
 *   label_commitment = Poseidon2(Poseidon1(label_name_field), Poseidon1(signer_field))
 *
 * Must match the derivation inside the Noir circuit.
 */
export function computeLabelCommitment(labelName: string, signer: Address): bigint {
    const labelHash   = poseidon.hash([labelNameToField(labelName)]);
    const signerHash  = poseidon.hash([addressToField(signer)]);
    return poseidon.hash([labelHash, signerHash]);
}

/**
 * Build the full circuit input object from a pre-computed Merkle proof.
 *
 * Use this low-level overload when you already hold a LabelMerkleProof
 * (e.g. when building inputs in a browser without the full tree present).
 */
export function buildLabelBindingCircuitInputFromProof(
    labelName:    string,
    signer:       Address,
    merkleProof:  LabelMerkleProof,
    registryRoot: bigint,
): LabelBindingCircuitInput {
    const commitment = computeLabelCommitment(labelName, signer);

    return {
        address_bytes:          addressToBytes(signer),
        label_bytes:            labelNameToBytes(labelName),
        merkle_proof_length:    merkleProof.merkle_proof_length,
        merkle_proof_indices:   merkleProof.merkle_proof_indices,
        merkle_proof_siblings:  merkleProof.merkle_proof_siblings,
        registry_root:          toHex(registryRoot),
        label_commitment:       toHex(commitment),
    };
}

/**
 * Build the full circuit input from a live LeanIMT tree.
 *
 * Automatically derives the Merkle proof from the tree.
 */
export function buildLabelBindingCircuitInput(
    labelName:    string,
    signer:       Address,
    tree:         LeanIMT,
    registryRoot: bigint,
): LabelBindingCircuitInput {
    const proof = getLabelMerkleProof(tree, labelName, signer);
    return buildLabelBindingCircuitInputFromProof(labelName, signer, proof, registryRoot);
}
