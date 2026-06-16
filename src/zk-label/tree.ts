/**
 * Merkle tree construction and proof generation for the ZK Label registry.
 *
 * Uses LeanIMT (Lean Incremental Merkle Tree) with Poseidon2 as the internal
 * node hash — matching the binary_merkle_root call inside the Noir circuit.
 */

import { LeanIMT } from "@zk-kit/lean-imt";
import { toHex, type Hex, type Address } from "viem";
import {
    computeLabelLeaf,
    labelsHash,
} from "./leaf.js";
import {
    LABELS_MAX_DEPTH,
    type LabelEntry,
    type LabelsTree,
    type LabelMerkleProof,
} from "./types.js";

/**
 * Build a LeanIMT registry tree from an ordered list of label entries.
 *
 * Insertion order determines the Merkle path for each leaf, so the caller
 * must use a canonical ordering (e.g. sorted by labelName) to ensure the
 * resulting registryRoot is deterministic and reproducible.
 */
export function buildLabelsTree(labels: LabelEntry[]): LabelsTree {
    const leaves: bigint[] = labels.map(({ labelName, signer: address }) =>
        computeLabelLeaf(labelName, address)
    );

    // @ts-ignore — LeanIMT constructor signature varies across versions
    const tree = new LeanIMT(labelsHash);
    for (const leaf of leaves) tree.insert(leaf);

    return { tree, registryRoot: tree.root, leaves };
}

/**
 * Generate a Merkle membership proof for a specific (labelName, address) pair.
 *
 * The proof is padded to LABELS_MAX_DEPTH and structured for direct use as
 * the circuit's private inputs.
 *
 * @throws if the (labelName, signer) pair is not found in the tree.
 */
export function getLabelMerkleProof(
    tree: LeanIMT,
    labelName: string,
    signer: Address,
): LabelMerkleProof {
    const leaf  = computeLabelLeaf(labelName, signer);
    const index = tree.indexOf(leaf);

    if (index === -1) {
        throw new Error(
            `Label "${labelName}" => ${signer} not found in tree. ` +
            `Ensure the registry was built with the same entry ordering.`
        );
    }

    const proof = tree.generateProof(index);

    // Pad siblings to LABELS_MAX_DEPTH; unused slots are "0x0".
    const paddedSiblings: Hex[] = Array.from(
        { length: LABELS_MAX_DEPTH },
        (_, i) => (i < proof.siblings.length ? toHex(proof.siblings[i]) : "0x0") as Hex,
    );

    // Decode direction bits from leaf index: bit i = direction at depth i.
    const paddedIndices: number[] = Array.from(
        { length: LABELS_MAX_DEPTH },
        (_, i) => (proof.index >> i) & 1,
    );

    return {
        merkle_proof_length:   proof.siblings.length,
        merkle_proof_indices:  paddedIndices,
        merkle_proof_siblings: paddedSiblings,
    };
}
