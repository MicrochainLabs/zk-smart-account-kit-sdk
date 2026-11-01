/**
 * Merkle tree construction and proof generation for the ZK Label registry.
 *
 * Uses LeanIMT (Lean Incremental Merkle Tree) with Poseidon2 as the internal
 * node hash — matching the binary_merkle_root call inside the Noir circuit.
 */

import type { Address } from "viem";
import { buildTree, generatePaddedProof, type MerkleTreeLike } from "../internal/merkle.js";
import { computeLabelLeaf, labelsHash } from "./leaf.js";
import { LABELS_MAX_DEPTH, type LabelEntry, type LabelsTree, type LabelMerkleProof } from "./types.js";

/**
 * Build a LeanIMT registry tree from an ordered list of label entries.
 *
 * Insertion order determines the Merkle path for each leaf, so the caller
 * must use a canonical ordering (e.g. sorted by labelName) to ensure the
 * resulting registryRoot is deterministic and reproducible.
 *
 * @throws {InvalidArgumentError} if `labels` is empty or an entry is invalid.
 * @throws {TreeCapacityError} if there are more than 2 ** LABELS_MAX_DEPTH entries.
 */
export function buildLabelsTree(labels: LabelEntry[]): LabelsTree {
    const leaves: bigint[] = labels.map(({ labelName, signer: address }) => computeLabelLeaf(labelName, address));
    const tree = buildTree(leaves, labelsHash, LABELS_MAX_DEPTH, "Labels registry");

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
export function getLabelMerkleProof(tree: MerkleTreeLike, labelName: string, signer: Address): LabelMerkleProof {
    return generatePaddedProof(
        tree,
        computeLabelLeaf(labelName, signer),
        LABELS_MAX_DEPTH,
        () =>
            `Label "${labelName}" => ${signer} not found in tree. ` +
            `Ensure the registry was built with the same entry ordering.`,
    );
}
