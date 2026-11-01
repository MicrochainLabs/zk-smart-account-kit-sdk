/**
 * Merkle tree construction and proof generation for the ZK Signer registry.
 *
 * Uses LeanIMT (Lean Incremental Merkle Tree) with Poseidon2 as the internal
 * node hash — matching the binary_merkle_root call inside the Noir circuit.
 */

import type { Address } from "viem";
import { generatePaddedProof, buildTree, type MerkleTreeLike } from "../internal/merkle.js";
import { computeSignerLeaf, signersHash } from "./leaf.js";
import { SIGNERS_MAX_DEPTH, type SignerEntry, type SignersTree, type SignerMerkleProof } from "./types.js";

/**
 * Build a LeanIMT signers tree from an ordered list of signer entries.
 *
 * Insertion order determines the Merkle path for each leaf, so the caller
 * must use a canonical ordering (e.g. sorted by address ascending) to ensure
 * the resulting signersRoot is deterministic and reproducible.
 *
 * @throws {InvalidArgumentError} if `signers` is empty or contains an invalid address.
 * @throws {TreeCapacityError} if there are more than 2 ** SIGNERS_MAX_DEPTH signers
 *         (such a root could never be proven by the circuit).
 */
export function buildSignersTree(signers: SignerEntry[]): SignersTree {
    const leaves: bigint[] = signers.map(({ signer }) => computeSignerLeaf(signer));
    const tree = buildTree(leaves, signersHash, SIGNERS_MAX_DEPTH, "Signers tree");

    return { tree, signersRoot: tree.root, leaves };
}

/**
 * Generate a Merkle membership proof for a specific signer address.
 *
 * The proof is padded to SIGNERS_MAX_DEPTH and structured for direct use as
 * the circuit's private inputs.
 *
 * @throws {NotFoundError} if the signer is not found in the tree.
 */
export function getSignerMerkleProof(tree: MerkleTreeLike, signer: Address): SignerMerkleProof {
    return generatePaddedProof(
        tree,
        computeSignerLeaf(signer),
        SIGNERS_MAX_DEPTH,
        () => `Signer ${signer} not found in tree. ` + `Ensure the signers set was built with the same entry ordering.`,
    );
}
