/**
 * Merkle tree construction and proof generation for the ZK MultiSig signers set.
 *
 * Uses LeanIMT (Lean Incremental Merkle Tree) with Poseidon2 as the internal
 * node hash — matching the binary_merkle_root call inside the Noir circuit.
 */

import { LeanIMT } from "@zk-kit/lean-imt";
import { toHex, type Hex, type Address } from "viem";
import { computeSignerLeaf, signersHash } from "./leaf.js";
import {
    SIGNERS_MAX_DEPTH,
    type SignerEntry,
    type SignersTree,
    type SignerMerkleProof,
} from "./types.js";

/**
 * Build a LeanIMT signers tree from an ordered list of signer entries.
 *
 * Insertion order determines the Merkle path for each leaf, so the caller
 * must use a canonical ordering (e.g. sorted by address ascending) to ensure
 * the resulting signersRoot is deterministic and reproducible.
 */
export function buildSignersTree(signers: SignerEntry[]): SignersTree {
    const leaves: bigint[] = signers.map(({ address }) =>
        computeSignerLeaf(address)
    );

    // @ts-ignore — LeanIMT constructor signature varies across versions
    const tree = new LeanIMT(signersHash);
    for (const leaf of leaves) tree.insert(leaf);

    return { tree, signersRoot: tree.root, leaves };
}

/**
 * Generate a Merkle membership proof for a specific signer address.
 *
 * The proof is padded to SIGNERS_MAX_DEPTH and structured for direct use as
 * the circuit's private inputs.
 *
 * @throws if the address is not found in the tree.
 */
export function getSignerMerkleProof(
    tree: LeanIMT,
    address: Address,
): SignerMerkleProof {
    const leaf  = computeSignerLeaf(address);
    const index = tree.indexOf(leaf);

    if (index === -1) {
        throw new Error(
            `Signer ${address} not found in tree. ` +
            `Ensure the signers set was built with the same entry ordering.`
        );
    }

    const proof = tree.generateProof(index);

    // Pad siblings to SIGNERS_MAX_DEPTH; unused slots are "0x0".
    const paddedSiblings: Hex[] = Array.from(
        { length: SIGNERS_MAX_DEPTH },
        (_, i) => (i < proof.siblings.length ? toHex(proof.siblings[i]) : "0x0") as Hex,
    );

    // Decode direction bits from leaf index: bit i = direction at depth i.
    const paddedIndices: number[] = Array.from(
        { length: SIGNERS_MAX_DEPTH },
        (_, i) => (proof.index >> i) & 1,
    );

    return {
        merkle_proof_length:   proof.siblings.length,
        merkle_proof_indices:  paddedIndices,
        merkle_proof_siblings: paddedSiblings,
    };
}
