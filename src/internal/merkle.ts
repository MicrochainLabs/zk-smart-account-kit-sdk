/**
 * Lean Incremental Merkle Tree (LeanIMT) and circuit-ready proof generation.
 *
 * The tree is a port of the append-only subset of `@zk-kit/lean-imt` that the
 * SDK needs. It is implemented here so the published package has no runtime
 * dependency on `@zk-kit/utils` → `ethers` → `ws`, a chain that is never loaded
 * but is flagged by `npm audit` in every consumer project. Behaviour is pinned
 * to the upstream implementation by differential tests (test/merkle.spec.ts).
 *
 * Shape: a node with no right sibling is promoted unchanged to the next level
 * (no padding hashes), which is what the Noir `merkle_root_with_depth` expects.
 */

import { toHex, type Hex } from "viem";
import { InvalidArgumentError, NotFoundError, TreeCapacityError } from "../errors.js";

/** Binary node hash. */
export type HashFunction = (a: bigint, b: bigint) => bigint;

/** The part of a tree needed to produce a proof; satisfied by this class and by `@zk-kit/lean-imt`. */
export interface MerkleTreeLike {
    indexOf(leaf: bigint): number;
    generateProof(index: number): { siblings: bigint[]; index: number };
}

/** Append-only Lean Incremental Merkle Tree. */
export class LeanIMT implements MerkleTreeLike {
    private readonly nodes: bigint[][] = [[]];

    constructor(private readonly hash: HashFunction) {}

    /** Merkle root. Throws on an empty tree, which has no defined root. */
    get root(): bigint {
        if (this.size === 0) throw new InvalidArgumentError("An empty tree has no root.");
        return this.nodes[this.depth][0];
    }

    get depth(): number {
        return this.nodes.length - 1;
    }

    get size(): number {
        return this.nodes[0].length;
    }

    get leaves(): bigint[] {
        return this.nodes[0].slice();
    }

    indexOf(leaf: bigint): number {
        return this.nodes[0].indexOf(leaf);
    }

    has(leaf: bigint): boolean {
        return this.nodes[0].includes(leaf);
    }

    insert(leaf: bigint): void {
        if (typeof leaf !== "bigint") throw new InvalidArgumentError("Tree leaves must be bigint.");

        if (this.depth < Math.ceil(Math.log2(this.size + 1))) this.nodes.push([]);

        let node = leaf;
        let index = this.size;
        for (let level = 0; level < this.depth; level++) {
            this.nodes[level][index] = node;
            if (index & 1) node = this.hash(this.nodes[level][index - 1], node);
            index >>= 1;
        }
        this.nodes[this.depth] = [node];
    }

    /**
     * Membership proof for the leaf at `index`. `siblings` omits levels where the
     * node was promoted without a sibling; `index` packs the left/right bits of
     * the remaining levels (bit 0 = lowest level).
     */
    generateProof(index: number): { root: bigint; leaf: bigint; siblings: bigint[]; index: number } {
        if (!Number.isInteger(index) || index < 0 || index >= this.size) {
            throw new NotFoundError(`The leaf at index '${index}' does not exist in this tree.`);
        }

        const leaf = this.nodes[0][index];
        const siblings: bigint[] = [];
        const path: number[] = [];

        let cursor = index;
        for (let level = 0; level < this.depth; level++) {
            const isRight = cursor & 1;
            const sibling = this.nodes[level][isRight ? cursor - 1 : cursor + 1];
            if (sibling !== undefined) {
                path.push(isRight);
                siblings.push(sibling);
            }
            cursor >>= 1;
        }

        return {
            root: this.root,
            leaf,
            siblings,
            index: path.length === 0 ? 0 : Number.parseInt([...path].reverse().join(""), 2),
        };
    }
}

/** Circuit-ready, fixed-size Merkle proof. Field names match the Noir circuit inputs. */
export interface PaddedMerkleProof {
    /** Actual number of sibling hashes. */
    merkle_proof_length: number;
    /** Direction bits per level, padded with `false`: `false` = node is the left child. */
    merkle_proof_indices: boolean[];
    /** Sibling hashes per level, padded with `"0x0"`. */
    merkle_proof_siblings: Hex[];
}

/** Reject a leaf set the circuit could never prove (`size > 2 ** maxDepth`). */
export function assertTreeCapacity(size: number, maxDepth: number, what: string): void {
    const capacity = 2 ** maxDepth;
    if (size > capacity) {
        throw new TreeCapacityError(
            `${what} would hold ${size} entries but the circuit supports at most ${capacity} (depth ${maxDepth}). ` +
                `A root over more entries cannot be proven.`,
        );
    }
}

/**
 * Build a LeanIMT from leaves, enforcing a non-empty set that fits the circuit depth.
 */
export function buildTree(leaves: bigint[], hash: HashFunction, maxDepth: number, what: string): LeanIMT {
    if (leaves.length === 0) {
        throw new InvalidArgumentError(`${what} must contain at least one entry.`);
    }
    assertTreeCapacity(leaves.length, maxDepth, what);

    const tree = new LeanIMT(hash);
    for (const leaf of leaves) tree.insert(leaf);
    return tree;
}

/**
 * Produce a Merkle proof for `leaf`, padded to `maxDepth` for use as private circuit inputs.
 *
 * @throws {NotFoundError} if the leaf is not in the tree.
 * @throws {TreeCapacityError} if the proof is deeper than the circuit supports.
 */
export function generatePaddedProof(
    tree: MerkleTreeLike,
    leaf: bigint,
    maxDepth: number,
    describeMissing: () => string,
): PaddedMerkleProof {
    const index = tree.indexOf(leaf);
    if (index === -1) throw new NotFoundError(describeMissing());

    const proof = tree.generateProof(index);
    if (proof.siblings.length > maxDepth) {
        throw new TreeCapacityError(
            `Merkle proof has depth ${proof.siblings.length} but the circuit supports at most ${maxDepth}.`,
        );
    }

    return {
        merkle_proof_length: proof.siblings.length,
        merkle_proof_indices: Array.from({ length: maxDepth }, (_, i) => ((proof.index >> i) & 1) === 1),
        merkle_proof_siblings: Array.from({ length: maxDepth }, (_, i) =>
            i < proof.siblings.length ? toHex(proof.siblings[i]) : "0x0",
        ),
    };
}

/** Validate a caller-supplied padded proof against the circuit depth. */
export function assertPaddedProof(proof: PaddedMerkleProof, maxDepth: number): void {
    if (
        !proof ||
        !Number.isInteger(proof.merkle_proof_length) ||
        proof.merkle_proof_length < 0 ||
        proof.merkle_proof_length > maxDepth
    ) {
        throw new InvalidArgumentError(`merkle_proof_length must be an integer in 0..${maxDepth}.`);
    }
    if (!Array.isArray(proof.merkle_proof_indices) || proof.merkle_proof_indices.length !== maxDepth) {
        throw new InvalidArgumentError(`merkle_proof_indices must have exactly ${maxDepth} entries.`);
    }
    if (!Array.isArray(proof.merkle_proof_siblings) || proof.merkle_proof_siblings.length !== maxDepth) {
        throw new InvalidArgumentError(`merkle_proof_siblings must have exactly ${maxDepth} entries.`);
    }
}
