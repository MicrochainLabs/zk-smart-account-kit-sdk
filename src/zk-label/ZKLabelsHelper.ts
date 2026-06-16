/**
 * createZKLabels — high-level factory for ZK Label registry management.
 *
 * Returns a plain object (viem-style) with methods for tree construction,
 * proof generation, and commitment helpers. Suitable for Node.js backends
 * and CLI scripts.
 *
 * @example
 * ```ts
 * import circuit from "...zk_label_binding.json" assert { type: "json" };
 * import { createZKLabels } from "@microchain/zk-sdk/zk-label";
 *
 * const labels = createZKLabels(
 *   [
 *     { labelName: "admin",  address: "0xABCD…" },
 *     { labelName: "signer", address: "0x1234…" },
 *   ],
 *   circuit,
 * );
 *
 * const proofData = await labels.proveLabelMembership("admin", "0xABCD…");
 * console.log("proof:", proofData.proof);
 * ```
 */

import { type Address, type Hex } from "viem";
import { computeLabelLeaf } from "./leaf.js";
import { buildLabelsTree } from "./tree.js";
import { computeLabelCommitment } from "./circuit.js";
import { generateLabelBindingProof } from "./prove.js";
import type {
    LabelEntry,
    LabelBindingProofData,
} from "./types.js";

// ─── Public type ───────────────────────────────────────────────────────────────

export type ZKLabels = {
    /** On-chain Merkle root commitment (hex). Updated automatically after addLabel / removeLabel. */
    readonly registryRoot: Hex;
    /** Generate a ZK membership proof for the given (labelName, signer) pair. */
    proveLabelMembership(labelName: string, signer: Address): Promise<LabelBindingProofData>;
    /** Compute the Poseidon leaf commitment without proving. */
    computeLabelCommitment(labelName: string, signer: Address): bigint;
    /** Returns true if the (labelName, signer) pair is present in the registry. */
    hasLabel(labelName: string, signer: Address): boolean;
    /**
     * Append a new label entry to the registry.
     * Inserts the leaf into the live Merkle tree and returns the updated registryRoot.
     */
    addLabel(entry: LabelEntry): Hex;
    /**
     * Remove an existing label entry from the registry.
     * Rebuilds the tree from the remaining entries and returns the updated registryRoot.
     * @throws if the (labelName, signer) pair is not found.
     */
    removeLabel(entry: LabelEntry): Hex;
};

// ─── Factory ───────────────────────────────────────────────────────────────────

/**
 * Build the registry Merkle tree and return a ZKLabels instance.
 *
 * @param labels  - Ordered label entries (canonical ordering required for determinism).
 * @param circuit - Compiled Noir circuit artifact (parsed JSON).
 */
export function createZKLabels(
    labels:  LabelEntry[],
    circuit: unknown,
): ZKLabels {
    // Mutable state — mutated by addLabel / removeLabel.
    const state = {
        entries: [...labels],
        tree:    buildLabelsTree(labels),
    };

    const instance: ZKLabels = {
        get registryRoot(): Hex {
            return `0x${state.tree.tree.root.toString(16)}` as Hex;
        },

        proveLabelMembership(labelName, signer) {
            return generateLabelBindingProof(labelName, signer, state.tree, circuit);
        },

        computeLabelCommitment(labelName, signer) {
            return computeLabelCommitment(labelName, signer);
        },

        hasLabel(labelName, signer) {
            const leaf = computeLabelLeaf(labelName, signer);
            return state.tree.tree.indexOf(leaf) !== -1;
        },

        addLabel({ labelName, signer }) {
            const leaf = computeLabelLeaf(labelName, signer);
            state.entries.push({ labelName, signer });
            state.tree.tree.insert(leaf);
            state.tree.leaves.push(leaf);
            state.tree.registryRoot = state.tree.tree.root;
            return instance.registryRoot;
        },

        removeLabel({ labelName, signer }) {
            const leaf = computeLabelLeaf(labelName, signer);
            if (state.tree.tree.indexOf(leaf) === -1) {
                throw new Error(
                    `Label "${labelName}" => ${signer} not found in registry.`,
                );
            }
            state.entries = state.entries.filter(
                e => !(e.labelName === labelName && e.signer === signer),
            );
            state.tree = buildLabelsTree(state.entries);
            return instance.registryRoot;
        },
    };

    return instance;
}
