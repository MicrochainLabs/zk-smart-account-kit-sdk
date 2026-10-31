/**
 * createZKLabels — high-level factory for ZK Label registry management.
 *
 * Returns a plain object (viem-style) with methods for tree construction,
 * proof generation, and commitment helpers. Suitable for Node.js backends
 * and CLI scripts.
 *
 * @example
 * ```ts
 * import circuit from "...zk_label_binding.json" with { type: "json" };
 * import { createZKLabels } from "zk-smart-account-kit-sdk/zk-label";
 *
 * const labels = createZKLabels(
 *   [
 *     { labelName: "admin",  signer: "0xABCD…" },
 *     { labelName: "signer", signer: "0x1234…" },
 *   ],
 *   circuit,
 * );
 *
 * const proofData = await labels.proveLabelMembership("admin", "0xABCD…");
 * console.log("proof:", proofData.proof);
 * ```
 */

import { type Address, type Hex } from "viem";
import { InvalidArgumentError, NotFoundError } from "../errors.js";
import { assertCircuit } from "../internal/compiled-circuit.js";
import type { ProveOptions } from "../internal/prover.js";
import { computeLabelLeaf } from "./leaf.js";
import { buildLabelsTree } from "./tree.js";
import { computeLabelCommitment } from "./circuit.js";
import { generateLabelBindingProof, ZK_LABEL_BINDING_CIRCUIT_PARAMS } from "./prove.js";
import type { LabelEntry, LabelBindingProofData } from "./types.js";

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
     * Returns the updated registryRoot. The registry is left unchanged if the entry is invalid.
     *
     * @throws {InvalidArgumentError} if the entry is malformed.
     * @throws {TreeCapacityError} if the registry is already full (16 entries).
     */
    addLabel(entry: LabelEntry): Hex;
    /**
     * Remove an existing label entry from the registry.
     * Rebuilds the tree from the remaining entries and returns the updated registryRoot.
     * @throws {NotFoundError} if the (labelName, signer) pair is not found.
     * @throws {InvalidArgumentError} if it is the last remaining entry (an empty registry has no root).
     */
    removeLabel(entry: LabelEntry): Hex;
};

// ─── Factory ───────────────────────────────────────────────────────────────────

/**
 * Build the registry Merkle tree and return a ZKLabels instance.
 *
 * @param labels  - Ordered label entries (canonical ordering required for determinism).
 * @param circuit - Compiled zk_label_binding artifact (parsed JSON).
 * @param options - Optional {@link ProveOptions} applied to every proof (e.g. a shared Barretenberg instance).
 * @throws {InvalidArgumentError} if `labels` is empty or invalid.
 * @throws {InvalidCircuitError} if `circuit` is not the zk_label_binding artifact.
 */
export function createZKLabels(labels: LabelEntry[], circuit: unknown, options?: ProveOptions): ZKLabels {
    const compiled = assertCircuit(circuit, "zk_label_binding", ZK_LABEL_BINDING_CIRCUIT_PARAMS);

    // Replaced wholesale on every mutation so a failed update never leaves a half-modified tree.
    const state = {
        entries: labels.map(({ labelName, signer }) => ({ labelName, signer })),
        tree: buildLabelsTree(labels),
    };

    const instance: ZKLabels = {
        get registryRoot(): Hex {
            return `0x${state.tree.registryRoot.toString(16)}`;
        },

        proveLabelMembership(labelName, signer) {
            return generateLabelBindingProof(labelName, signer, state.tree, compiled, options);
        },

        computeLabelCommitment(labelName, signer) {
            return computeLabelCommitment(labelName, signer);
        },

        hasLabel(labelName, signer) {
            return state.tree.tree.indexOf(computeLabelLeaf(labelName, signer)) !== -1;
        },

        addLabel({ labelName, signer }) {
            const entries = [...state.entries, { labelName, signer }];
            state.tree = buildLabelsTree(entries);
            state.entries = entries;
            return instance.registryRoot;
        },

        removeLabel({ labelName, signer }) {
            const leaf = computeLabelLeaf(labelName, signer);
            if (state.tree.tree.indexOf(leaf) === -1) {
                throw new NotFoundError(`Label "${labelName}" => ${signer} not found in registry.`);
            }
            // Compare by leaf, not by string, so address casing cannot leave a stale entry behind.
            const entries = state.entries.filter((e) => computeLabelLeaf(e.labelName, e.signer) !== leaf);
            if (entries.length === 0) {
                throw new InvalidArgumentError("Cannot remove the last label: an empty registry has no root.");
            }
            state.tree = buildLabelsTree(entries);
            state.entries = entries;
            return instance.registryRoot;
        },
    };

    return instance;
}
