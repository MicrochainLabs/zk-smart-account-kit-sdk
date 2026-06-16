/**
 * Merkle tree construction and proof generation for the ZK Scope registry.
 */

import { LeanIMT } from "@zk-kit/lean-imt";
import { toHex, type Hex } from "viem";
import { computeRuleLeaf, scopeHash } from "./rule.js";
import {
    SCOPE_MAX_DEPTH,
    type ScopeRule,
    type ScopeTree,
    type ScopeMerkleProof,
} from "./types.js";

/**
 * Build a LeanIMT scope tree from an ordered list of scope rules.
 *
 * Insertion order determines the Merkle path for each rule. Use a canonical
 * ordering (e.g. sorted by target + selector) for deterministic roots.
 */
export function buildScopeTree(rules: ScopeRule[]): ScopeTree {
    const leaves = rules.map(computeRuleLeaf);

    // @ts-ignore — LeanIMT constructor signature varies across versions
    const tree = new LeanIMT(scopeHash);
    for (const leaf of leaves) tree.insert(leaf);

    return { tree, scopeRoot: tree.root, leaves };
}

/**
 * Generate a Merkle membership proof for the given scope rule.
 *
 * The proof is padded to SCOPE_MAX_DEPTH and structured for direct use as
 * the circuit's private inputs.
 *
 * @throws if the rule is not found in the tree. Ensure the tree was built
 *         with the same rule set and ordering.
 */
export function getRuleMerkleProof(
    tree: LeanIMT,
    rule: ScopeRule,
): ScopeMerkleProof {
    const leaf  = computeRuleLeaf(rule);
    const index = tree.indexOf(leaf);

    if (index === -1) {
        throw new Error(
            `Scope rule (target=${rule.target}, selector=${rule.selector}) ` +
            `not found in tree. Ensure the registry was built with the same rule set.`
        );
    }

    const proof = tree.generateProof(index);

    const paddedSiblings: Hex[] = Array.from(
        { length: SCOPE_MAX_DEPTH },
        (_, i) => (i < proof.siblings.length ? toHex(proof.siblings[i]) : "0x0") as Hex,
    );

    const paddedIndices: number[] = Array.from(
        { length: SCOPE_MAX_DEPTH },
        (_, i) => (proof.index >> i) & 1,
    );

    return {
        merkle_proof_length:   proof.siblings.length,
        merkle_proof_indices:  paddedIndices,
        merkle_proof_siblings: paddedSiblings,
    };
}
