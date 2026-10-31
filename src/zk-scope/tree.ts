/**
 * Merkle tree construction and proof generation for the ZK Scope registry.
 */

import { buildTree, generatePaddedProof, type MerkleTreeLike } from "../internal/merkle.js";
import { computeRuleLeaf, scopeHash } from "./rule.js";
import { SCOPE_MAX_DEPTH, type ScopeRule, type ScopeTree, type ScopeMerkleProof } from "./types.js";

/**
 * Build a LeanIMT scope tree from an ordered list of scope rules.
 *
 * Insertion order determines the Merkle path for each rule. Use a canonical
 * ordering (e.g. sorted by target + selector) for deterministic roots.
 *
 * @throws {InvalidArgumentError} if `rules` is empty or a rule is invalid.
 * @throws {TreeCapacityError} if there are more than 2 ** SCOPE_MAX_DEPTH rules.
 */
export function buildScopeTree(rules: ScopeRule[]): ScopeTree {
    const leaves = rules.map(computeRuleLeaf);
    const tree = buildTree(leaves, scopeHash, SCOPE_MAX_DEPTH, "Scope tree");

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
export function getRuleMerkleProof(tree: MerkleTreeLike, rule: ScopeRule): ScopeMerkleProof {
    return generatePaddedProof(
        tree,
        computeRuleLeaf(rule),
        SCOPE_MAX_DEPTH,
        () =>
            `Scope rule (target=${rule.target}, selector=${rule.selector}) ` +
            `not found in tree. Ensure the registry was built with the same rule set.`,
    );
}
