/**
 * Circuit input builder for zk_scope_validation.
 *
 * Browser-safe: no Node.js builtins, no proving deps.
 * Import `./prove.js` for actual proof generation (Node.js only).
 */

import { toHex, type Address, type Hex } from "viem";
import { InvalidArgumentError } from "../errors.js";
import { assertPaddedProof, type MerkleTreeLike } from "../internal/merkle.js";
import { assertField } from "../internal/validation.js";
import {
    addressToField,
    selectorToField,
    assertScopeRule,
    assertU128,
    computeCalldataHash,
    padParamValues,
} from "./rule.js";
import { getRuleMerkleProof } from "./tree.js";
import {
    MAX_PARAMS,
    PARAM_EXACT,
    PARAM_RANGE_MAX,
    SCOPE_MAX_DEPTH,
    type ScopeRule,
    type ScopeMerkleProof,
    type ScopeCircuitInput,
} from "./types.js";

/**
 * Build the full circuit input object from a pre-computed Merkle proof.
 *
 * Use this when you already hold a ScopeMerkleProof (e.g. in a browser
 * that received the proof from a server).
 */
export function buildScopeCircuitInputFromProof(
    txnTarget: Address,
    txnSelector: Hex,
    txnValue: bigint,
    paramValues: bigint[],
    rule: ScopeRule,
    merkleProof: ScopeMerkleProof,
    scopeRoot: bigint,
): ScopeCircuitInput {
    assertScopeRule(rule);
    const target = addressToField(txnTarget);
    const selector = selectorToField(txnSelector);
    assertU128(txnValue, "txnValue");
    assertField(scopeRoot, "scopeRoot");
    assertPaddedProof(merkleProof, SCOPE_MAX_DEPTH);

    const padded = padParamValues(paramValues);
    assertTxnWithinRule(target, selector, txnValue, padded, rule);
    const calldataHash = computeCalldataHash(padded);

    return {
        // Private: rule
        rule_target: toHex(addressToField(rule.target)),
        rule_selector: toHex(selectorToField(rule.selector)),
        rule_value_max: toHex(rule.valueMax),
        rule_constraints: rule.constraints.map((c) => ({
            constraint_type: c.constraintType,
            value: toHex(c.value),
        })),
        // Private: decoded calldata
        param_values: padded.map((v) => toHex(v)),
        // Private: Merkle proof
        proof_length: merkleProof.merkle_proof_length,
        proof_indices: merkleProof.merkle_proof_indices,
        proof_siblings: merkleProof.merkle_proof_siblings,
        // Public: transaction
        txn_target: toHex(target),
        txn_selector: toHex(selector),
        txn_value: toHex(txnValue),
        txn_calldata_hash: toHex(calldataHash),
        // Public: on-chain
        scope_root: toHex(scopeRoot),
    };
}

/**
 * Build the full circuit input from a live LeanIMT tree.
 * Automatically derives the Merkle proof from the tree.
 */
export function buildScopeCircuitInput(
    txnTarget: Address,
    txnSelector: Hex,
    txnValue: bigint,
    paramValues: bigint[],
    rule: ScopeRule,
    tree: MerkleTreeLike,
    scopeRoot: bigint,
): ScopeCircuitInput {
    const proof = getRuleMerkleProof(tree, rule);
    return buildScopeCircuitInputFromProof(txnTarget, txnSelector, txnValue, paramValues, rule, proof, scopeRoot);
}

/**
 * Off-circuit mirror of the transaction checks in `verify_scope_membership`
 * (target, selector, value cap, parameter constraints). Fails fast with a precise
 * message instead of an opaque witness failure after the proving set-up.
 */
function assertTxnWithinRule(target: bigint, selector: bigint, value: bigint, params: bigint[], rule: ScopeRule): void {
    if (addressToField(rule.target) !== target) {
        throw new InvalidArgumentError("Transaction target does not match the rule target.");
    }
    if (selectorToField(rule.selector) !== selector) {
        throw new InvalidArgumentError("Transaction selector does not match the rule selector.");
    }
    if (value > rule.valueMax) {
        throw new InvalidArgumentError(`Transaction value ${value} exceeds the rule maximum ${rule.valueMax}.`);
    }
    for (let i = 0; i < MAX_PARAMS; i++) {
        const { constraintType, value: bound } = rule.constraints[i];
        if (constraintType === PARAM_EXACT && params[i] !== bound) {
            throw new InvalidArgumentError(`Parameter ${i} must equal ${bound}; got ${params[i]}.`);
        }
        if (constraintType === PARAM_RANGE_MAX) {
            assertU128(params[i], `paramValues[${i}] (range-constrained)`);
            if (params[i] > bound) {
                throw new InvalidArgumentError(`Parameter ${i} must be at most ${bound}; got ${params[i]}.`);
            }
        }
    }
}
