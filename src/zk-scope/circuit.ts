/**
 * Circuit input builder for zk_scope_validation.
 *
 * Browser-safe: no Node.js builtins, no proving deps.
 * Import `./prove.js` for actual proof generation (Node.js only).
 */

import { toHex, type Address, type Hex } from "viem";
import { LeanIMT } from "@zk-kit/lean-imt";
import {
    addressToField,
    selectorToField,
    computeCalldataHash,
    padParamValues,
} from "./rule.js";
import { getRuleMerkleProof } from "./tree.js";
import type {
    ScopeRule,
    ScopeMerkleProof,
    ScopeCircuitInput,
} from "./types.js";

/**
 * Build the full circuit input object from a pre-computed Merkle proof.
 *
 * Use this when you already hold a ScopeMerkleProof (e.g. in a browser
 * that received the proof from a server).
 */
export function buildScopeCircuitInputFromProof(
    txnTarget:    Address,
    txnSelector:  Hex,
    txnValue:     bigint,
    paramValues:  bigint[],
    rule:         ScopeRule,
    merkleProof:  ScopeMerkleProof,
    scopeRoot:    bigint,
): ScopeCircuitInput {
    const padded          = padParamValues(paramValues);
    const calldataHash    = computeCalldataHash(padded);

    return {
        // Private: rule
        rule_target:    toHex(addressToField(rule.target)),
        rule_selector:  toHex(selectorToField(rule.selector)),
        rule_value_max: toHex(rule.valueMax),
        rule_constraints: rule.constraints.map((c) => ({
            constraint_type: c.constraintType,
            value:           toHex(c.value),
        })),
        // Private: decoded calldata
        param_values: padded.map((v) => toHex(v)),
        // Private: Merkle proof
        proof_length:   merkleProof.merkle_proof_length,
        proof_indices:  merkleProof.merkle_proof_indices,
        proof_siblings: merkleProof.merkle_proof_siblings,
        // Public: transaction
        txn_target:        toHex(addressToField(txnTarget)),
        txn_selector:      toHex(selectorToField(txnSelector)),
        txn_value:         toHex(txnValue),
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
    txnTarget:   Address,
    txnSelector: Hex,
    txnValue:    bigint,
    paramValues: bigint[],
    rule:        ScopeRule,
    tree:        LeanIMT,
    scopeRoot:   bigint,
): ScopeCircuitInput {
    const proof = getRuleMerkleProof(tree, rule);
    return buildScopeCircuitInputFromProof(
        txnTarget, txnSelector, txnValue, paramValues, rule, proof, scopeRoot,
    );
}
