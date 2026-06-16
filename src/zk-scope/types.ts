import type { Hex, Address } from "viem";
import type { LeanIMT } from "@zk-kit/lean-imt";

// ─── Constants ─────────────────────────────────────────────────────────────────
// Must stay in sync with lib/zk_scope/src/lib.nr.

/** Maximum Merkle tree depth for the scope rule registry (2^6 = 64 rules max). */
export const SCOPE_MAX_DEPTH = 6;

/** Maximum number of decoded parameter constraints per scope rule. */
export const MAX_PARAMS = 4;

// ─── Constraint types ──────────────────────────────────────────────────────────

export const PARAM_UNCONSTRAINED = 0 as const;
export const PARAM_EXACT         = 1 as const;
export const PARAM_RANGE_MAX     = 2 as const;

export type ParamConstraintType =
    | typeof PARAM_UNCONSTRAINED
    | typeof PARAM_EXACT
    | typeof PARAM_RANGE_MAX;

// ─── Rule types ────────────────────────────────────────────────────────────────

/** A single constraint on one decoded calldata parameter. */
export interface ParamConstraint {
    /** Constraint type: 0 = unconstrained, 1 = exact match, 2 = range max (<=). */
    constraintType: ParamConstraintType;
    /**
     * Reference value for the constraint.
     * - EXACT: param must equal this value.
     * - RANGE_MAX: param must be <= this value (u128 comparison).
     * - UNCONSTRAINED: ignored (use 0n).
     */
    value: bigint;
}

/**
 * A scope rule: defines one permitted transaction pattern.
 * Each rule commits to (target, selector, valueMax, constraints).
 */
export interface ScopeRule {
    /** Allowed target contract address. */
    target: Address;
    /** Allowed 4-byte function selector (e.g. "0xd0e30db0"). */
    selector: Hex;
    /** Maximum ETH value in wei (0n = no ETH transfer allowed). */
    valueMax: bigint;
    /**
     * Parameter constraints, padded to MAX_PARAMS.
     * Unconstrained slots should use { constraintType: PARAM_UNCONSTRAINED, value: 0n }.
     */
    constraints: [ParamConstraint, ParamConstraint, ParamConstraint, ParamConstraint];
}

// ─── Tree types ────────────────────────────────────────────────────────────────

/** Result of buildScopeTree. */
export interface ScopeTree {
    /** The underlying LeanIMT instance. */
    tree:      LeanIMT;
    /** Poseidon Merkle root — stored on-chain in the validator. */
    scopeRoot: bigint;
    /** Computed leaf for each rule, in insertion order. */
    leaves:    bigint[];
}

// ─── Proof types ───────────────────────────────────────────────────────────────

/** Merkle membership proof for a scope rule, padded to SCOPE_MAX_DEPTH. */
export interface ScopeMerkleProof {
    merkle_proof_length:   number;
    merkle_proof_indices:  number[];
    merkle_proof_siblings: Hex[];
}

// ─── Circuit I/O ───────────────────────────────────────────────────────────────

/** Full input object for the zk_scope_validation Noir circuit. */
export interface ScopeCircuitInput {
    // Private: matching rule
    rule_target:      Hex;
    rule_selector:    Hex;
    rule_value_max:   Hex;
    rule_constraints: Array<{ constraint_type: number; value: Hex }>;
    // Private: decoded calldata
    param_values:     Hex[];
    // Private: Merkle proof
    proof_length:     number;
    proof_indices:    number[];
    proof_siblings:   Hex[];
    // Public: transaction
    txn_target:        Hex;
    txn_selector:      Hex;
    txn_value:         Hex;
    txn_calldata_hash: Hex;
    // Public: on-chain
    scope_root: Hex;
}

/** Output from generateScopeProof. */
export interface ScopeProofData {
    proof:           Hex;
    publicInputs:    Hex[];   // [txn_target, txn_selector, txn_value, txn_calldata_hash, scope_root]
    txnTarget:       Hex;
    txnSelector:     Hex;
    txnValue:        Hex;
    txnCalldataHash: Hex;
    scopeRoot:       Hex;
}

// ─── Helpers ───────────────────────────────────────────────────────────────────

/** Build a fully-unconstrained ParamConstraint slot (for padding). */
export function unconstrained(): ParamConstraint {
    return { constraintType: PARAM_UNCONSTRAINED, value: 0n };
}

/** Build an exact-match ParamConstraint. */
export function exactMatch(value: bigint): ParamConstraint {
    return { constraintType: PARAM_EXACT, value };
}

/** Build a range-max ParamConstraint (param <= value). */
export function rangeMax(max: bigint): ParamConstraint {
    return { constraintType: PARAM_RANGE_MAX, value: max };
}

/**
 * Pad a constraint array to exactly MAX_PARAMS slots.
 * Missing slots are filled with unconstrained.
 */
export function padConstraints(
    constraints: ParamConstraint[],
): [ParamConstraint, ParamConstraint, ParamConstraint, ParamConstraint] {
    const padded = Array.from({ length: MAX_PARAMS }, (_, i) =>
        constraints[i] ?? unconstrained()
    );
    return padded as [ParamConstraint, ParamConstraint, ParamConstraint, ParamConstraint];
}
