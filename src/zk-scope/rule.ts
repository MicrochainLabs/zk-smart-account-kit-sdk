/**
 * Rule encoding and leaf hashing for the ZK Scope registry.
 *
 * All hash constructions must exactly match lib/zk_scope/src/lib.nr.
 */

import { poseidon } from "@iden3/js-crypto";
import { toHex, type Address, type Hex } from "viem";
import {
    MAX_PARAMS,
    type ParamConstraint,
    type ScopeRule,
} from "./types.js";

// ─── Field conversions ────────────────────────────────────────────────────────

/**
 * Convert an Ethereum address to a BN254 field element.
 * Identical to ZK Label's addressToField — safe because 2^160 < field modulus.
 */
export function addressToField(address: Address): bigint {
    return BigInt(address.toLowerCase());
}

/**
 * Convert a 4-byte function selector (e.g. "0xd0e30db0") to a field element.
 * The selector occupies the low 32 bits of the field.
 */
export function selectorToField(selector: Hex): bigint {
    // Strip 0x and parse as big-endian u32
    const hex = selector.startsWith("0x") ? selector.slice(2) : selector;
    return BigInt("0x" + hex.padStart(8, "0").slice(0, 8));
}

// ─── Hashing (matches lib/zk_scope/src/lib.nr) ───────────────────────────────

/**
 * Compute the Poseidon commitment to a set of parameter constraints.
 *
 * Construction (must match `compute_params_hash` in Noir):
 *   c_i       = Poseidon2([constraint_type_i, value_i])
 *   h_lo      = Poseidon2([c_0, c_1])
 *   h_hi      = Poseidon2([c_2, c_3])
 *   params_hash = Poseidon2([h_lo, h_hi])
 */
export function computeParamsHash(
    constraints: [ParamConstraint, ParamConstraint, ParamConstraint, ParamConstraint],
): bigint {
    const c = constraints.map((con) =>
        poseidon.hash([BigInt(con.constraintType), con.value])
    );
    return poseidon.hash([
        poseidon.hash([c[0], c[1]]),
        poseidon.hash([c[2], c[3]]),
    ]);
}

/**
 * Compute the Poseidon commitment to the decoded calldata parameter values.
 *
 * Construction (must match `compute_calldata_hash` in Noir):
 *   h_lo          = Poseidon2([p_0, p_1])
 *   h_hi          = Poseidon2([p_2, p_3])
 *   calldata_hash = Poseidon2([h_lo, h_hi])
 *
 * @param paramValues - Decoded parameter values, padded with 0n to MAX_PARAMS length.
 */
export function computeCalldataHash(paramValues: bigint[]): bigint {
    const padded = Array.from({ length: MAX_PARAMS }, (_, i) => paramValues[i] ?? 0n);
    return poseidon.hash([
        poseidon.hash([padded[0], padded[1]]),
        poseidon.hash([padded[2], padded[3]]),
    ]);
}

/**
 * Compute the Merkle leaf for a scope rule.
 *
 * Construction (must match `compute_rule_leaf` in Noir):
 *   rule_leaf = Poseidon4([target, selector, value_max, params_hash])
 */
export function computeRuleLeaf(rule: ScopeRule): bigint {
    const targetField   = addressToField(rule.target);
    const selectorField = selectorToField(rule.selector);
    const paramsHash    = computeParamsHash(rule.constraints);
    return poseidon.hash([targetField, selectorField, rule.valueMax, paramsHash]);
}

/**
 * The Poseidon2 hash used as the LeanIMT internal node hash.
 * Must be the same function passed to `new LeanIMT(scopeHash)`.
 */
export function scopeHash(a: bigint, b: bigint): bigint {
    return poseidon.hash([a, b]);
}

/**
 * Pad a raw param values array to exactly MAX_PARAMS entries (fill with 0n).
 */
export function padParamValues(values: bigint[]): bigint[] {
    return Array.from({ length: MAX_PARAMS }, (_, i) => values[i] ?? 0n);
}
