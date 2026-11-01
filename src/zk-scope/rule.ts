/**
 * Rule encoding and leaf hashing for the ZK Scope registry.
 *
 * All hash constructions must exactly match lib/zk_scope/src/lib.nr.
 */

import { poseidon } from "../internal/poseidon.js";
import { type Address, type Hex } from "viem";
import { InvalidArgumentError } from "../errors.js";
import { assertAddress, assertField } from "../internal/validation.js";
import {
    MAX_PARAMS,
    PARAM_EXACT,
    PARAM_RANGE_MAX,
    PARAM_UNCONSTRAINED,
    type ParamConstraint,
    type ScopeRule,
} from "./types.js";

/** Largest value the circuit can compare: it casts `value`, `value_max` and range bounds to u128. */
export const U128_MAX = (1n << 128n) - 1n;

// ─── Field conversions ────────────────────────────────────────────────────────

/**
 * Convert an Ethereum address to a BN254 field element.
 * Identical to ZK Label's addressToField — safe because 2^160 < field modulus.
 */
export function addressToField(address: Address): bigint {
    assertAddress(address, "address");
    return BigInt(address.toLowerCase());
}

/**
 * Convert a 4-byte function selector (e.g. "0xd0e30db0") to a field element.
 * The selector occupies the low 32 bits of the field.
 *
 * @throws {InvalidArgumentError} unless `selector` is a 0x-prefixed hex string of exactly 4 bytes.
 *         Full calldata is rejected rather than silently truncated.
 */
export function selectorToField(selector: Hex): bigint {
    if (typeof selector !== "string" || !/^0x[0-9a-fA-F]{8}$/.test(selector)) {
        throw new InvalidArgumentError(
            `selector must be a 0x-prefixed 4-byte hex string (e.g. "0xd0e30db0"); got ${JSON.stringify(selector)}.`,
        );
    }
    return BigInt(selector);
}

/** A value the circuit compares as u128 (transaction value, value cap, range-max bound). */
export function assertU128(value: unknown, name: string): bigint {
    const field = assertField(value, name);
    if (field > U128_MAX) {
        throw new InvalidArgumentError(
            `${name} must be at most 2^128 - 1 (the circuit compares it as u128); got ${field}.`,
        );
    }
    return field;
}

/**
 * Validate a scope rule: address, selector, value cap and every parameter constraint.
 *
 * @throws {InvalidArgumentError} on the first invalid field.
 */
export function assertScopeRule(rule: ScopeRule): void {
    if (typeof rule !== "object" || rule === null) {
        throw new InvalidArgumentError("rule must be an object.");
    }
    assertAddress(rule.target, "rule.target");
    selectorToField(rule.selector);
    assertU128(rule.valueMax, "rule.valueMax");

    if (!Array.isArray(rule.constraints) || rule.constraints.length !== MAX_PARAMS) {
        throw new InvalidArgumentError(
            `rule.constraints must have exactly ${MAX_PARAMS} entries (use padConstraints); got ${
                Array.isArray(rule.constraints) ? rule.constraints.length : typeof rule.constraints
            }.`,
        );
    }
    rule.constraints.forEach((c, i) => {
        if (![PARAM_UNCONSTRAINED, PARAM_EXACT, PARAM_RANGE_MAX].includes(c?.constraintType)) {
            throw new InvalidArgumentError(`rule.constraints[${i}].constraintType must be 0, 1 or 2.`);
        }
        if (c.constraintType === PARAM_RANGE_MAX) assertU128(c.value, `rule.constraints[${i}].value`);
        else assertField(c.value, `rule.constraints[${i}].value`);
    });
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
    const items: readonly ParamConstraint[] = constraints;
    if (items.length !== MAX_PARAMS) {
        throw new InvalidArgumentError(`constraints must have exactly ${MAX_PARAMS} entries.`);
    }
    const c = items.map((con, i) =>
        poseidon.hash([BigInt(con.constraintType), assertField(con.value, `constraints[${i}].value`)]),
    );
    return poseidon.hash([poseidon.hash([c[0], c[1]]), poseidon.hash([c[2], c[3]])]);
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
    const padded = padParamValues(paramValues);
    return poseidon.hash([poseidon.hash([padded[0], padded[1]]), poseidon.hash([padded[2], padded[3]])]);
}

/**
 * Compute the Merkle leaf for a scope rule.
 *
 * Construction (must match `compute_rule_leaf` in Noir):
 *   rule_leaf = Poseidon4([target, selector, value_max, params_hash])
 */
export function computeRuleLeaf(rule: ScopeRule): bigint {
    assertScopeRule(rule);
    const targetField = addressToField(rule.target);
    const selectorField = selectorToField(rule.selector);
    const paramsHash = computeParamsHash(rule.constraints);
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
 *
 * @throws {InvalidArgumentError} if there are more than MAX_PARAMS values or one is not a field element.
 */
export function padParamValues(values: bigint[]): bigint[] {
    if (!Array.isArray(values) || values.length > MAX_PARAMS) {
        throw new InvalidArgumentError(
            `paramValues must be an array of at most ${MAX_PARAMS} values; got ${
                Array.isArray(values) ? values.length : typeof values
            }.`,
        );
    }
    return Array.from({ length: MAX_PARAMS }, (_, i) => assertField(values[i] ?? 0n, `paramValues[${i}]`));
}
