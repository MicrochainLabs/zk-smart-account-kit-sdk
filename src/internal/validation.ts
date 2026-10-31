/**
 * Runtime argument validation shared by all modules.
 *
 * TypeScript types are erased at runtime and circuit inputs are byte-exact, so
 * every value that reaches a hash or a circuit is checked here first.
 */

import { isAddress, type Address, type Hex } from "viem";
import { InvalidArgumentError } from "../errors.js";

/** Order of the BN254 scalar field. Every Noir `Field` must be strictly below it. */
export const BN254_FIELD_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

/** Order n of the secp256k1 group; signatures must be low-S (s <= n / 2). */
export const SECP256K1_ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

export function assertAddress(value: unknown, name: string): asserts value is Address {
    if (typeof value !== "string" || !isAddress(value)) {
        throw new InvalidArgumentError(
            `${name} must be a valid 20-byte Ethereum address (a mixed-case address must carry a valid EIP-55 checksum); got ${describe(value)}.`,
        );
    }
}

/** Accepts `number[]` or `Uint8Array` and returns a plain `number[]` of exactly `length` bytes. */
export function assertBytes(value: unknown, length: number, name: string): number[] {
    if (!Array.isArray(value) && !(value instanceof Uint8Array)) {
        throw new InvalidArgumentError(
            `${name} must be a number[] or Uint8Array of ${length} bytes; got ${describe(value)}.`,
        );
    }
    if (value.length !== length) {
        throw new InvalidArgumentError(`${name} must be ${length} bytes; got ${value.length}.`);
    }
    const bytes = Array.from(value as ArrayLike<unknown>);
    for (let i = 0; i < bytes.length; i++) {
        const b = bytes[i];
        if (typeof b !== "number" || !Number.isInteger(b) || b < 0 || b > 255) {
            throw new InvalidArgumentError(`${name}[${i}] must be an integer in 0..255; got ${describe(b)}.`);
        }
    }
    return bytes as number[];
}

export function assertHexBytes(value: unknown, length: number, name: string): Hex {
    if (typeof value !== "string" || !new RegExp(`^0x[0-9a-fA-F]{${length * 2}}$`).test(value)) {
        throw new InvalidArgumentError(
            `${name} must be a 0x-prefixed hex string of ${length} bytes; got ${describe(value)}.`,
        );
    }
    return value as Hex;
}

/** Any even-length 0x-prefixed hex string (e.g. proof bytes). */
export function assertHex(value: unknown, name: string): Hex {
    if (typeof value !== "string" || !/^0x([0-9a-fA-F]{2})*$/.test(value)) {
        throw new InvalidArgumentError(
            `${name} must be a 0x-prefixed, even-length hex string; got ${describe(value)}.`,
        );
    }
    return value as Hex;
}

/** A value that fits in a BN254 field element (`0 <= v < p`). */
export function assertField(value: unknown, name: string): bigint {
    if (typeof value !== "bigint") {
        throw new InvalidArgumentError(`${name} must be a bigint; got ${describe(value)}.`);
    }
    if (value < 0n || value >= BN254_FIELD_MODULUS) {
        throw new InvalidArgumentError(`${name} must be in [0, BN254 field modulus); got ${value}.`);
    }
    return value;
}

/** Accepts a bigint or a 0x-prefixed hex string and returns it as a field element. */
export function toFieldElement(value: unknown, name: string): bigint {
    if (typeof value === "string") {
        if (!/^0x[0-9a-fA-F]+$/.test(value)) {
            throw new InvalidArgumentError(
                `${name} must be a bigint or a 0x-prefixed hex string; got ${describe(value)}.`,
            );
        }
        return assertField(BigInt(value), name);
    }
    return assertField(value, name);
}

export function assertNonEmptyArray(value: unknown, name: string): void {
    if (!Array.isArray(value) || value.length === 0) {
        throw new InvalidArgumentError(`${name} must be a non-empty array.`);
    }
}

export function assertInteger(value: unknown, name: string, min: number, max: number): number {
    if (typeof value !== "number" || !Number.isInteger(value) || value < min || value > max) {
        throw new InvalidArgumentError(`${name} must be an integer in ${min}..${max}; got ${describe(value)}.`);
    }
    return value;
}

function describe(value: unknown): string {
    if (typeof value === "string") return JSON.stringify(value.length > 80 ? `${value.slice(0, 80)}…` : value);
    if (typeof value === "bigint") return `${value}n`;
    if (value === null) return "null";
    if (Array.isArray(value)) return `array(length ${value.length})`;
    return typeof value;
}
