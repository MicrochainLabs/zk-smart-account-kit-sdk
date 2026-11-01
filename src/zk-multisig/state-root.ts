/**
 * The public commitment of a ZK MultiSig account and its helpers.
 *
 *     state_root = Poseidon3(signers_root, Poseidon1(threshold), salt)
 *
 * Must match `compute_state_root` in both Noir circuits. The salt is what makes the commitment hiding:
 * without it the (low-entropy) signer set and threshold could be recovered from the public root by
 * enumerating candidate addresses.
 */

import { toHex, type Hex } from "viem";
import { InvalidArgumentError, UnsupportedEnvironmentError } from "../errors.js";
import { poseidon } from "../internal/poseidon.js";
import { BN254_FIELD_MODULUS, assertField, assertInteger } from "../internal/validation.js";
import { MAX_THRESHOLD } from "./types.js";

/**
 * `state_root = Poseidon3(signers_root, Poseidon1(threshold), salt)`.
 *
 * @throws {InvalidArgumentError} if `threshold` is not an integer in `[1, 5]`, or `salt` is zero or not a field element.
 */
export function computeStateRoot(signersRoot: bigint, threshold: number | bigint, salt: bigint): bigint {
    assertField(signersRoot, "signersRoot");
    const t = typeof threshold === "bigint" ? Number(threshold) : threshold;
    assertInteger(t, "threshold", 1, MAX_THRESHOLD);
    assertSalt(salt);
    return poseidon.hash([signersRoot, poseidon.hash([BigInt(t)]), salt]);
}

/**
 * Generates a fresh random salt: 248 random bits (31 bytes) from the platform CSPRNG, never zero and
 * always below the field modulus. Works in Node.js and browsers.
 *
 * @throws {UnsupportedEnvironmentError} if no `crypto.getRandomValues` is available.
 */
export function generateSalt(): bigint {
    const webCrypto = (globalThis as { crypto?: { getRandomValues?: (bytes: Uint8Array) => Uint8Array } }).crypto;
    if (typeof webCrypto?.getRandomValues !== "function") {
        throw new UnsupportedEnvironmentError(
            "A secure random source (crypto.getRandomValues) is required to generate a salt.",
        );
    }
    for (;;) {
        const bytes = new Uint8Array(31);
        webCrypto.getRandomValues(bytes);
        const salt = BigInt(toHex(bytes));
        if (salt !== 0n) return salt;
    }
}

/**
 * Parses and validates a salt given as a `0x…` hex string, a decimal string or a bigint.
 *
 * @throws {InvalidArgumentError} if it is missing, malformed, zero, or not below the BN254 modulus.
 */
export function parseSalt(salt: string | bigint | undefined): bigint {
    if (salt === undefined || (typeof salt === "string" && salt.trim() === "")) {
        throw new InvalidArgumentError(
            "Missing private salt. Use the salt that was generated when the account was created.",
        );
    }
    let value: bigint;
    if (typeof salt === "bigint") {
        value = salt;
    } else {
        const text = salt.trim();
        if (!/^(0x[0-9a-fA-F]+|[0-9]+)$/.test(text)) {
            throw new InvalidArgumentError("Invalid salt: expected a hex (0x…) or decimal number.");
        }
        value = BigInt(text);
    }
    assertSalt(value);
    return value;
}

/** A salt as a 32-byte `0x…` string, the form it is stored and passed to the circuit in. */
export function saltToHex(salt: bigint): Hex {
    assertSalt(salt);
    return toHex(salt, { size: 32 });
}

/** A field element (such as a state root) as a 32-byte `0x…` string, the form the contracts use. */
export function fieldToBytes32(value: bigint): Hex {
    assertField(value, "value");
    return toHex(value, { size: 32 });
}

function assertSalt(salt: bigint): void {
    if (typeof salt !== "bigint" || salt <= 0n || salt >= BN254_FIELD_MODULUS) {
        throw new InvalidArgumentError("Invalid salt: must be a non-zero bigint smaller than the BN254 field modulus.");
    }
}
