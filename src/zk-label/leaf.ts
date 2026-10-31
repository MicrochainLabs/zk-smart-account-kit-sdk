/**
 * Leaf computation for the ZK Label registry.
 *
 * Encoding and hashing must exactly match the Noir circuit in
 * lib/zk_labels/src/lib.nr. Any divergence produces a leaf that the
 * circuit will reject.
 */

import { poseidon } from "../internal/poseidon.js";
import { toBytes, type Address } from "viem";
import { InvalidArgumentError } from "../errors.js";
import { assertAddress, assertBytes } from "../internal/validation.js";
import { LABEL_NAME_BYTES } from "./types.js";

// ─── Encoding ─────────────────────────────────────────────────────────────────

/**
 * Encode a UTF-8 label name as a padded byte array.
 *
 * Layout: label bytes occupy the FIRST positions (index 0 = most significant),
 * remaining bytes are zero. This matches `bytes_to_field<31>` in the Noir circuit.
 *
 * @throws {InvalidArgumentError} if `labelName` is not a string or its UTF-8 encoding exceeds LABEL_NAME_BYTES (31).
 */
export function labelNameToBytes(labelName: string): number[] {
    if (typeof labelName !== "string") {
        throw new InvalidArgumentError("labelName must be a string.");
    }
    const utf8 = new TextEncoder().encode(labelName);
    if (utf8.length > LABEL_NAME_BYTES) {
        throw new InvalidArgumentError(
            `Label name "${labelName}" is ${utf8.length} bytes; max is ${LABEL_NAME_BYTES}.`,
        );
    }
    const padded = new Uint8Array(LABEL_NAME_BYTES);
    padded.set(utf8, 0);
    return Array.from(padded);
}

/**
 * Convert a padded label byte array to a BN254 field element (big-endian).
 * Matches `bytes_to_field<31>` in the Noir circuit.
 */
export function labelBytesToField(bytes: number[]): bigint {
    assertBytes(bytes, LABEL_NAME_BYTES, "label bytes");
    let result = 0n;
    for (const b of bytes) result = (result << 8n) | BigInt(b);
    return result;
}

/**
 * Convert a label name directly to a field element.
 * Equivalent to labelBytesToField(labelNameToBytes(name)).
 */
export function labelNameToField(labelName: string): bigint {
    return labelBytesToField(labelNameToBytes(labelName));
}

/**
 * Encode a 20-byte Ethereum address as a BN254 field element.
 * Safe because 2^160 < BN254 field modulus.
 */
export function addressToField(signer: Address): bigint {
    assertAddress(signer, "signer");
    return BigInt(signer.toLowerCase());
}

// ─── Leaf construction ────────────────────────────────────────────────────────

/**
 * Compute the Merkle leaf for a (labelName, signer) pair.
 *
 * Construction (matches lib/zk_labels/src/lib.nr → label_leaf):
 *   label_hash   = Poseidon1([label_name_field])
 *   signer_hash  = Poseidon1([signer_field])
 *   leaf         = Poseidon2([label_hash, signer_hash])
 *
 * The double-hash prevents independent brute-forcing of either input.
 */
export function computeLabelLeaf(labelName: string, signer: Address): bigint {
    const labelField = labelNameToField(labelName);
    const signerField = addressToField(signer);
    const labelHash = poseidon.hash([labelField]);
    const signerHash = poseidon.hash([signerField]);
    return poseidon.hash([labelHash, signerHash]);
}

/**
 * The Poseidon2 hash used as the LeanIMT internal node hash.
 * Must be the same function passed to `new LeanIMT(labelsHash)`.
 */
export function labelsHash(a: bigint, b: bigint): bigint {
    return poseidon.hash([a, b]);
}

/**
 * Encode a signer address as a byte array. Used for the circuit's address_bytes input.
 */
export function addressToBytes(signer: Address): number[] {
    assertAddress(signer, "signer");
    return Array.from(toBytes(signer));
}
