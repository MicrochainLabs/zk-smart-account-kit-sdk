/**
 * Leaf computation for the ZK Label registry.
 *
 * Encoding and hashing must exactly match the Noir circuit in
 * lib/zk_labels/src/lib.nr. Any divergence produces a leaf that the
 * circuit will reject.
 */

import { poseidon } from "@iden3/js-crypto";
import { toBytes, type Hex, type Address } from "viem";
import { LABEL_NAME_BYTES } from "./types.js";

// ─── Encoding ─────────────────────────────────────────────────────────────────

/**
 * Encode a UTF-8 label name as a padded byte array.
 *
 * Layout: label bytes occupy the FIRST positions (index 0 = most significant),
 * remaining bytes are zero. This matches `bytes_to_field<31>` in the Noir circuit.
 *
 * @throws if the UTF-8 encoding exceeds LABEL_NAME_BYTES (31).
 */
export function labelNameToBytes(labelName: string): number[] {
    const utf8 = new TextEncoder().encode(labelName);
    if (utf8.length > LABEL_NAME_BYTES) {
        throw new RangeError(
            `Label name "${labelName}" is ${utf8.length} bytes; max is ${LABEL_NAME_BYTES}.`
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
    const labelField   = labelNameToField(labelName);
    const signerField  = addressToField(signer);
    const labelHash    = poseidon.hash([labelField]);
    const signerHash   = poseidon.hash([signerField]);
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
    return Array.from(toBytes(signer as Hex));
}
