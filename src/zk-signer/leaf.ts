/**
 * Leaf computation for the ZK Signer registry.
 *
 * Encoding and hashing must exactly match the Noir circuit in
 * lib/zk_signer/src/lib.nr. Any divergence produces a leaf that the
 * circuit will reject.
 */

import { poseidon } from "@iden3/js-crypto";
import type { Address } from "viem";

// ─── Field conversion ─────────────────────────────────────────────────────────

/**
 * Encode a 20-byte Ethereum address as a BN254 field element (big-endian).
 * Matches address_to_field in lib/zk_signer/src/lib.nr.
 * Safe because 2^160 < BN254 field modulus.
 */
export function signerToField(signer: Address): bigint {
    return BigInt(signer.toLowerCase());
}

// ─── Leaf construction ────────────────────────────────────────────────────────

/**
 * Compute the Merkle leaf for a signer address.
 *
 * Construction (matches lib/zk_signer/src/lib.nr → signer_leaf):
 *   leaf = Poseidon1([address_to_field(signer)])
 */
export function computeSignerLeaf(signer: Address): bigint {
    return poseidon.hash([signerToField(signer)]);
}

/**
 * The Poseidon2 hash used as the LeanIMT internal node hash.
 * Must be the same function passed to `new LeanIMT(signersHash)`.
 */
export function signersHash(a: bigint, b: bigint): bigint {
    return poseidon.hash([a, b]);
}
