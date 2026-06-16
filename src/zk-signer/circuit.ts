/**
 * Circuit input builders for the zk_signers Noir circuit.
 *
 * This module is browser-safe (no Node.js builtins, no heavy proving deps).
 * Import `./prove.js` for actual proof generation.
 */

import { toHex, type Hex, type Address } from "viem";
import { getSignerMerkleProof } from "./tree.js";
import {
    SIGNERS_MAX_DEPTH,
    type PubKey,
    type SignerMerkleProof,
    type SignersTree,
    type ZKSignerCircuitInput,
} from "./types.js";

/**
 * Build the full circuit input for zk_signers from a pre-computed Merkle proof.
 *
 * Use this low-level overload when you already hold a SignerMerkleProof
 * (e.g. when building inputs in a browser without the full tree present).
 *
 * @param pubKey      - Uncompressed secp256k1 public key of the signer.
 * @param signature   - 64-byte ECDSA signature: r(32) || s(32), low-S, no Ethereum prefix.
 * @param merkleProof - Padded Merkle membership proof for the signer.
 * @param signersRoot - Merkle root of the authorized signers tree.
 * @param txnHash     - 32-byte transaction hash that was signed.
 */
export function buildZKSignerCircuitInputFromProof(
    pubKey:       PubKey,
    signature:    number[],
    merkleProof:  SignerMerkleProof,
    signersRoot:  bigint,
    txnHash:      number[],
): ZKSignerCircuitInput {
    if (signature.length !== 64) {
        throw new RangeError(`Signature must be 64 bytes (r||s); got ${signature.length}.`);
    }
    if (txnHash.length !== 32) {
        throw new RangeError(`txnHash must be 32 bytes; got ${txnHash.length}.`);
    }

    return {
        pubkey:         pubKey,
        signature,
        proof_length:   merkleProof.merkle_proof_length,
        proof_index:    merkleProof.merkle_proof_indices,
        proof_siblings: merkleProof.merkle_proof_siblings,
        txn_hash:       txnHash,
        signers_root:   toHex(signersRoot),
    };
}

/**
 * Build the full circuit input for zk_signers from a live signers tree.
 *
 * Automatically derives the Merkle proof for `signer` from the tree.
 *
 * @param pubKey      - Uncompressed secp256k1 public key of the signer.
 * @param signature   - 64-byte ECDSA signature: r(32) || s(32), low-S, no Ethereum prefix.
 * @param signer      - Ethereum address of the signer (used to look up the Merkle proof).
 * @param signersTree - Signers Merkle tree returned by `buildSignersTree`.
 * @param txnHash     - 32-byte transaction hash that was signed.
 */
export function buildZKSignerCircuitInput(
    pubKey:       PubKey,
    signature:    number[],
    signer:       Address,
    signersTree:  SignersTree,
    txnHash:      number[],
): ZKSignerCircuitInput {
    const proof = getSignerMerkleProof(signersTree.tree, signer);
    return buildZKSignerCircuitInputFromProof(pubKey, signature, proof, signersTree.signersRoot, txnHash);
}
