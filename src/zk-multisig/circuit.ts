/**
 * Circuit input builders for the ZK MultiSig Noir circuits.
 *
 * This module is browser-safe (no Node.js builtins, no heavy proving deps).
 * Import `./prove.js` for actual proof generation.
 */

import { poseidon } from "@iden3/js-crypto";
import { toHex, type Hex } from "viem";
import { getSignerMerkleProof } from "./tree.js";
import {
    SIGNERS_MAX_DEPTH,
    MAX_SIGNERS,
    NIL_PUBKEY,
    NIL_SIGNATURE,
    type ActiveSigner,
    type SignersTree,
    type MultiSigCircuitInput,
    type PrivateStateValidationCircuitInput,
} from "./types.js";

// ─── State root ──────────────────────────────────────────────────────────────

/**
 * Compute the on-chain state root committing to (signersRoot, threshold).
 *
 * Formula (matches compute_state_root in lib/zk_multisig/src/lib.nr):
 *
 *   threshold_hash = Poseidon1([threshold as Field])
 *   state_root     = binary_merkle_root(
 *                      poseidon2, signersRoot, depth=1, indices=[0], siblings=[threshold_hash]
 *                    )
 *                  = Poseidon2([signersRoot, threshold_hash])
 *
 * The binary_merkle_root at depth=1 with index_bit=0 (signersRoot is the left
 * child) simplifies to a single Poseidon2 call.
 */
export function computeOnChainStateRoot(signersRoot: bigint, threshold: number): bigint {
    const thresholdHash = poseidon.hash([BigInt(threshold)]);
    return poseidon.hash([signersRoot, thresholdHash]);
}

// ─── zk_multi_sig_ecdsa ──────────────────────────────────────────────────────

/**
 * Build the full circuit input for zk_multi_sig_ecdsa.
 *
 * @param activeSigners - Signers providing evidence, in strictly increasing
 *                        Ethereum address order (circuit-enforced).
 * @param threshold     - Minimum number of valid signatures required.
 * @param signersTree   - Signers Merkle tree from buildSignersTree.
 * @param txnHash       - 32-byte transaction hash as a byte array.
 *
 * Inactive slots (length < MAX_SIGNERS) are automatically padded with the
 * NIL_PUBKEY sentinel (secp256k1 G) and zero signatures.
 *
 * @throws if activeSigners.length > MAX_SIGNERS.
 */
export function buildMultiSigCircuitInput(
    activeSigners: ActiveSigner[],
    threshold:     number,
    signersTree:   SignersTree,
    txnHash:       number[],
): MultiSigCircuitInput {
    if (activeSigners.length > MAX_SIGNERS) {
        throw new RangeError(
            `Too many active signers: got ${activeSigners.length}, max is ${MAX_SIGNERS}.`
        );
    }

    const onChainStateRoot = computeOnChainStateRoot(signersTree.signersRoot, threshold);

    const signers:          { x: number[]; y: number[] }[] = [];
    const signatures:       number[][] = [];
    const proofLengths:     number[] = [];
    const indices:          number[][] = [];
    const siblings:         Hex[][] = [];

    for (let i = 0; i < MAX_SIGNERS; i++) {
        if (i < activeSigners.length) {
            const { pubKey, signature, address } = activeSigners[i];
            const proof = getSignerMerkleProof(signersTree.tree, address);
            signers.push(pubKey);
            signatures.push(signature);
            proofLengths.push(proof.merkle_proof_length);
            indices.push(proof.merkle_proof_indices);
            siblings.push(proof.merkle_proof_siblings);
        } else {
            signers.push(NIL_PUBKEY);
            signatures.push(NIL_SIGNATURE);
            proofLengths.push(0);
            indices.push(new Array(SIGNERS_MAX_DEPTH).fill(0));
            siblings.push(new Array(SIGNERS_MAX_DEPTH).fill("0x0") as Hex[]);
        }
    }

    return {
        signers,
        threshold,
        signers_root:        toHex(signersTree.signersRoot),
        merkle_proof_length: proofLengths,
        indices,
        siblings,
        signatures,
        txn_hash:            txnHash,
        on_chain_state_root: toHex(onChainStateRoot),
    };
}

// ─── zk_multi_sig_ecdsa_private_state_validation ────────────────────────────

/**
 * Build the full circuit input for zk_multi_sig_ecdsa_private_state_validation.
 *
 * Use this circuit to prove that an on_chain_state_root is consistent with
 * a given (signersRoot, threshold) pair — without running a full multi-sig
 * signature verification.
 *
 * @param signersRoot - The Merkle root of the private signers tree.
 * @param threshold   - The required signature threshold.
 */
export function buildPrivateStateValidationCircuitInput(
    signersRoot: bigint,
    threshold:   number,
): PrivateStateValidationCircuitInput {
    const onChainStateRoot = computeOnChainStateRoot(signersRoot, threshold);
    return {
        signers_root:        toHex(signersRoot),
        threshold,
        on_chain_state_root: toHex(onChainStateRoot),
    };
}
