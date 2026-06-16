/**
 * TypeScript mirrors of Noir types from:
 *   lib/zk_multisig/src/lib.nr
 *   zk_multi_sig_ecdsa/src/main.nr
 *   zk_multi_sig_ecdsa_private_state_validation/src/main.nr
 *
 * ZK MultiSig proves that M-of-N ECDSA signers have signed a transaction
 * whose hash and the on-chain state root (committing to the signer set and
 * threshold) are publicly known — without revealing the signer set itself.
 */

import type { Hex, Address } from "viem";
import type { LeanIMT } from "@zk-kit/lean-imt";

// ─── Re-exports from zk-signer ───────────────────────────────────────────────

export type { PubKey, ECDSASignature } from "../zk-signer/types.js";

// ─── Constants ───────────────────────────────────────────────────────────────
// Must stay in sync with lib/zk_multisig/src/lib.nr and lib/zk_signer/src/lib.nr.

/**
 * Maximum Merkle tree depth for the signers tree.
 * Defined locally — matches SIGNERS_MAX_DEPTH in both lib/zk_multisig and lib/zk_signer.
 */
export const SIGNERS_MAX_DEPTH = 4;

/** Maximum number of signer slots in the multi-sig circuit. */
export const MAX_SIGNERS = 5;

/** Maximum allowed threshold value. Invariant: MAX_THRESHOLD <= MAX_SIGNERS. */
export const MAX_THRESHOLD = 5;

// ─── NIL sentinel ────────────────────────────────────────────────────────────

/**
 * secp256k1 generator point G (x-coordinate, big-endian bytes).
 * Used as the NIL pubkey sentinel for inactive signer slots.
 * Matches the is_nil_pubkey check in lib/zk_signer/src/lib.nr.
 */
export const SECP256K1_G_X: number[] = [
    121, 190, 102, 126, 249, 220, 187, 172,
     85, 160,  98, 149, 206, 135,  11,   7,
      2, 155, 252, 219,  45, 206,  40, 217,
     89, 242, 129,  91,  22, 248,  23, 152,
];

/**
 * secp256k1 generator point G (y-coordinate, big-endian bytes).
 */
export const SECP256K1_G_Y: number[] = [
     72,  58, 218, 119,  38, 163, 196, 101,
     93, 164, 251, 252,  14,  17,   8, 168,
    253,  23, 180,  72, 166, 133,  84,  25,
    156,  71, 208, 143, 251,  16, 212, 184,
];

/**
 * The NIL pubkey sentinel: the secp256k1 generator point G.
 *
 * Inactive signer slots in the multi-sig circuit MUST use this value.
 * The circuit skips any slot whose pubkey equals G.
 */
export const NIL_PUBKEY = { x: SECP256K1_G_X, y: SECP256K1_G_Y };

/**
 * The NIL signature sentinel: 64 zero bytes.
 * Used to pad inactive signer slots — the circuit ignores these slots entirely.
 */
export const NIL_SIGNATURE: number[] = new Array(64).fill(0);

// ─── Registry types ──────────────────────────────────────────────────────────

/** A single entry in the authorized signers set. */
export interface SignerEntry {
    /** Ethereum address of the authorized signer. */
    address: Address;
}

/** Result of buildSignersTree. */
export interface SignersTree {
    /** The underlying LeanIMT instance. */
    tree: LeanIMT;
    /** Poseidon2 Merkle root — committed on-chain as part of on_chain_state_root. */
    signersRoot: bigint;
    /** Computed leaf for each entry, in insertion order. */
    leaves: bigint[];
}

// ─── Proof types ─────────────────────────────────────────────────────────────

/** Merkle membership proof for a single signer, padded to SIGNERS_MAX_DEPTH. */
export interface SignerMerkleProof {
    /** Actual number of sibling hashes (0–4). */
    merkle_proof_length: number;
    /** Direction bits: 0 = proved leaf is the left child, 1 = right child. */
    merkle_proof_indices: number[];   // [u1; SIGNERS_MAX_DEPTH]
    /** Sibling hashes at each level; unused slots are "0x0". */
    merkle_proof_siblings: Hex[];     // [Field; SIGNERS_MAX_DEPTH]
}

// ─── Active signer (proof input) ─────────────────────────────────────────────

/**
 * An active signer providing evidence for a multi-sig proof.
 *
 * Signers MUST be provided in strictly increasing Ethereum address order
 * (enforced by the circuit to prevent the same signer from signing twice).
 */
export interface ActiveSigner {
    /** Uncompressed secp256k1 public key { x: number[32], y: number[32] }. */
    pubKey: { x: number[]; y: number[] };
    /**
     * Raw 64-byte ECDSA signature: r (bytes 0–31) || s (bytes 32–63).
     * Maps to Noir's `type Signature = [u8; 64]`.
     */
    signature: number[];
    /** Ethereum address — used to derive the Merkle membership proof. */
    address: Address;
}

// ─── Circuit I/O ─────────────────────────────────────────────────────────────

/**
 * Full input for the zk_multi_sig_ecdsa Noir circuit.
 *
 * Private inputs are the signer data and Merkle proofs.
 * Public inputs are the transaction hash (32 byte-fields) and on_chain_state_root.
 */
export interface MultiSigCircuitInput {
    // Private inputs
    signers:             { x: number[]; y: number[] }[];  // [PubKey; MAX_SIGNERS]
    threshold:           number;                           // u8
    signers_root:        Hex;                              // Field
    merkle_proof_length: number[];                         // [u32; MAX_SIGNERS]
    indices:             number[][];                       // [[u1; SIGNERS_MAX_DEPTH]; MAX_SIGNERS]
    siblings:            Hex[][];                          // [[Field; SIGNERS_MAX_DEPTH]; MAX_SIGNERS]
    signatures:          number[][];                       // [[u8; 64]; MAX_SIGNERS]
    // Public inputs
    txn_hash:            number[];                         // [u8; 32]
    on_chain_state_root: Hex;                              // Field
}

/**
 * Full input for the zk_multi_sig_ecdsa_private_state_validation Noir circuit.
 *
 * Proves that on_chain_state_root = compute_state_root(signers_root, threshold)
 * without running a full multi-sig signature verification.
 */
export interface PrivateStateValidationCircuitInput {
    // Private inputs
    signers_root:        Hex;    // Field
    threshold:           number; // u8
    // Public inputs
    on_chain_state_root: Hex;    // Field
}

// ─── Proof output ────────────────────────────────────────────────────────────

/** Output from generateMultiSigProof. */
export interface MultiSigProofData {
    proof:            Hex;
    /** All 33 raw public inputs: txn_hash bytes (32) + on_chain_state_root (1). */
    publicInputs:     Hex[];
    /** Transaction hash as a 32-byte hex string. */
    txnHash:          Hex;
    /** On-chain state root committing to (signers_root, threshold). */
    onChainStateRoot: Hex;
}

/** Output from generatePrivateStateValidationProof. */
export interface PrivateStateValidationProofData {
    proof:            Hex;
    /** Raw public inputs: [on_chain_state_root]. */
    publicInputs:     Hex[];
    /** On-chain state root committing to (signers_root, threshold). */
    onChainStateRoot: Hex;
}
