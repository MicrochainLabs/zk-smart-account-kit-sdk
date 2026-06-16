/**
 * TypeScript mirrors of Noir types from lib/zk_signer/src/lib.nr.
 *
 * ZK Signer proves ECDSA signature ownership without revealing the private key.
 * The signer's address is encoded as a field element and committed as a leaf in
 * a Merkle tree — or used standalone as a nullifier / identity commitment.
 *
 * Noir source:
 *   lib/zk_signer/src/lib.nr
 *   zk_multi_sig_ecdsa/src/main.nr
 */

import type { Hex, Address } from "viem";
import type { LeanIMT } from "@zk-kit/lean-imt";

// ─── Constants ─────────────────────────────────────────────────────────────────

/** Maximum Merkle tree depth for the signers tree. Matches SIGNERS_MAX_DEPTH in lib/zk_signer/src/lib.nr. */
export const SIGNERS_MAX_DEPTH = 4;

/** Byte length of an ECDSA public key component (x or y coordinate). */
export const PUBKEY_BYTES = 32;

/** Byte length of an ECDSA signature component (r or s). */
export const SIGNATURE_BYTES = 32;

/** Byte length of a keccak256 hash (used for the signed message hash). */
export const HASH_BYTES = 32;

/** Byte length of an Ethereum address (20 bytes). */
export const ADDRESS_BYTES = 20;

/**
 * The secp256k1 generator point G, used as the "empty slot" sentinel in
 * multi-signer arrays. Matches is_nil_pubkey in lib/zk_signer/src/lib.nr.
 */
export const NIL_PUBKEY: PubKey = {
    x: [121,190,102,126,249,220,187,172, 85,160, 98,149,206,135, 11,  7,
          2,155,252,219, 45,206, 40,217, 89,242,129, 91, 22,248, 23,152],
    y: [ 72, 58,218,119, 38,163,196,101, 93,164,251,252, 14, 17,  8,168,
        253, 23,180, 72,166,133, 84, 25,156, 71,208,143,251, 16,212,184],
};

// ─── Registry types ───────────────────────────────────────────────────────────

/** A single entry in the signers registry. */
export interface SignerEntry {
    /** Ethereum address of the signer. */
    signer: Address;
}

/** Result of buildSignersTree. */
export interface SignersTree {
    /** The underlying LeanIMT instance. */
    tree: LeanIMT;
    /** Poseidon Merkle root — stored on-chain in the validator. */
    signersRoot: bigint;
    /** Computed leaf for each entry, in insertion order. */
    leaves: bigint[];
}

/** Merkle membership proof, padded to SIGNERS_MAX_DEPTH. */
export interface SignerMerkleProof {
    /** Actual number of sibling hashes (0–4). */
    merkle_proof_length: number;
    /** Direction bits: 0 = proved leaf is the left child, 1 = right child. */
    merkle_proof_indices: number[];
    /** Sibling hashes at each level; unused slots are "0x0". */
    merkle_proof_siblings: Hex[];
}

// ─── Noir-mirrored types ───────────────────────────────────────────────────────

/**
 * Uncompressed ECDSA public key.
 * Maps to `struct PubKey { x: [u8; 32], y: [u8; 32] }` in Noir.
 */
export interface PubKey {
    x: number[];  // 32 bytes, big-endian
    y: number[];  // 32 bytes, big-endian
}

/**
 * ECDSA signature (without recovery bit — the circuit derives v from parity).
 * Maps to `struct Signature { r: [u8; 32], s: [u8; 32] }` in Noir.
 */
export interface ECDSASignature {
    r: number[];  // 32 bytes, big-endian
    s: number[];  // 32 bytes, big-endian
}

/**
 * Message hash input for the ECDSA circuit.
 * Typically `keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", payload))`.
 */
export type MessageHash = number[];  // [u8; 32]

// ─── Circuit I/O ───────────────────────────────────────────────────────────────

/**
 * Circuit input for the zk_signers Noir circuit.
 *
 * zk_signers proves in zero-knowledge that the prover knows an ECDSA private
 * key that:
 *   1. Produced `signature` over `txn_hash`
 *   2. Derives to an Ethereum address that is a member of the `signers_root` tree
 *
 * Public inputs: txn_hash[0..31] (32 byte-fields, indices 0–31) + signers_root (index 32).
 */
export interface ZKSignerCircuitInput {
    // Private inputs
    pubkey:         { x: number[]; y: number[] };  // PubKey — secp256k1 uncompressed key
    signature:      number[];    // Signature = [u8; 64] — r(32) || s(32), low-S, no Ethereum prefix
    proof_length:   number;      // u32 — actual Merkle path depth (0 for a single-signer tree)
    proof_index:    number[];    // [u1; SIGNERS_MAX_DEPTH] — direction bits (0 = left, 1 = right)
    proof_siblings: Hex[];       // [Field; SIGNERS_MAX_DEPTH] — sibling hashes; unused slots = "0x0"
    // Public inputs
    txn_hash:     number[];  // Hash = [u8; 32] — transaction hash that was signed
    signers_root: Hex;       // Field — Merkle root of authorized signers stored on-chain
}

/**
 * Output from a ZK Signer proof (zk_signers circuit).
 */
export interface ZKSignerProofData {
    proof:        Hex;
    /**
     * 33 raw public inputs:
     *   publicInputs[0..31] — txn_hash bytes (each byte serialised as one BN254 field element)
     *   publicInputs[32]    — signers_root
     */
    publicInputs: Hex[];
    /** Transaction hash as a 32-byte hex string. */
    txnHash:      Hex;
    /** Signers Merkle root. */
    signersRoot:  Hex;
}

// ─── Encoding helpers (types only — implementations in separate file if needed) ─

/**
 * Parse a compressed 65-byte public key (0x04 || x || y) into PubKey.
 * Throws if the prefix is not 0x04 (uncompressed required).
 */
export function parsePubKey(bytes: Uint8Array | number[]): PubKey {
    const buf = Array.from(bytes);
    if (buf[0] !== 0x04 || buf.length !== 65) {
        throw new Error("Expected uncompressed public key: 0x04 || x(32) || y(32)");
    }
    return {
        x: buf.slice(1, 33),
        y: buf.slice(33, 65),
    };
}

/**
 * Parse a 64-byte raw signature (r || s) into ECDSASignature.
 */
export function parseSignature(bytes: Uint8Array | number[]): ECDSASignature {
    const buf = Array.from(bytes);
    if (buf.length < 64) {
        throw new Error(`Signature too short: got ${buf.length} bytes, expected >= 64`);
    }
    return {
        r: buf.slice(0, 32),
        s: buf.slice(32, 64),
    };
}
