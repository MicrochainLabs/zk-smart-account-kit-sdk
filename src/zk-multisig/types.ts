/**
 * Types and constants for the ZK MultiSig primitive (`zk_multi_sig_ecdsa` and
 * `zk_multi_sig_ecdsa_private_state_validation` in microchain-zk-signers).
 *
 * An account is controlled by a *private* set of at most 5 ECDSA signers and a *private* threshold.
 * Only a hiding commitment is public (the "state root"):
 *
 *     state_root = Poseidon3(signers_root, Poseidon1(threshold), salt)
 *
 * To authorise a transaction, `threshold` of the signers sign its hash and a ZK proof shows that
 * valid signatures from members of the committed set exist, without revealing who signed, who the
 * other members are, or the threshold.
 */

import type { Hex } from "viem";
import type { LeanIMT } from "../internal/merkle.js";

// ─── Constants (must match noir/zk_multi_sig_ecdsa/src/main.nr) ──────────────

/** Maximum number of signers (and of signatures in one proof). */
export const MAX_SIGNERS = 5;

/** Maximum threshold. */
export const MAX_THRESHOLD = 5;

/** Number of public inputs of the transaction circuit: 32 hash bytes + the state root. */
export const MULTISIG_PUBLIC_INPUTS = 33;

/**
 * The "empty slot" signature: the secp256k1 generator's `x || y`. Pairs with `NIL_PUBKEY`
 * (exported by `zk-signer`); the circuit skips slots whose public key is NIL.
 */
export const NIL_SIGNATURE: readonly number[] = [
    121, 190, 102, 126, 249, 220, 187, 172, 85, 160, 98, 149, 206, 135, 11, 7, 2, 155, 252, 219, 45, 206, 40, 217, 89,
    242, 129, 91, 22, 248, 23, 152, 72, 58, 218, 119, 38, 163, 196, 101, 93, 164, 251, 252, 14, 17, 8, 168, 253, 23,
    180, 72, 166, 133, 84, 25, 156, 71, 208, 143, 251, 16, 212, 184,
];

// ─── Private state ────────────────────────────────────────────────────────────

/**
 * How the entries of `signers` are given.
 *
 *  - `"address"`: Ethereum addresses (the default).
 *  - `"poseidon-hash"`: the leaves `Poseidon1(address)` themselves, for accounts whose signer addresses
 *    are kept off the operator's machine. Such leaves are sorted by their own numeric value, which is
 *    how the existing CLI builds the tree, so roots stay compatible.
 */
export type SignersFormat = "address" | "poseidon-hash";

/**
 * The private configuration of a ZK MultiSig account. Everything here is secret except in aggregate:
 * the public state root reveals nothing about it, but anyone holding the full configuration can
 * rebuild the account's authority structure. Losing the `salt` makes the account unprovable forever.
 */
export interface MultiSigConfig {
    /** Signer addresses (or leaf hashes, see `signersFormat`), 1 to {@link MAX_SIGNERS} entries, any order or case. */
    signers: readonly string[];
    /** Number of signatures required, `1 <= threshold <= signers.length`. */
    threshold: number;
    /** Random non-zero BN254 field element that makes the commitment hiding. Back it up with the signer list. */
    salt: bigint;
    /** Format of `signers`. Defaults to `"address"`. */
    signersFormat?: SignersFormat;
}

/** Result of `buildMultiSigTree`. */
export interface MultiSigTree {
    /** The underlying LeanIMT (Poseidon2 nodes). */
    tree: LeanIMT;
    /** Poseidon Merkle root of the signer leaves (private input of the circuit). */
    signersRoot: bigint;
    /** Signer leaves in insertion (sorted) order. */
    leaves: bigint[];
}

/** A fully derived ZK MultiSig configuration. Treat as secret: see {@link MultiSigConfig}. */
export interface MultiSigState extends Required<MultiSigConfig> {
    /** Signers in canonical (ascending numeric) order, as inserted in the tree. */
    signers: string[];
    tree: MultiSigTree;
    signersRoot: bigint;
    /** The public commitment stored on-chain. */
    stateRoot: bigint;
}

// ─── Circuit I/O ──────────────────────────────────────────────────────────────

/**
 * Input of `zk_multi_sig_ecdsa`. Names and shapes mirror the circuit ABI.
 * Private: signers, threshold, signers_root, salt, merkle_proof_length, indices, siblings, signatures.
 * Public: txn_hash (32 bytes) and on_chain_state_root.
 */
export interface MultiSigCircuitInput {
    signers: { x: number[]; y: number[] }[];
    threshold: number;
    signers_root: Hex;
    salt: Hex;
    merkle_proof_length: number[];
    indices: boolean[][];
    siblings: Hex[][];
    signatures: number[][];
    txn_hash: number[];
    on_chain_state_root: Hex;
}

/** Input of `zk_multi_sig_ecdsa_private_state_validation`. */
export interface StateValidationCircuitInput {
    signers_root: Hex;
    threshold: number;
    salt: Hex;
    on_chain_state_root: Hex;
}

/** Output of {@link generateMultiSigProof}. */
export interface MultiSigProofData {
    /** UltraHonk (EVM flavour) proof. For Safe and Nexus this is submitted as the signature. */
    proof: Hex;
    /** The 33 public inputs: `[0..31]` hash bytes (one field each), `[32]` the state root. */
    publicInputs: Hex[];
    /** The transaction hash that was authorised, 32 bytes. */
    txnHash: Hex;
    /** The state root the proof is bound to, 32 bytes. */
    stateRoot: Hex;
}

/** Output of {@link generateStateValidationProof}. */
export interface StateValidationProofData {
    /** UltraHonk (EVM flavour) proof that `stateRoot` commits to a valid configuration. */
    proof: Hex;
    /** The single public input: the state root. */
    publicInputs: Hex[];
    /** The state root, 32 bytes. */
    stateRoot: Hex;
}
