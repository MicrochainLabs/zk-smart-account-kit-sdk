import type { Hex, Address } from "viem";
import type { LeanIMT } from "@zk-kit/lean-imt";

// ─── Constants ─────────────────────────────────────────────────────────────────
// Must stay in sync with lib/zk_labels/src/lib.nr in the Noir workspace.

/** Maximum Merkle tree depth. Matches LABELS_MAX_DEPTH in the Noir circuit. */
export const LABELS_MAX_DEPTH = 4;

/** Maximum label name length in bytes. Matches LABEL_NAME_BYTES in the Noir circuit. */
export const LABEL_NAME_BYTES = 31;

// ─── Registry types ────────────────────────────────────────────────────────────

/** A single entry in the label registry. */
export interface LabelEntry {
    /** UTF-8 label name, max 31 bytes (role, permission, group, tag, …). */
    labelName: string;
    /** Ethereum address bound to this label. */
    signer: Address;
}

/** Result of buildLabelsTree. */
export interface LabelsTree {
    /** The underlying LeanIMT instance. */
    tree: LeanIMT;
    /** Poseidon2 Merkle root — stored on-chain in the validator. */
    registryRoot: bigint;
    /** Computed leaf for each entry, in insertion order. */
    leaves: bigint[];
}

// ─── Proof types ───────────────────────────────────────────────────────────────

/** Merkle membership proof, padded to LABELS_MAX_DEPTH. */
export interface LabelMerkleProof {
    /** Actual number of sibling hashes (0–4). */
    merkle_proof_length: number;
    /** Direction bits: 0 = proved leaf is the left child, 1 = right child. */
    merkle_proof_indices: number[];
    /** Sibling hashes at each level; unused slots are "0x0". */
    merkle_proof_siblings: Hex[];
}

// ─── Circuit I/O ───────────────────────────────────────────────────────────────

/** Full input for the zk_label_binding Noir circuit. */
export interface LabelBindingCircuitInput {
    // Private inputs
    address_bytes:          number[];   // [u8; 20]
    label_bytes:            number[];   // [u8; 31]
    merkle_proof_length:    number;
    merkle_proof_indices:   number[];   // [u1; LABELS_MAX_DEPTH]
    merkle_proof_siblings:  Hex[];      // [Field; LABELS_MAX_DEPTH]
    // Public inputs
    registry_root:          Hex;        // Merkle root
    label_commitment:       Hex;        // Poseidon2(label_hash, address_hash)
}

/** Output from generateLabelBindingProof. */
export interface LabelBindingProofData {
    proof:          Hex;
    publicInputs:   Hex[];   // [registry_root, label_commitment]
    registryRoot:   Hex;
    labelCommitment: Hex;
}
