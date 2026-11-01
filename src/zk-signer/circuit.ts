/**
 * Circuit input builders for the zk_signers Noir circuit.
 *
 * This module is browser-safe (no Node.js builtins, no heavy proving deps).
 * Import `./prove.js` for actual proof generation.
 */

import { secp256k1 } from "@noble/curves/secp256k1";
import { bytesToHex, toHex, type Address } from "viem";
import { publicKeyToAddress } from "viem/utils";
import { InvalidArgumentError } from "../errors.js";
import { assertPaddedProof } from "../internal/merkle.js";
import { SECP256K1_ORDER, assertAddress, assertBytes, assertField } from "../internal/validation.js";
import { getSignerMerkleProof } from "./tree.js";
import {
    ADDRESS_BYTES,
    HASH_BYTES,
    PUBKEY_BYTES,
    SIGNATURE_BYTES,
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
 * Shapes and byte lengths are validated, but the signature itself is not
 * verified here — use {@link buildZKSignerCircuitInput} for the full pre-flight.
 *
 * @param pubKey      - Uncompressed secp256k1 public key of the signer.
 * @param signature   - 64-byte ECDSA signature: r(32) || s(32), low-S, no Ethereum prefix.
 * @param merkleProof - Padded Merkle membership proof for the signer.
 * @param signersRoot - Merkle root of the authorized signers tree.
 * @param txnHash     - 32-byte transaction hash that was signed.
 * @throws {InvalidArgumentError} on any malformed argument.
 */
export function buildZKSignerCircuitInputFromProof(
    pubKey: PubKey,
    signature: number[],
    merkleProof: SignerMerkleProof,
    signersRoot: bigint,
    txnHash: number[],
): ZKSignerCircuitInput {
    const x = assertBytes(pubKey?.x, PUBKEY_BYTES, "pubKey.x");
    const y = assertBytes(pubKey?.y, PUBKEY_BYTES, "pubKey.y");
    const sig = assertBytes(signature, SIGNATURE_BYTES * 2, "signature");
    const hash = assertBytes(txnHash, HASH_BYTES, "txnHash");
    assertField(signersRoot, "signersRoot");
    assertPaddedProof(merkleProof, SIGNERS_MAX_DEPTH);

    return {
        pubkey: { x, y },
        signature: sig,
        proof_length: merkleProof.merkle_proof_length,
        proof_index: merkleProof.merkle_proof_indices,
        proof_siblings: merkleProof.merkle_proof_siblings,
        txn_hash: hash,
        signers_root: toHex(signersRoot),
    };
}

/**
 * Build the full circuit input for zk_signers from a live signers tree.
 *
 * Automatically derives the Merkle proof for `signer` from the tree and runs a
 * cheap off-circuit pre-flight, so mistakes fail here with a clear error instead
 * of as an opaque witness failure after seconds of proving work:
 *   - `pubKey` must derive to `signer`;
 *   - `signature` must be low-S and a valid ECDSA signature of `txnHash` by `signer`;
 *   - `signer` must be a member of the tree.
 *
 * @param pubKey      - Uncompressed secp256k1 public key of the signer.
 * @param signature   - 64-byte ECDSA signature: r(32) || s(32), low-S, no Ethereum prefix.
 * @param signer      - Ethereum address of the signer (used to look up the Merkle proof).
 * @param signersTree - Signers Merkle tree returned by `buildSignersTree`.
 * @param txnHash     - 32-byte transaction hash that was signed.
 * @throws {InvalidArgumentError} if the key, signature or hash is malformed or inconsistent.
 * @throws {NotFoundError} if `signer` is not in the tree.
 */
export function buildZKSignerCircuitInput(
    pubKey: PubKey,
    signature: number[],
    signer: Address,
    signersTree: SignersTree,
    txnHash: number[],
): ZKSignerCircuitInput {
    assertAddress(signer, "signer");
    const proof = getSignerMerkleProof(signersTree.tree, signer);
    const input = buildZKSignerCircuitInputFromProof(pubKey, signature, proof, signersTree.signersRoot, txnHash);

    assertSignatureMatchesSigner(input, signer);
    return input;
}

function assertSignatureMatchesSigner(input: ZKSignerCircuitInput, signer: Address): void {
    const uncompressed = bytesToHex(Uint8Array.from([0x04, ...input.pubkey.x, ...input.pubkey.y]));
    const derived = publicKeyToAddress(uncompressed);
    if (derived.toLowerCase() !== signer.toLowerCase()) {
        throw new InvalidArgumentError(
            `pubKey derives to ${derived}, not the declared signer ${signer} (an address is ${ADDRESS_BYTES} bytes of keccak256(pubKey)).`,
        );
    }

    const sValue = BigInt(bytesToHex(Uint8Array.from(input.signature.slice(SIGNATURE_BYTES))));
    if (sValue === 0n || sValue > SECP256K1_ORDER / 2n) {
        throw new InvalidArgumentError("signature must be low-S (0 < s <= n/2); normalise it before proving.");
    }

    if (!verifies(input)) {
        throw new InvalidArgumentError(
            "signature is not a valid ECDSA signature of txnHash by pubKey " +
                "(sign the raw 32-byte hash, with no Ethereum message prefix).",
        );
    }
}

function verifies(input: ZKSignerCircuitInput): boolean {
    try {
        return secp256k1.verify(
            Uint8Array.from(input.signature),
            Uint8Array.from(input.txn_hash),
            Uint8Array.from([0x04, ...input.pubkey.x, ...input.pubkey.y]),
        );
    } catch {
        // noble throws on points that are not on the curve.
        return false;
    }
}
