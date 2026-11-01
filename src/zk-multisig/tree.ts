/**
 * Signers Merkle tree of a ZK MultiSig account.
 *
 * Leaves are `Poseidon1(address)` and nodes are `Poseidon2`, exactly as in `zk-signer`; what differs is
 * the construction rule: the signer set is sorted (ascending numeric value), contains no duplicates and
 * has 1 to {@link MAX_SIGNERS} members, so the same set always yields the same root.
 */

import type { Address } from "viem";
import { InvalidArgumentError } from "../errors.js";
import { buildTree, generatePaddedProof, type MerkleTreeLike, type PaddedMerkleProof } from "../internal/merkle.js";
import { assertAddress, assertField } from "../internal/validation.js";
import { computeSignerLeaf, signersHash } from "../zk-signer/leaf.js";
import { SIGNERS_MAX_DEPTH } from "../zk-signer/types.js";
import { MAX_SIGNERS, type MultiSigTree, type SignersFormat } from "./types.js";

/** Numerically sorts signers (addresses or leaf hashes), matching the circuit's byte-wise address ordering. */
export function sortSigners<T extends string>(signers: readonly T[]): T[] {
    return [...signers].sort((a, b) => {
        const x = BigInt(a);
        const y = BigInt(b);
        return x < y ? -1 : x > y ? 1 : 0;
    });
}

/**
 * Builds the signers tree of a ZK MultiSig account.
 *
 * @param signers       Signer addresses (any order, any case) or, with `"poseidon-hash"`, their leaves.
 * @param signersFormat How `signers` is given. Defaults to `"address"`.
 * @throws {InvalidArgumentError} if the set is empty, larger than {@link MAX_SIGNERS}, has duplicates, or has an invalid entry.
 */
export function buildMultiSigTree(signers: readonly string[], signersFormat: SignersFormat = "address"): MultiSigTree {
    if (!Array.isArray(signers) || signers.length === 0 || signers.length > MAX_SIGNERS) {
        throw new InvalidArgumentError(`The signer set must contain between 1 and ${MAX_SIGNERS} entries.`);
    }
    if (signersFormat !== "address" && signersFormat !== "poseidon-hash") {
        throw new InvalidArgumentError('signersFormat must be "address" or "poseidon-hash".');
    }

    const values = (signers as readonly unknown[]).map((signer, i) => parseSigner(signer, signersFormat, i));
    if (new Set(values).size !== values.length) {
        throw new InvalidArgumentError("The signer set contains duplicate entries.");
    }

    const sorted = [...values].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    const leaves = sorted.map((value) => (signersFormat === "address" ? computeSignerLeaf(toAddress(value)) : value));

    const tree = buildTree(leaves, signersHash, SIGNERS_MAX_DEPTH, "Signers tree");
    return { tree, signersRoot: tree.root, leaves };
}

/**
 * Circuit-ready Merkle membership proof for `signer`, padded to the circuit depth.
 *
 * @throws {NotFoundError} if the signer is not in the tree.
 */
export function getMultiSigMerkleProof(tree: MerkleTreeLike, signer: Address): PaddedMerkleProof {
    return generatePaddedProof(
        tree,
        computeSignerLeaf(signer),
        SIGNERS_MAX_DEPTH,
        () => `Signer ${signer} is not part of the private signer set.`,
    );
}

function parseSigner(signer: unknown, format: SignersFormat, index: number): bigint {
    if (format === "address") {
        assertAddress(signer, `signers[${index}]`);
        return BigInt(signer.toLowerCase());
    }
    if (typeof signer !== "string" || !/^(0x[0-9a-fA-F]+|[0-9]+)$/.test(signer)) {
        throw new InvalidArgumentError(
            `signers[${index}] must be a 0x-hex or decimal field element (a Poseidon1 leaf).`,
        );
    }
    return assertField(BigInt(signer), `signers[${index}]`);
}

function toAddress(value: bigint): Address {
    return `0x${value.toString(16).padStart(40, "0")}`;
}
