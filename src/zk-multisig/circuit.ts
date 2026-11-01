/**
 * Circuit input builders for `zk_multi_sig_ecdsa` and `zk_multi_sig_ecdsa_private_state_validation`.
 *
 * Browser-safe (no Node.js builtins, no proving deps). Import `./prove.js` for proof generation.
 */

import { secp256k1 } from "@noble/curves/secp256k1";
import { bytesToHex, hexToBytes, toHex, type Address, type Hex } from "viem";
import { publicKeyToAddress } from "viem/utils";
import { ChainStateError, InvalidArgumentError } from "../errors.js";
import { SECP256K1_ORDER, assertBytes, assertHexBytes, toFieldElement } from "../internal/validation.js";
import { NIL_PUBKEY, SIGNERS_MAX_DEPTH, type PubKey } from "../zk-signer/types.js";
import { computeStateRoot } from "./state-root.js";
import { createMultiSigState } from "./state.js";
import { getMultiSigMerkleProof } from "./tree.js";
import {
    MAX_SIGNERS,
    NIL_SIGNATURE,
    type MultiSigCircuitInput,
    type MultiSigConfig,
    type StateValidationCircuitInput,
} from "./types.js";

/** A signature with the signer it recovers to. */
export interface RecoveredSigner {
    address: Address;
    pubKey: PubKey;
    /** `r || s`, 64 bytes, as the circuit expects. */
    signature: number[];
}

/** A 32-byte transaction hash as a `0x…` string, `Uint8Array` or `number[]`. */
export type HashInput = Hex | Uint8Array | readonly number[];

/** Normalises a 32-byte hash to `number[]`. @throws {InvalidArgumentError} if it is not exactly 32 bytes. */
export function normalizeHash(hash: HashInput, name = "txnHash"): number[] {
    if (typeof hash === "string") {
        return Array.from(hexToBytes(assertHexBytes(hash, 32, name)));
    }
    return assertBytes(hash, 32, name);
}

/**
 * Recovers the signer of a 65-byte `r || s || v` signature over the raw 32-byte `hash` (no Ethereum
 * message prefix — sign with `account.sign({ hash })` or EIP-712 `signTypedData`, whose digest is the hash).
 *
 * @param signature 65-byte hex signature with `v` in `{0, 1, 27, 28}`. Must be low-S, as produced by
 *                  Ethereum wallets and `viem`.
 * @throws {InvalidArgumentError} if the signature is malformed, high-S, or does not recover to a public key.
 */
export function recoverMultiSigSigner(hash: HashInput, signature: Hex): RecoveredSigner {
    const digest = Uint8Array.from(normalizeHash(hash));
    const bytes = hexToBytes(assertHexBytes(signature, 65, "signature"));

    const v = bytes[64];
    if (v !== 0 && v !== 1 && v !== 27 && v !== 28) {
        throw new InvalidArgumentError(`signature recovery byte v must be 0, 1, 27 or 28; got ${v}.`);
    }
    const r = BigInt(bytesToHex(bytes.subarray(0, 32)));
    const s = BigInt(bytesToHex(bytes.subarray(32, 64)));
    if (r === 0n || r >= SECP256K1_ORDER) {
        throw new InvalidArgumentError("signature r is out of range.");
    }
    if (s === 0n || s > SECP256K1_ORDER / 2n) {
        throw new InvalidArgumentError("signature must be low-S (0 < s <= n/2); normalise it before proving.");
    }

    let point: Uint8Array;
    try {
        point = new secp256k1.Signature(r, s)
            .addRecoveryBit(v >= 27 ? v - 27 : v)
            .recoverPublicKey(digest)
            .toRawBytes(false);
    } catch {
        throw new InvalidArgumentError("signature does not recover to a valid public key for this hash.");
    }

    return {
        address: publicKeyToAddress(bytesToHex(point)),
        pubKey: { x: Array.from(point.subarray(1, 33)), y: Array.from(point.subarray(33, 65)) },
        signature: Array.from(bytes.subarray(0, 64)),
    };
}

/**
 * Builds the input of `zk_multi_sig_ecdsa` from the private configuration and the collected signatures.
 *
 * Signatures are recovered, ordered by signer address (the circuit requires strictly increasing
 * addresses), matched against the private signer set with Merkle proofs, and padded with NIL slots.
 * Mistakes fail here with a precise message instead of as an opaque witness failure:
 *
 *  - fewer signatures than `threshold`, or more than 5;
 *  - the same signer twice, or a signer outside the private set;
 *  - a state root that does not match `onChainStateRoot` (wrong signers, threshold or salt).
 *
 * This pre-flight is a convenience, not a security control: the circuit is the authority.
 *
 * @param config           The account's private configuration.
 * @param txnHash          The 32-byte hash that was signed (a Safe transaction hash or a UserOperation hash).
 * @param signatures       65-byte signatures over `txnHash`, at least `threshold` of them, in any order.
 * @param onChainStateRoot The state root currently stored on-chain; checked against the derived one when given.
 * @throws {InvalidArgumentError} on malformed or insufficient signatures, or an unprovable configuration.
 * @throws {NotFoundError} if a signature recovers to an address outside the private set.
 * @throws {ChainStateError} if the derived state root differs from `onChainStateRoot`.
 */
export function buildMultiSigCircuitInput(
    config: MultiSigConfig,
    txnHash: HashInput,
    signatures: readonly Hex[],
    onChainStateRoot?: bigint | Hex,
): MultiSigCircuitInput {
    const state = createMultiSigState(config);
    const hash = normalizeHash(txnHash);

    if (!Array.isArray(signatures) || signatures.length === 0) {
        throw new InvalidArgumentError("At least one signature is required.");
    }
    if (signatures.length > MAX_SIGNERS) {
        throw new InvalidArgumentError(
            `At most ${MAX_SIGNERS} signatures can be proven at once; got ${signatures.length}.`,
        );
    }
    if (signatures.length < state.threshold) {
        throw new InvalidArgumentError(
            `${signatures.length} signature(s) supplied but the threshold is ${state.threshold}.`,
        );
    }

    if (onChainStateRoot !== undefined) {
        const expected = toFieldElement(onChainStateRoot, "onChainStateRoot");
        if (expected !== state.stateRoot) {
            throw new ChainStateError(
                "The state root derived from the private signers, threshold and salt does not match the on-chain " +
                    "commitment. Use exactly the values the account was created with.",
            );
        }
    }

    const recovered = (signatures as readonly Hex[])
        .map((signature: Hex) => recoverMultiSigSigner(hash, signature))
        .sort((a, b) => {
            const x = BigInt(a.address.toLowerCase());
            const y = BigInt(b.address.toLowerCase());
            return x < y ? -1 : x > y ? 1 : 0;
        });
    for (let i = 1; i < recovered.length; i++) {
        if (recovered[i].address.toLowerCase() === recovered[i - 1].address.toLowerCase()) {
            throw new InvalidArgumentError(
                `Signer ${recovered[i].address} signed more than once; each signer counts once.`,
            );
        }
    }

    const proofs = recovered.map(({ address }) => getMultiSigMerkleProof(state.tree.tree, address));
    const emptyIndices = new Array<boolean>(SIGNERS_MAX_DEPTH).fill(false);
    const emptySiblings = new Array<Hex>(SIGNERS_MAX_DEPTH).fill("0x0");
    const pad = <T>(items: T[], fill: T): T[] =>
        Array.from({ length: MAX_SIGNERS }, (_, i) => (i < items.length ? items[i] : fill));

    return {
        signers: pad(
            recovered.map((r) => r.pubKey),
            NIL_PUBKEY,
        ),
        threshold: state.threshold,
        signers_root: toHex(state.signersRoot),
        salt: toHex(state.salt),
        merkle_proof_length: pad(
            proofs.map((p) => p.merkle_proof_length),
            0,
        ),
        indices: pad(
            proofs.map((p) => p.merkle_proof_indices),
            emptyIndices,
        ),
        siblings: pad(
            proofs.map((p) => p.merkle_proof_siblings),
            emptySiblings,
        ),
        signatures: pad(
            recovered.map((r) => r.signature),
            [...NIL_SIGNATURE],
        ),
        txn_hash: hash,
        on_chain_state_root: toHex(state.stateRoot),
    };
}

/**
 * Builds the input of `zk_multi_sig_ecdsa_private_state_validation`, which proves that a state root
 * commits to a valid configuration. Required when creating an account or changing its state root.
 *
 * @throws {InvalidArgumentError} on an invalid or unprovable configuration.
 */
export function buildStateValidationCircuitInput(config: MultiSigConfig): StateValidationCircuitInput {
    const state = createMultiSigState(config);
    return {
        signers_root: toHex(state.signersRoot),
        threshold: state.threshold,
        salt: toHex(state.salt),
        on_chain_state_root: toHex(computeStateRoot(state.signersRoot, state.threshold, state.salt)),
    };
}
