/**
 * Derivation, validation and persistence of a ZK MultiSig account's private configuration.
 */

import { isHex, toHex } from "viem";
import { InvalidArgumentError } from "../errors.js";
import { assertInteger } from "../internal/validation.js";
import { computeStateRoot, fieldToBytes32, generateSalt, parseSalt, saltToHex } from "./state-root.js";
import { buildMultiSigTree, sortSigners } from "./tree.js";
import { MAX_THRESHOLD, type MultiSigConfig, type MultiSigState, type SignersFormat } from "./types.js";

/** Input of {@link createMultiSigState}: like {@link MultiSigConfig}, with an optional salt. */
export type MultiSigStateInput = Omit<MultiSigConfig, "salt"> & {
    /** Salt of an existing account. Omit to generate a fresh random one. */
    salt?: bigint;
};

/**
 * Derives everything about a ZK MultiSig account from its private configuration: the signers tree, the
 * signers root and the public state root. Generates a fresh salt unless one is supplied.
 *
 * Besides validating each field, it rejects configurations that could never produce a proof
 * (`threshold > signers.length`), which would lock the account forever once the root is installed.
 *
 * @throws {InvalidArgumentError} on any invalid or unprovable configuration.
 */
export function createMultiSigState(input: MultiSigStateInput): MultiSigState {
    const signersFormat: SignersFormat = input.signersFormat ?? "address";
    const tree = buildMultiSigTree(input.signers, signersFormat);

    assertInteger(input.threshold, "threshold", 1, MAX_THRESHOLD);
    if (input.threshold > tree.leaves.length) {
        throw new InvalidArgumentError(
            `threshold (${input.threshold}) exceeds the number of signers (${tree.leaves.length}): no proof could ever be generated.`,
        );
    }

    const salt = input.salt === undefined ? generateSalt() : parseSalt(input.salt);
    return {
        signers: sortSigners(input.signers),
        threshold: input.threshold,
        salt,
        signersFormat,
        tree,
        signersRoot: tree.signersRoot,
        stateRoot: computeStateRoot(tree.signersRoot, input.threshold, salt),
    };
}

/**
 * Serialises the private configuration to JSON for backup (version 1). **The output is secret**: it
 * contains the signer list, the threshold and the salt. Store it encrypted, together with — never apart
 * from — the account's other recovery material. Losing the salt makes the account unprovable forever.
 */
export function serializeMultiSigState(state: MultiSigState): string {
    return JSON.stringify({
        version: 1,
        signers: state.signers,
        threshold: state.threshold,
        salt: saltToHex(state.salt),
        signersFormat: state.signersFormat,
        stateRoot: fieldToBytes32(state.stateRoot),
    });
}

/**
 * Restores a configuration saved by {@link serializeMultiSigState}. The state root is recomputed and,
 * if the backup carries one, must match it — so a corrupted or mismatched backup is detected at
 * restore time rather than when a proof is needed.
 *
 * @throws {InvalidArgumentError} if the JSON is malformed, has an unknown version, or the root does not match.
 */
export function parseMultiSigState(json: string): MultiSigState {
    let data: unknown;
    try {
        data = JSON.parse(json);
    } catch {
        throw new InvalidArgumentError("The backup is not valid JSON.");
    }
    if (typeof data !== "object" || data === null) {
        throw new InvalidArgumentError("The backup must be a JSON object.");
    }
    const record = data as Record<string, unknown>;
    if (record.version !== 1) {
        throw new InvalidArgumentError(`Unsupported backup version: ${String(record.version)}.`);
    }
    if (!Array.isArray(record.signers) || typeof record.threshold !== "number") {
        throw new InvalidArgumentError("The backup is missing signers or threshold.");
    }

    const state = createMultiSigState({
        signers: record.signers as string[],
        threshold: record.threshold,
        salt: parseSalt(record.salt as string | undefined),
        signersFormat: (record.signersFormat ?? "address") as SignersFormat,
    });

    if (record.stateRoot !== undefined) {
        if (!isHex(record.stateRoot) || BigInt(record.stateRoot) !== state.stateRoot) {
            throw new InvalidArgumentError(
                `The backup is inconsistent: its state root does not match the one derived from its signers, threshold and salt (${toHex(state.stateRoot)}).`,
            );
        }
    }
    return state;
}
