/**
 * Typed errors thrown by the SDK.
 *
 * Every error extends {@link ZKSdkError} and carries a stable, machine-readable
 * `code`, so callers can branch on `error.code` (or `instanceof`) instead of
 * parsing messages. Messages are for humans and may change between releases.
 */

/** Stable identifiers for every failure category the SDK can report. */
export type ZKSdkErrorCode =
    | "INVALID_ARGUMENT"
    | "NOT_FOUND"
    | "TREE_CAPACITY_EXCEEDED"
    | "INVALID_CIRCUIT"
    | "MISSING_PEER_DEPENDENCY"
    | "PROOF_GENERATION_FAILED"
    | "UNSUPPORTED_ENVIRONMENT"
    | "CHAIN_STATE_MISMATCH";

/** Base class of every error thrown by this SDK. */
export class ZKSdkError extends Error {
    readonly code: ZKSdkErrorCode;

    constructor(code: ZKSdkErrorCode, message: string, options?: { cause?: unknown }) {
        super(message, options);
        this.name = new.target.name;
        this.code = code;
    }
}

/** An argument has the wrong type, length, range or format. */
export class InvalidArgumentError extends ZKSdkError {
    constructor(message: string) {
        super("INVALID_ARGUMENT", message);
    }
}

/** A requested entry (signer, label, rule) is not present in the tree. */
export class NotFoundError extends ZKSdkError {
    constructor(message: string) {
        super("NOT_FOUND", message);
    }
}

/** The tree is deeper than the circuit can prove, so the root would be unprovable. */
export class TreeCapacityError extends ZKSdkError {
    constructor(message: string) {
        super("TREE_CAPACITY_EXCEEDED", message);
    }
}

/** The supplied compiled circuit is malformed or is not the expected circuit. */
export class InvalidCircuitError extends ZKSdkError {
    constructor(message: string) {
        super("INVALID_CIRCUIT", message);
    }
}

/** `@aztec/bb.js` or `@noir-lang/noir_js` is required for proving but not installed. */
export class MissingPeerDependencyError extends ZKSdkError {
    constructor(packageName: string, cause?: unknown) {
        super(
            "MISSING_PEER_DEPENDENCY",
            `Proof generation requires the optional peer dependency "${packageName}". ` +
                `Install it with: pnpm add ${packageName}`,
            { cause },
        );
    }
}

/** Witness execution or proving failed (for example an unsatisfied circuit constraint). */
export class ProofGenerationError extends ZKSdkError {
    constructor(message: string, cause?: unknown) {
        super("PROOF_GENERATION_FAILED", message, { cause });
    }
}

/** The runtime lacks a required capability (for example a secure random source). */
export class UnsupportedEnvironmentError extends ZKSdkError {
    constructor(message: string) {
        super("UNSUPPORTED_ENVIRONMENT", message);
    }
}

/** On-chain state does not match what the caller expects (wrong state root, validator not installed, …). */
export class ChainStateError extends ZKSdkError {
    constructor(message: string, cause?: unknown) {
        super("CHAIN_STATE_MISMATCH", message, { cause });
    }
}
