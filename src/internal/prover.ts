/**
 * Shared proving pipeline: witness execution + UltraHonk proof generation.
 *
 * NODE.JS ONLY. `@aztec/bb.js` and `@noir-lang/noir_js` are optional peer
 * dependencies, loaded lazily so the browser-safe parts of the SDK never import them.
 */

import { toHex, type Hex } from "viem";
import { MissingPeerDependencyError, ProofGenerationError } from "../errors.js";
import type { CompiledCircuit } from "./compiled-circuit.js";

/** Proof flavours accepted by `@aztec/bb.js`. */
export type VerifierTarget =
    | "evm"
    | "evm-no-zk"
    | "noir-recursive"
    | "noir-recursive-no-zk"
    | "noir-rollup"
    | "noir-rollup-no-zk"
    | "starknet"
    | "starknet-no-zk";

/** The slice of a Barretenberg instance the SDK touches (structural, so bb.js types stay optional). */
export interface BarretenbergLike {
    destroy(): Promise<void>;
}

/** Options accepted by every `generate*Proof` function. */
export interface ProveOptions {
    /**
     * Proof flavour. Defaults to `"evm"` (keccak transcript, zero-knowledge), which is what the
     * Solidity `HonkVerifier` contracts generated from these circuits verify. A proof generated for a
     * different target is rejected on-chain, so only change this for off-chain/recursive verification.
     */
    verifierTarget?: VerifierTarget;
    /**
     * Verify the proof locally before returning it (default `true`). Costs a fraction of proving time
     * and guarantees that a returned proof is valid for `verifierTarget`.
     */
    verify?: boolean;
    /**
     * An existing Barretenberg instance to reuse across proofs. Creating one is
     * expensive (process/WASM start-up), so long-running services should create it
     * once — with {@link createBarretenberg} — and pass it here. When supplied, the SDK
     * does NOT destroy it: the caller owns its lifecycle. When omitted, an instance is
     * created and destroyed for each call.
     */
    barretenberg?: BarretenbergLike;
}

export interface RawProof {
    proof: Hex;
    publicInputs: Hex[];
}

/**
 * Creates a Barretenberg instance that is connected and ready, to share across proofs
 * (see {@link ProveOptions.barretenberg}); destroy it with `await instance.destroy()`.
 *
 * Prefer this over `Barretenberg.new()` from `@aztec/bb.js`: the native backend connects to its
 * prover process in the background and gives up after five seconds if the event loop is blocked
 * meanwhile — which witness generation does for the larger circuits — leaving a dead instance.
 * This function completes the connection before returning.
 *
 * @param options.threads Number of prover threads (default: one per CPU core, up to 16).
 * @throws {MissingPeerDependencyError} if `@aztec/bb.js` is not installed.
 */
export async function createBarretenberg(options: { threads?: number } = {}): Promise<BarretenbergLike> {
    const bb = await loadPeer("@aztec/bb.js", () => import("@aztec/bb.js"));
    const api = await bb.Barretenberg.new(options);
    try {
        // A trivial round-trip forces the lazy connection to complete now, while the event loop is free.
        await api.grumpkinGetRandomFr({ dummy: 0 });
    } catch (error) {
        await api.destroy().catch(() => undefined);
        throw error;
    }
    return api;
}

/** Load an optional peer dependency, translating "not installed" into an actionable error. */
export async function loadPeer<T>(packageName: string, load: () => Promise<T>): Promise<T> {
    try {
        return await load();
    } catch (error) {
        const code = (error as { code?: string } | null)?.code;
        if (code === "ERR_MODULE_NOT_FOUND" || code === "MODULE_NOT_FOUND") {
            throw new MissingPeerDependencyError(packageName, error);
        }
        throw error;
    }
}

/**
 * Execute `circuit` on `input` and produce an UltraHonk proof (EVM-verifiable by default).
 *
 * @param expectedPublicInputs - number of public inputs the circuit exposes; a different count means
 *                               the artifact does not match this SDK version and the proof is rejected.
 */
export async function proveCircuit(
    circuit: CompiledCircuit,
    input: Record<string, unknown>,
    expectedPublicInputs: number,
    options: ProveOptions = {},
): Promise<RawProof> {
    const bb = await loadPeer("@aztec/bb.js", () => import("@aztec/bb.js"));
    const { Noir } = await loadPeer("@noir-lang/noir_js", () => import("@noir-lang/noir_js"));

    // Witness generation comes first: it can block the event loop for seconds on the larger circuits,
    // and a Barretenberg instance created before it would lose its connection to the prover process.
    let witness: Uint8Array;
    try {
        const noir = new Noir(circuit as unknown as ConstructorParameters<typeof Noir>[0]);
        ({ witness } = await noir.execute(input as Parameters<InstanceType<typeof Noir>["execute"]>[0]));
    } catch (error) {
        throw new ProofGenerationError(
            `Witness generation failed — the inputs do not satisfy the circuit: ${messageOf(error)}`,
            error,
        );
    }

    const ownsApi = options.barretenberg === undefined;
    const api = (options.barretenberg ?? (await createBarretenberg())) as Awaited<
        ReturnType<typeof bb.Barretenberg.new>
    >;

    try {
        const verifierTarget = options.verifierTarget ?? "evm";
        let result: { proof: Uint8Array; publicInputs: string[] };
        try {
            const backend = new bb.UltraHonkBackend(circuit.bytecode, api);
            result = await backend.generateProof(witness, { verifierTarget });
            if (options.verify !== false && !(await backend.verifyProof(result, { verifierTarget }))) {
                throw new Error("the generated proof does not verify");
            }
        } catch (error) {
            throw new ProofGenerationError(`Proof generation failed: ${messageOf(error)}`, error);
        }

        if (result.publicInputs.length !== expectedPublicInputs) {
            throw new ProofGenerationError(
                `Circuit exposed ${result.publicInputs.length} public inputs; expected ${expectedPublicInputs}. ` +
                    `The circuit artifact does not match this SDK version.`,
            );
        }

        return { proof: toHex(result.proof), publicInputs: result.publicInputs as Hex[] };
    } finally {
        if (ownsApi) await api.destroy();
    }
}

function messageOf(error: unknown): string {
    return error instanceof Error ? error.message : String(error);
}
