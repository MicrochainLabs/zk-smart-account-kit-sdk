/**
 * Shared proving pipeline: witness execution + UltraHonk proof generation.
 *
 * NODE.JS ONLY. `@aztec/bb.js` and `@noir-lang/noir_js` are optional peer
 * dependencies, loaded lazily so the browser-safe parts of the SDK never import them.
 */

import { toHex, type Hex } from "viem";
import { MissingPeerDependencyError, ProofGenerationError } from "../errors.js";
import type { CompiledCircuit } from "./compiled-circuit.js";

/** The slice of a Barretenberg instance the SDK touches (structural, so bb.js types stay optional). */
export interface BarretenbergLike {
    destroy(): Promise<void>;
}

/** Options accepted by every `generate*Proof` function. */
export interface ProveOptions {
    /**
     * An existing Barretenberg instance to reuse across proofs. Creating one is
     * expensive (WASM/worker start-up), so long-running services should create it
     * once and pass it here. When supplied, the SDK does NOT destroy it — the
     * caller owns its lifecycle. When omitted, an instance is created and
     * destroyed for each call.
     */
    barretenberg?: BarretenbergLike;
}

export interface RawProof {
    proof: Hex;
    publicInputs: Hex[];
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
 * Execute `circuit` on `input` and produce an UltraHonk proof.
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

    const ownsApi = options.barretenberg === undefined;
    const api = (options.barretenberg ?? (await bb.Barretenberg.new())) as Awaited<
        ReturnType<typeof bb.Barretenberg.new>
    >;

    try {
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

        let result: { proof: Uint8Array; publicInputs: string[] };
        try {
            const backend = new bb.UltraHonkBackend(circuit.bytecode, api);
            result = await backend.generateProof(witness);
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
