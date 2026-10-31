/**
 * Compiled Noir circuit artifact handling.
 */

import { InvalidCircuitError } from "../errors.js";

/**
 * A compiled Noir circuit: the JSON written by `nargo compile` to `target/<name>.json`.
 * Only the fields the SDK reads are typed; the rest of the artifact is passed through to Noir.
 */
export interface CompiledCircuit {
    /** Base64-encoded, gzip-compressed ACIR bytecode. */
    bytecode: string;
    /** Circuit ABI. Its parameter names are checked against the circuit the SDK expects. */
    abi: { parameters: ReadonlyArray<{ name: string }> } & Record<string, unknown>;
    [key: string]: unknown;
}

/**
 * Check that `circuit` is a compiled artifact whose parameters are exactly `expectedParams`.
 *
 * Catches the most common integration error (passing the wrong circuit JSON to a prover),
 * which would otherwise surface as an opaque ABI error from Noir.
 */
export function assertCircuit(
    circuit: unknown,
    circuitName: string,
    expectedParams: readonly string[],
): CompiledCircuit {
    if (typeof circuit !== "object" || circuit === null) {
        throw new InvalidCircuitError(`circuit must be the compiled ${circuitName} artifact (parsed JSON object).`);
    }

    const candidate = circuit as Partial<CompiledCircuit>;
    if (typeof candidate.bytecode !== "string" || candidate.bytecode.length === 0) {
        throw new InvalidCircuitError(
            `circuit.bytecode is missing; pass the output of "nargo compile" for ${circuitName}.`,
        );
    }
    const parameters = candidate.abi?.parameters;
    if (!Array.isArray(parameters)) {
        throw new InvalidCircuitError(
            `circuit.abi.parameters is missing; pass the output of "nargo compile" for ${circuitName}.`,
        );
    }

    const actual = parameters.map((p: { name: string }) => p.name);
    const matches = actual.length === expectedParams.length && expectedParams.every((name, i) => actual[i] === name);
    if (!matches) {
        throw new InvalidCircuitError(
            `circuit is not ${circuitName}: expected parameters [${expectedParams.join(", ")}] but found [${actual.join(", ")}].`,
        );
    }

    return circuit as CompiledCircuit;
}
