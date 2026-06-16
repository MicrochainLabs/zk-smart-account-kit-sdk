/**
 * Minimal ambient type stubs for optional peer dependencies.
 *
 * These packages are NOT installed at build time. They are provided at
 * runtime by consumers of the SDK who need proof generation.
 *
 * Required peer deps (proof generation only):
 *   @aztec/bb.js          >=0.63.0
 *   @noir-lang/noir_js    >=1.0.0
 */

/* eslint-disable @typescript-eslint/no-explicit-any */

declare module "@aztec/bb.js" {
    export class Barretenberg {
        static new(): Promise<Barretenberg>;
    }

    export class UltraHonkBackend {
        constructor(bytecode: string, api?: Barretenberg);
        generateProof(
            witness: Uint8Array,
        ): Promise<{ proof: Uint8Array; publicInputs: string[] }>;
        verifyProof(proof: { proof: Uint8Array; publicInputs: string[] }): Promise<boolean>;
        destroy(): Promise<void>;
    }
}

declare module "@noir-lang/noir_js" {
    export class Noir {
        constructor(circuit: any);
        execute(
            inputs: Record<string, any>,
        ): Promise<{ witness: Uint8Array; returnValue: any }>;
    }
}
