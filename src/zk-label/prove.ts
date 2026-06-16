/**
 * ZK Label proof generation using Barretenberg UltraHonk.
 *
 * NODE.JS ONLY — imports @aztec/bb.js and @noir-lang/noir_js, which are
 * not available in the browser. Install the peer dependencies before use:
 *
 *   pnpm add @aztec/bb.js @noir-lang/noir_js
 *
 * The compiled circuit artifact (JSON) must be passed in explicitly so
 * this module stays agnostic to bundler/FS conventions.
 *
 * @example
 * ```ts
 * import circuit from "../../../noir/zk_label_binding/target/zk_label_binding.json" assert { type: "json" };
 * import { buildLabelsTree } from "./tree.js";
 * import { generateLabelBindingProof } from "./prove.js";
 *
 * const tree = buildLabelsTree(labels);
 * const proofData = await generateLabelBindingProof("admin", address, tree, circuit);
 * ```
 */

import { buildLabelBindingCircuitInput } from "./circuit.js";
import { toHex, type Address, type Hex } from "viem";
import type { LabelsTree, LabelBindingProofData } from "./types.js";

// Dynamically imported peer deps — kept as type-only to avoid hard dep at build time.
type UltraHonkBackend = import("@aztec/bb.js").UltraHonkBackend;
type NoirInstance = InstanceType<typeof import("@noir-lang/noir_js").Noir>;

/**
 * Generate a ZK Label membership proof.
 *
 * @param labelName   - Label name (max 31 bytes UTF-8).
 * @param signer      - Ethereum address (signer) bound to the label.
 * @param labelsTree  - Registry tree returned by `buildLabelsTree`.
 * @param circuit     - Compiled Noir circuit artifact (parsed JSON).
 * @returns Proof bytes and public inputs, ready for on-chain submission.
 */
export async function generateLabelBindingProof(
    labelName:   string,
    signer:      Address,
    labelsTree:  LabelsTree,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    circuit:     any,
): Promise<LabelBindingProofData> {
    // Lazy-load the heavy peer deps at call time.
    const [{ UltraHonkBackend }, { Noir }] = await Promise.all([
        import("@aztec/bb.js"),
        import("@noir-lang/noir_js"),
    ]);

    const circuitInput = buildLabelBindingCircuitInput(
        labelName,
        signer,
        labelsTree.tree,
        labelsTree.registryRoot,
    );

    const { Barretenberg } = await import("@aztec/bb.js");
    const api     = await Barretenberg.new();
    const backend = new UltraHonkBackend(circuit.bytecode, api) as UltraHonkBackend;
    const noir    = new Noir(circuit) as NoirInstance;

    const { witness }      = await noir.execute(circuitInput);
    const { proof, publicInputs } = await backend.generateProof(witness);

    const registryRoot    = publicInputs[0] as Hex;
    const labelCommitment = publicInputs[1] as Hex;

    return {
        proof:           toHex(proof) as Hex,
        publicInputs:    publicInputs as Hex[],
        registryRoot,
        labelCommitment,
    };
}
