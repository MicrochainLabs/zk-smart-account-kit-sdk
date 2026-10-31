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
import { assertCircuit } from "../internal/compiled-circuit.js";
import { proveCircuit, type ProveOptions } from "../internal/prover.js";
import type { Address } from "viem";
import type { LabelsTree, LabelBindingProofData } from "./types.js";

/** Parameter names of the `zk_label_binding` circuit, in ABI order. */
export const ZK_LABEL_BINDING_CIRCUIT_PARAMS = [
    "address_bytes",
    "label_bytes",
    "merkle_proof_length",
    "merkle_proof_indices",
    "merkle_proof_siblings",
    "registry_root",
    "label_commitment",
] as const;

/** registry_root + label_commitment. */
const PUBLIC_INPUT_COUNT = 2;

/**
 * Generate a ZK Label membership proof.
 *
 * @param labelName   - Label name (max 31 bytes UTF-8).
 * @param signer      - Ethereum address (signer) bound to the label.
 * @param labelsTree  - Registry tree returned by `buildLabelsTree`.
 * @param circuit     - Compiled zk_label_binding artifact (parsed JSON).
 * @param options     - Optional {@link ProveOptions} (e.g. a shared Barretenberg instance).
 * @returns Proof bytes and public inputs, ready for on-chain submission.
 * @throws {InvalidArgumentError} on malformed inputs.
 * @throws {NotFoundError} if the (label, signer) pair is not in the tree.
 * @throws {InvalidCircuitError} if `circuit` is not the zk_label_binding artifact.
 * @throws {MissingPeerDependencyError} if the proving peer dependencies are not installed.
 * @throws {ProofGenerationError} if witness execution or proving fails.
 */
export async function generateLabelBindingProof(
    labelName: string,
    signer: Address,
    labelsTree: LabelsTree,
    circuit: unknown,
    options?: ProveOptions,
): Promise<LabelBindingProofData> {
    const compiled = assertCircuit(circuit, "zk_label_binding", ZK_LABEL_BINDING_CIRCUIT_PARAMS);
    const circuitInput = buildLabelBindingCircuitInput(labelName, signer, labelsTree.tree, labelsTree.registryRoot);

    const { proof, publicInputs } = await proveCircuit(
        compiled,
        circuitInput as unknown as Record<string, unknown>,
        PUBLIC_INPUT_COUNT,
        options,
    );

    return {
        proof,
        publicInputs,
        registryRoot: publicInputs[0],
        labelCommitment: publicInputs[1],
    };
}
