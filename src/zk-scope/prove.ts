/**
 * ZK Scope proof generation using Barretenberg UltraHonk.
 *
 * NODE.JS ONLY — requires @aztec/bb.js and @noir-lang/noir_js as peer deps.
 */

import { buildScopeCircuitInput } from "./circuit.js";
import { assertCircuit } from "../internal/compiled-circuit.js";
import { proveCircuit, type ProveOptions } from "../internal/prover.js";
import type { Address, Hex } from "viem";
import type { ScopeRule, ScopeTree, ScopeProofData } from "./types.js";

/** Parameter names of the `zk_scope_validation` circuit, in ABI order. */
export const ZK_SCOPE_VALIDATION_CIRCUIT_PARAMS = [
    "rule_target",
    "rule_selector",
    "rule_value_max",
    "rule_constraints",
    "param_values",
    "proof_length",
    "proof_indices",
    "proof_siblings",
    "txn_target",
    "txn_selector",
    "txn_value",
    "txn_calldata_hash",
    "scope_root",
] as const;

/** txn_target, txn_selector, txn_value, txn_calldata_hash, scope_root. */
const PUBLIC_INPUT_COUNT = 5;

/**
 * Generate a ZK Scope proof attesting that the given transaction is within
 * the private policy committed as scopeRoot.
 *
 * @param txnTarget    - Target contract address.
 * @param txnSelector  - 4-byte function selector (e.g. "0xd0e30db0").
 * @param txnValue     - ETH value in wei.
 * @param paramValues  - Decoded calldata parameter values (zero-padded to MAX_PARAMS).
 * @param matchingRule - The scope rule that permits this transaction (private).
 * @param scopeTree    - Scope tree returned by buildScopeTree.
 * @param circuit      - Compiled zk_scope_validation artifact (parsed JSON).
 * @param options      - Optional {@link ProveOptions} (e.g. a shared Barretenberg instance).
 * @throws {InvalidArgumentError} if inputs are malformed or the transaction violates `matchingRule`.
 * @throws {NotFoundError} if `matchingRule` is not in the tree.
 * @throws {InvalidCircuitError} if `circuit` is not the zk_scope_validation artifact.
 * @throws {MissingPeerDependencyError} if the proving peer dependencies are not installed.
 * @throws {ProofGenerationError} if witness execution or proving fails.
 */
export async function generateScopeProof(
    txnTarget: Address,
    txnSelector: Hex,
    txnValue: bigint,
    paramValues: bigint[],
    matchingRule: ScopeRule,
    scopeTree: ScopeTree,
    circuit: unknown,
    options?: ProveOptions,
): Promise<ScopeProofData> {
    const compiled = assertCircuit(circuit, "zk_scope_validation", ZK_SCOPE_VALIDATION_CIRCUIT_PARAMS);
    const circuitInput = buildScopeCircuitInput(
        txnTarget,
        txnSelector,
        txnValue,
        paramValues,
        matchingRule,
        scopeTree.tree,
        scopeTree.scopeRoot,
    );

    const { proof, publicInputs } = await proveCircuit(
        compiled,
        circuitInput as unknown as Record<string, unknown>,
        PUBLIC_INPUT_COUNT,
        options,
    );

    return {
        proof,
        publicInputs,
        txnTarget: publicInputs[0],
        txnSelector: publicInputs[1],
        txnValue: publicInputs[2],
        txnCalldataHash: publicInputs[3],
        scopeRoot: publicInputs[4],
    };
}
