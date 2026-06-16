/**
 * ZK Scope proof generation using Barretenberg UltraHonk.
 *
 * NODE.JS ONLY — requires @aztec/bb.js and @noir-lang/noir_js as peer deps.
 */

import { buildScopeCircuitInput } from "./circuit.js";
import { toHex, type Address, type Hex } from "viem";
import type { ScopeRule, ScopeTree, ScopeProofData } from "./types.js";

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
 */
export async function generateScopeProof(
    txnTarget:    Address,
    txnSelector:  Hex,
    txnValue:     bigint,
    paramValues:  bigint[],
    matchingRule: ScopeRule,
    scopeTree:    ScopeTree,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    circuit:      any,
): Promise<ScopeProofData> {
    const [{ UltraHonkBackend }, { Noir }] = await Promise.all([
        import("@aztec/bb.js"),
        import("@noir-lang/noir_js"),
    ]);

    const circuitInput = buildScopeCircuitInput(
        txnTarget,
        txnSelector,
        txnValue,
        paramValues,
        matchingRule,
        scopeTree.tree,
        scopeTree.scopeRoot,
    );

    const backend = new UltraHonkBackend(circuit.bytecode);
    const noir    = new Noir(circuit);

    const { witness }             = await noir.execute(circuitInput);
    const { proof, publicInputs } = await backend.generateProof(witness);

    return {
        proof:           toHex(proof) as Hex,
        publicInputs:    publicInputs as Hex[],
        txnTarget:       publicInputs[0] as Hex,
        txnSelector:     publicInputs[1] as Hex,
        txnValue:        publicInputs[2] as Hex,
        txnCalldataHash: publicInputs[3] as Hex,
        scopeRoot:       publicInputs[4] as Hex,
    };
}
