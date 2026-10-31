/**
 * ABI encoding helpers for on-chain interactions with ZK Scope validators.
 * Browser-safe.
 */

import { encodeAbiParameters, parseAbiParameters, toHex, type Hex, type Address } from "viem";
import { InvalidArgumentError } from "../errors.js";
import { assertHex, assertHexBytes, toFieldElement } from "../internal/validation.js";
import { addressToField, assertU128, selectorToField } from "./rule.js";
import type { ScopeProofData } from "./types.js";

/**
 * Encode the five public inputs for a ZK Scope proof as an ABI-encoded bytes32[].
 *
 * Order matches the circuit's public input declaration:
 *   [0] txn_target, [1] txn_selector, [2] txn_value, [3] txn_calldata_hash, [4] scope_root
 */
export function encodeScopePublicInputs(
    txnTarget: Address,
    txnSelector: Hex,
    txnValue: bigint,
    txnCalldataHash: bigint | Hex,
    scopeRoot: bigint | Hex,
): Hex {
    const calldataHash = toFieldElement(txnCalldataHash, "txnCalldataHash");
    const root = toFieldElement(scopeRoot, "scopeRoot");
    assertU128(txnValue, "txnValue");

    return encodeAbiParameters(parseAbiParameters("bytes32, bytes32, bytes32, bytes32, bytes32"), [
        toHex(addressToField(txnTarget), { size: 32 }),
        toHex(selectorToField(txnSelector), { size: 32 }),
        toHex(txnValue, { size: 32 }),
        toHex(calldataHash, { size: 32 }),
        toHex(root, { size: 32 }),
    ]);
}

/**
 * Derive and encode the public inputs from a ScopeProofData object.
 * Convenience wrapper for `encodeScopePublicInputs`.
 */
export function encodeScopeProofPublicInputs(proof: ScopeProofData): Hex {
    return encodeAbiParameters(
        parseAbiParameters("bytes32, bytes32, bytes32, bytes32, bytes32"),
        publicInputsOf(proof),
    );
}

function publicInputsOf(proof: ScopeProofData): [Hex, Hex, Hex, Hex, Hex] {
    if (!Array.isArray(proof?.publicInputs) || proof.publicInputs.length !== 5) {
        throw new InvalidArgumentError("proofData.publicInputs must contain exactly 5 entries.");
    }
    return proof.publicInputs.map((v, i) => assertHexBytes(v, 32, `proofData.publicInputs[${i}]`)) as [
        Hex,
        Hex,
        Hex,
        Hex,
        Hex,
    ];
}

/**
 * Encode the initialisation calldata for the scope validator (onInstall / scopeRoot setup).
 *
 * Layout: abi.encode(bytes32 scopeRoot)
 */
export function encodeScopeInitData(scopeRoot: bigint | Hex): Hex {
    const root = toFieldElement(scopeRoot, "scopeRoot");
    return encodeAbiParameters(parseAbiParameters("bytes32"), [toHex(root, { size: 32 })]);
}

/**
 * Encode calldata for updating the on-chain scope root.
 *
 * Layout: abi.encode(bytes32 newScopeRoot, bytes proof)
 */
export function encodeUpdateScopeRootData(newScopeRoot: bigint | Hex, proof: Hex): Hex {
    const root = toFieldElement(newScopeRoot, "newScopeRoot");
    assertHex(proof, "proof");
    return encodeAbiParameters(parseAbiParameters("bytes32, bytes"), [toHex(root, { size: 32 }), proof]);
}

/**
 * Encode full scope proof submission calldata.
 *
 * Layout: abi.encode(bytes proof, bytes publicInputs)
 */
export function encodeScopeProofCalldata(proofData: ScopeProofData): Hex {
    const encodedInputs = encodeScopeProofPublicInputs(proofData);
    return encodeAbiParameters(parseAbiParameters("bytes, bytes"), [
        assertHex(proofData.proof, "proofData.proof"),
        encodedInputs,
    ]);
}
