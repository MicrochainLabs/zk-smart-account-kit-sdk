/**
 * ABI encoding helpers for on-chain interactions with ZK Scope validators.
 * Browser-safe.
 */

import {
    encodeAbiParameters,
    parseAbiParameters,
    toHex,
    type Hex,
    type Address,
} from "viem";
import { addressToField, selectorToField, computeCalldataHash, padParamValues } from "./rule.js";
import type { ScopeProofData } from "./types.js";

/**
 * Encode the five public inputs for a ZK Scope proof as an ABI-encoded bytes32[].
 *
 * Order matches the circuit's public input declaration:
 *   [0] txn_target, [1] txn_selector, [2] txn_value, [3] txn_calldata_hash, [4] scope_root
 */
export function encodeScopePublicInputs(
    txnTarget:       Address,
    txnSelector:     Hex,
    txnValue:        bigint,
    txnCalldataHash: bigint | Hex,
    scopeRoot:       bigint | Hex,
): Hex {
    const calldataHash = typeof txnCalldataHash === "bigint" ? txnCalldataHash : BigInt(txnCalldataHash);
    const root         = typeof scopeRoot       === "bigint" ? scopeRoot       : BigInt(scopeRoot);

    return encodeAbiParameters(
        parseAbiParameters("bytes32, bytes32, bytes32, bytes32, bytes32"),
        [
            toHex(addressToField(txnTarget),        { size: 32 }),
            toHex(selectorToField(txnSelector),     { size: 32 }),
            toHex(txnValue,                          { size: 32 }),
            toHex(calldataHash,                     { size: 32 }),
            toHex(root,                             { size: 32 }),
        ],
    );
}

/**
 * Derive and encode the public inputs from a ScopeProofData object.
 * Convenience wrapper for `encodeScopePublicInputs`.
 */
export function encodeScopeProofPublicInputs(proof: ScopeProofData): Hex {
    return encodeAbiParameters(
        parseAbiParameters("bytes32, bytes32, bytes32, bytes32, bytes32"),
        proof.publicInputs.slice(0, 5) as [Hex, Hex, Hex, Hex, Hex],
    );
}

/**
 * Encode the initialisation calldata for the scope validator (onInstall / scopeRoot setup).
 *
 * Layout: abi.encode(bytes32 scopeRoot)
 */
export function encodeScopeInitData(scopeRoot: bigint | Hex): Hex {
    const root = typeof scopeRoot === "bigint" ? scopeRoot : BigInt(scopeRoot);
    return encodeAbiParameters(
        parseAbiParameters("bytes32"),
        [toHex(root, { size: 32 })],
    );
}

/**
 * Encode calldata for updating the on-chain scope root.
 *
 * Layout: abi.encode(bytes32 newScopeRoot, bytes proof)
 */
export function encodeUpdateScopeRootData(newScopeRoot: bigint | Hex, proof: Hex): Hex {
    const root = typeof newScopeRoot === "bigint" ? newScopeRoot : BigInt(newScopeRoot);
    return encodeAbiParameters(
        parseAbiParameters("bytes32, bytes"),
        [toHex(root, { size: 32 }), proof],
    );
}

/**
 * Encode full scope proof submission calldata.
 *
 * Layout: abi.encode(bytes proof, bytes publicInputs)
 */
export function encodeScopeProofCalldata(proofData: ScopeProofData): Hex {
    const encodedInputs = encodeAbiParameters(
        parseAbiParameters("bytes32, bytes32, bytes32, bytes32, bytes32"),
        proofData.publicInputs.slice(0, 5) as [Hex, Hex, Hex, Hex, Hex],
    );
    return encodeAbiParameters(
        parseAbiParameters("bytes, bytes"),
        [proofData.proof, encodedInputs],
    );
}
