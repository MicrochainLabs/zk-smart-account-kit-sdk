/**
 * ZK MultiSig proof generation using Barretenberg UltraHonk.
 *
 * NODE.JS ONLY — imports @aztec/bb.js and @noir-lang/noir_js, which are
 * not available in the browser. Install the peer dependencies before use:
 *
 *   pnpm add @aztec/bb.js @noir-lang/noir_js
 *
 * The compiled circuit artifacts (JSON) must be passed in explicitly so
 * this module stays agnostic to bundler/FS conventions.
 *
 * @example
 * ```ts
 * import multiSigCircuit from "...zk_multi_sig_ecdsa.json" assert { type: "json" };
 * import { buildSignersTree, generateMultiSigProof } from "@microchain/zk-sdk/zk-multisig";
 *
 * const tree = buildSignersTree([{ address: "0xABCD…" }, { address: "0x1234…" }]);
 *
 * const proofData = await generateMultiSigProof(
 *   [
 *     { pubKey, signature, address: "0xABCD…" },
 *     { pubKey: pubKey2, signature: sig2, address: "0x1234…" },
 *   ],
 *   2,      // threshold
 *   tree,
 *   txnHashBytes,
 *   multiSigCircuit,
 * );
 * ```
 */

import { buildMultiSigCircuitInput, buildPrivateStateValidationCircuitInput } from "./circuit.js";
import { toHex, type Hex } from "viem";
import type {
    ActiveSigner,
    SignersTree,
    MultiSigProofData,
    PrivateStateValidationProofData,
} from "./types.js";

// ─── zk_multi_sig_ecdsa ──────────────────────────────────────────────────────

/**
 * Generate a ZK MultiSig proof attesting that M-of-N signers have signed
 * the given transaction hash and that the on_chain_state_root commits to
 * the private signer set.
 *
 * Public inputs produced: txn_hash[0..31] (32 byte-fields) + on_chain_state_root.
 *
 * @param activeSigners - Active signers in strictly increasing address order.
 * @param threshold     - Number of signatures required (M in M-of-N).
 * @param signersTree   - Signers Merkle tree from buildSignersTree.
 * @param txnHash       - 32-byte transaction hash as a byte array.
 * @param circuit       - Compiled zk_multi_sig_ecdsa artifact (parsed JSON).
 */
export async function generateMultiSigProof(
    activeSigners: ActiveSigner[],
    threshold:     number,
    signersTree:   SignersTree,
    txnHash:       number[],
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    circuit:       any,
): Promise<MultiSigProofData> {
    const [{ UltraHonkBackend }, { Noir }] = await Promise.all([
        import("@aztec/bb.js"),
        import("@noir-lang/noir_js"),
    ]);

    const circuitInput = buildMultiSigCircuitInput(
        activeSigners,
        threshold,
        signersTree,
        txnHash,
    );

    const backend = new UltraHonkBackend(circuit.bytecode);
    const noir    = new Noir(circuit);

    const { witness }             = await noir.execute(circuitInput);
    const { proof, publicInputs } = await backend.generateProof(witness);

    // Public inputs layout:
    //   [0..31] — txn_hash bytes, each serialised as one BN254 field element
    //   [32]    — on_chain_state_root
    const onChainStateRoot = publicInputs[32] as Hex;
    const txnHashHex       = toHex(new Uint8Array(txnHash)) as Hex;

    return {
        proof:            toHex(proof) as Hex,
        publicInputs:     publicInputs as Hex[],
        txnHash:          txnHashHex,
        onChainStateRoot,
    };
}

// ─── zk_multi_sig_ecdsa_private_state_validation ────────────────────────────

/**
 * Generate a private state validation proof attesting that the on-chain
 * state root is the correct Poseidon commitment of (signersRoot, threshold).
 *
 * This is a lighter circuit that does not verify any ECDSA signatures —
 * useful for state root migration or initial deployment flows.
 *
 * Public inputs produced: on_chain_state_root (1 field element).
 *
 * @param signersRoot - The Merkle root of the private signers tree.
 * @param threshold   - The required signature threshold.
 * @param circuit     - Compiled zk_multi_sig_ecdsa_private_state_validation artifact (parsed JSON).
 */
export async function generatePrivateStateValidationProof(
    signersRoot: bigint,
    threshold:   number,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    circuit:     any,
): Promise<PrivateStateValidationProofData> {
    const [{ UltraHonkBackend }, { Noir }] = await Promise.all([
        import("@aztec/bb.js"),
        import("@noir-lang/noir_js"),
    ]);

    const circuitInput = buildPrivateStateValidationCircuitInput(signersRoot, threshold);

    const backend = new UltraHonkBackend(circuit.bytecode);
    const noir    = new Noir(circuit);

    const { witness }             = await noir.execute(circuitInput);
    const { proof, publicInputs } = await backend.generateProof(witness);

    // Public inputs layout: [0] — on_chain_state_root
    const onChainStateRoot = publicInputs[0] as Hex;

    return {
        proof:            toHex(proof) as Hex,
        publicInputs:     publicInputs as Hex[],
        onChainStateRoot,
    };
}
