/**
 * ZK Signer proof generation using Barretenberg UltraHonk.
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
 * import circuit from "./target/zk_signers.json" with { type: "json" };
 * import { buildSignersTree, generateZKSignerProof } from "zk-smart-account-kit-sdk/zk-signer";
 *
 * const tree = buildSignersTree([{ signer: "0xABCD…" }]);
 * const proofData = await generateZKSignerProof(
 *   pubKey, signature, "0xABCD…", tree, txnHashBytes, circuit,
 * );
 * ```
 */

import { buildZKSignerCircuitInput } from "./circuit.js";
import { assertCircuit } from "../internal/compiled-circuit.js";
import { proveCircuit, type ProveOptions } from "../internal/prover.js";
import { bytesToHex, type Address } from "viem";
import type { PubKey, SignersTree, ZKSignerProofData } from "./types.js";

/** Parameter names of the `zk_signers` circuit, in ABI order. */
export const ZK_SIGNERS_CIRCUIT_PARAMS = [
    "pubkey",
    "signature",
    "proof_length",
    "proof_index",
    "proof_siblings",
    "txn_hash",
    "signers_root",
] as const;

/** 32 txn_hash bytes + signers_root. */
const PUBLIC_INPUT_COUNT = 33;

/**
 * Generate a ZK Signer membership proof.
 *
 * Proves in zero-knowledge that:
 *   1. The prover knows the ECDSA private key that produced `signature` over `txnHash`.
 *   2. The derived Ethereum address is a member of the `signersRoot` tree.
 *
 * Public inputs produced:
 *   publicInputs[0..31] — txn_hash bytes (each byte as one BN254 field element)
 *   publicInputs[32]    — signers_root
 *
 * @param pubKey      - Uncompressed secp256k1 public key of the signer.
 * @param signature   - 64-byte ECDSA signature: r(32) || s(32), low-S, no Ethereum prefix.
 * @param signer      - Ethereum address of the signer.
 * @param signersTree - Signers Merkle tree from `buildSignersTree`.
 * @param txnHash     - 32-byte transaction hash that was signed.
 * @param circuit     - Compiled zk_signers artifact (parsed JSON).
 * @param options     - Optional {@link ProveOptions} (e.g. a shared Barretenberg instance).
 * @returns Proof bytes and public inputs, ready for on-chain submission.
 * @throws {InvalidArgumentError} on malformed or inconsistent inputs.
 * @throws {InvalidCircuitError} if `circuit` is not the zk_signers artifact.
 * @throws {MissingPeerDependencyError} if the proving peer dependencies are not installed.
 * @throws {ProofGenerationError} if witness execution or proving fails.
 */
export async function generateZKSignerProof(
    pubKey: PubKey,
    signature: number[],
    signer: Address,
    signersTree: SignersTree,
    txnHash: number[],
    circuit: unknown,
    options?: ProveOptions,
): Promise<ZKSignerProofData> {
    const compiled = assertCircuit(circuit, "zk_signers", ZK_SIGNERS_CIRCUIT_PARAMS);
    const circuitInput = buildZKSignerCircuitInput(pubKey, signature, signer, signersTree, txnHash);

    const { proof, publicInputs } = await proveCircuit(
        compiled,
        circuitInput as unknown as Record<string, unknown>,
        PUBLIC_INPUT_COUNT,
        options,
    );

    return {
        proof,
        publicInputs,
        txnHash: bytesToHex(Uint8Array.from(circuitInput.txn_hash)),
        // Public inputs layout: [0..31] txn_hash bytes, [32] signers_root.
        signersRoot: publicInputs[32],
    };
}
