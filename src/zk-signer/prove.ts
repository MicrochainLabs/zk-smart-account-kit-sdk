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
 * import circuit from "./target/zk_signers.json" assert { type: "json" };
 * import { buildSignersTree, generateZKSignerProof } from "@microchain/zk-sdk/zk-signer";
 *
 * const tree = buildSignersTree([{ signer: "0xABCD…" }]);
 * const proofData = await generateZKSignerProof(
 *   pubKey, signature, "0xABCD…", tree, txnHashBytes, circuit,
 * );
 * ```
 */

import { buildZKSignerCircuitInput } from "./circuit.js";
import { toHex, type Address, type Hex } from "viem";
import type { PubKey, SignersTree, ZKSignerProofData } from "./types.js";

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
 * @returns Proof bytes and public inputs, ready for on-chain submission.
 */
export async function generateZKSignerProof(
    pubKey:       PubKey,
    signature:    number[],
    signer:       Address,
    signersTree:  SignersTree,
    txnHash:      number[],
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    circuit:      any,
): Promise<ZKSignerProofData> {
    const [{ UltraHonkBackend }, { Noir }] = await Promise.all([
        import("@aztec/bb.js"),
        import("@noir-lang/noir_js"),
    ]);

    const circuitInput = buildZKSignerCircuitInput(
        pubKey,
        signature,
        signer,
        signersTree,
        txnHash,
    );

    const backend = new UltraHonkBackend(circuit.bytecode);
    const noir    = new Noir(circuit);

    const { witness }             = await noir.execute(circuitInput);
    const { proof, publicInputs } = await backend.generateProof(witness);

    // Public inputs layout:
    //   [0..31] — txn_hash bytes, each serialised as one BN254 field element
    //   [32]    — signers_root
    const signersRoot = publicInputs[32] as Hex;
    const txnHashHex  = toHex(new Uint8Array(txnHash)) as Hex;

    return {
        proof:        toHex(proof) as Hex,
        publicInputs: publicInputs as Hex[],
        txnHash:      txnHashHex,
        signersRoot,
    };
}
