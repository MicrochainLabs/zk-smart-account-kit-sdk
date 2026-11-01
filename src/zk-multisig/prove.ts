/**
 * Proof generation for the ZK MultiSig circuits using Barretenberg UltraHonk.
 *
 * NODE.JS ONLY — loads `@aztec/bb.js` and `@noir-lang/noir_js`, optional peer dependencies:
 *
 *   pnpm add @aztec/bb.js @noir-lang/noir_js
 *
 * The compiled circuits (`zk_multi_sig_ecdsa.json`, `zk_multi_sig_ecdsa_private_state_validation.json`)
 * are passed in explicitly so this module stays agnostic to bundler and filesystem conventions.
 * Proofs are EVM-verifiable by default; see {@link ProveOptions}.
 */

import { bytesToHex, type Hex } from "viem";
import { assertCircuit } from "../internal/compiled-circuit.js";
import { proveCircuit, type ProveOptions } from "../internal/prover.js";
import {
    buildMultiSigCircuitInput,
    buildStateValidationCircuitInput,
    normalizeHash,
    type HashInput,
} from "./circuit.js";
import {
    MULTISIG_PUBLIC_INPUTS,
    type MultiSigConfig,
    type MultiSigProofData,
    type StateValidationProofData,
} from "./types.js";

/** Parameter names of `zk_multi_sig_ecdsa`, in ABI order. */
export const ZK_MULTISIG_CIRCUIT_PARAMS = [
    "signers",
    "threshold",
    "signers_root",
    "salt",
    "merkle_proof_length",
    "indices",
    "siblings",
    "signatures",
    "txn_hash",
    "on_chain_state_root",
] as const;

/** Parameter names of `zk_multi_sig_ecdsa_private_state_validation`, in ABI order. */
export const ZK_MULTISIG_STATE_VALIDATION_CIRCUIT_PARAMS = [
    "signers_root",
    "threshold",
    "salt",
    "on_chain_state_root",
] as const;

/**
 * Generates the proof that authorises `txnHash`: at least `threshold` signers from the private set
 * signed it, and the private configuration matches the on-chain state root.
 *
 * For Safe the proof is wrapped as a contract signature; for Nexus it is the UserOperation signature
 * (see `zk-multisig/safe` and `zk-multisig/nexus`).
 *
 * @param config           The account's private configuration (signers, threshold, salt).
 * @param txnHash          The signed 32-byte hash (Safe transaction hash or UserOperation hash).
 * @param signatures       65-byte signatures over `txnHash`, at least `threshold` of them.
 * @param onChainStateRoot The state root stored on-chain; the proof is refused early if it does not match.
 * @param circuit          Compiled `zk_multi_sig_ecdsa` artifact (parsed JSON).
 * @param options          Optional {@link ProveOptions} (shared Barretenberg instance, …).
 * @throws {InvalidArgumentError} on malformed inputs, insufficient or duplicate signatures.
 * @throws {NotFoundError} if a signer is outside the private set.
 * @throws {ChainStateError} if the configuration does not match `onChainStateRoot`.
 * @throws {InvalidCircuitError} if `circuit` is not `zk_multi_sig_ecdsa`.
 * @throws {MissingPeerDependencyError} if the proving peer dependencies are not installed.
 * @throws {ProofGenerationError} if witness execution or proving fails.
 */
export async function generateMultiSigProof(
    config: MultiSigConfig,
    txnHash: HashInput,
    signatures: readonly Hex[],
    onChainStateRoot: bigint | Hex,
    circuit: unknown,
    options?: ProveOptions,
): Promise<MultiSigProofData> {
    const compiled = assertCircuit(circuit, "zk_multi_sig_ecdsa", ZK_MULTISIG_CIRCUIT_PARAMS);
    const input = buildMultiSigCircuitInput(config, txnHash, signatures, onChainStateRoot);

    const { proof, publicInputs } = await proveCircuit(
        compiled,
        input as unknown as Record<string, unknown>,
        MULTISIG_PUBLIC_INPUTS,
        options,
    );

    return {
        proof,
        publicInputs,
        txnHash: bytesToHex(Uint8Array.from(normalizeHash(txnHash))),
        // Public inputs: [0..31] hash bytes, [32] state root.
        stateRoot: publicInputs[32],
    };
}

/**
 * Generates the proof that a state root commits to a valid configuration (signers, threshold, salt).
 * It is submitted when creating a Safe signer or Nexus account, and when changing the state root.
 *
 * @param config  The account's private configuration.
 * @param circuit Compiled `zk_multi_sig_ecdsa_private_state_validation` artifact (parsed JSON).
 * @param options Optional {@link ProveOptions}.
 * @throws {InvalidArgumentError} on an invalid or unprovable configuration.
 * @throws {InvalidCircuitError} if `circuit` is not the state-validation circuit.
 * @throws {MissingPeerDependencyError} if the proving peer dependencies are not installed.
 * @throws {ProofGenerationError} if witness execution or proving fails.
 */
export async function generateStateValidationProof(
    config: MultiSigConfig,
    circuit: unknown,
    options?: ProveOptions,
): Promise<StateValidationProofData> {
    const compiled = assertCircuit(
        circuit,
        "zk_multi_sig_ecdsa_private_state_validation",
        ZK_MULTISIG_STATE_VALIDATION_CIRCUIT_PARAMS,
    );
    const input = buildStateValidationCircuitInput(config);

    const { proof, publicInputs } = await proveCircuit(
        compiled,
        input as unknown as Record<string, unknown>,
        1,
        options,
    );

    return { proof, publicInputs, stateRoot: publicInputs[0] };
}
