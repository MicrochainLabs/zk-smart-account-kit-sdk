/**
 * ZK MultiSig on Safe — a Safe owned by a private M-of-N signer set.
 *
 *   1. Pick the private configuration (signers, threshold) and a random salt. Only a hiding commitment,
 *      the *state root*, goes on-chain. BACK UP the configuration together with the salt: without the
 *      salt no proof can ever be generated again.
 *   2. Prove the commitment is valid and create the ZK signer through the factory.
 *   3. Deploy a Safe that has the ZK signer as its owner.
 *   4. Per transaction: `threshold` signers sign the Safe transaction hash, and a proof — not their
 *      signatures — is submitted, revealing neither who signed nor the other members.
 *
 * Requires the optional peers (pnpm add @aztec/bb.js @noir-lang/noir_js), the compiled circuits
 * `zk_multi_sig_ecdsa` and `zk_multi_sig_ecdsa_private_state_validation`, and the deployed
 * microchain-zk-signers contracts (see docs/COMPATIBILITY.md).
 */

import type { Address, Client, Hex, LocalAccount } from "viem";
import { getChainId, sendTransaction, waitForTransactionReceipt } from "viem/actions";
import {
    createBarretenberg,
    createMultiSigState,
    generateStateValidationProof,
    serializeMultiSigState,
    type MultiSigConfig,
} from "zk-smart-account-kit-sdk/zk-multisig";
import {
    buildSafeTransaction,
    createZKSigner,
    encodeCreateSafeProxy,
    encodeExecTransaction,
    encodeSafeSetup,
    generateSafeTransactionProof,
    getSafeInfo,
    parseSafeProxyCreation,
    predictSafeAddress,
    signSafeTransaction,
} from "zk-smart-account-kit-sdk/zk-multisig/safe";
import stateCircuit from "../test/fixtures/circuits/zk_multi_sig_ecdsa_private_state_validation.json" with { type: "json" };
import txCircuit from "../test/fixtures/circuits/zk_multi_sig_ecdsa.json" with { type: "json" };

export async function main(params: {
    /** A viem client with an account that pays gas (wallet client extended with public actions). */
    client: Client;
    /** Deployed ZKMultiSigEcdsaFactory, and the transaction verifier (ZKMultiSigEcdsaProofVerifier) it will use. */
    factory: Address;
    verifier: Address;
    /** The private signers' accounts (in production, each one signs in its own wallet or HSM). */
    owners: LocalAccount[];
    threshold: number;
    recipient: Address;
    /** Funds the new Safe so it can send the transfer. */
    fundSafe: (safe: Address) => Promise<void>;
}) {
    const { client, factory, verifier, owners, threshold, recipient, fundSafe } = params;

    // 1. The private configuration. A fresh random salt is generated; keep `backup` encrypted and safe.
    const state = createMultiSigState({ signers: owners.map((o) => o.address), threshold });
    const config: MultiSigConfig = { signers: state.signers, threshold, salt: state.salt };
    const backup = serializeMultiSigState(state); // SECRET: signers + threshold + salt

    // One Barretenberg instance for all proofs of this process.
    const barretenberg = await createBarretenberg();
    try {
        // 2. Prove the commitment is valid and create the ZK signer.
        const stateProof = await generateStateValidationProof(config, stateCircuit, { barretenberg });
        const { signer: zkSigner } = await createZKSigner(client, {
            factory,
            stateRoot: state.stateRoot,
            verifier,
            stateValidationProof: stateProof.proof,
        });

        // 3. Deploy a Safe owned by the ZK signer (threshold 1: the proof is the only signature needed).
        const initializer = encodeSafeSetup({ owners: [zkSigner], threshold: 1 });
        const proxy = { initializer, saltNonce: BigInt(Date.now()) };
        const safe = await predictSafeAddress(client, proxy);
        const deployment = encodeCreateSafeProxy(proxy);
        const deployed = await sendTransaction(client, {
            ...deployment,
            account: client.account!,
            chain: client.chain,
        });
        const receipt = await waitForTransactionReceipt(client, { hash: deployed });
        if (parseSafeProxyCreation(receipt.logs) !== safe) throw new Error("unexpected Safe address");

        await fundSafe(safe);

        // 4. A transaction: signers sign its hash, a proof replaces their signatures.
        const { nonce } = await getSafeInfo(client, safe, zkSigner);
        const transaction = buildSafeTransaction({ to: recipient, value: 1n, nonce });
        const chainId = await getChainId(client);
        const signatures: Hex[] = await Promise.all(
            owners.slice(0, threshold).map((owner) => signSafeTransaction(owner, chainId, safe, transaction)),
        );
        const { signatures: safeSignatures } = await generateSafeTransactionProof(client, {
            safe,
            zkSigner,
            transaction,
            signatures,
            config,
            circuit: txCircuit,
            options: { barretenberg },
        });

        const hash = await sendTransaction(client, {
            to: safe,
            data: encodeExecTransaction(transaction, safeSignatures),
            account: client.account!,
            chain: client.chain,
        });
        return { backup, zkSigner, safe, transactionHash: hash };
    } finally {
        await barretenberg.destroy();
    }
}
