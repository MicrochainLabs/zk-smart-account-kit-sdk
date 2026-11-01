/**
 * ZK MultiSig on a Nexus (ERC-7579) smart account — an account controlled by a private M-of-N signer set.
 *
 *   1. Pick the private configuration and a random salt; only the hiding state root goes on-chain.
 *      BACK UP the configuration with the salt: without it no proof can ever be generated again.
 *   2. Create the account through the factory (the validator verifies the commitment on-chain).
 *   3. Per UserOperation: `threshold` signers sign its hash, and a proof — not their signatures —
 *      becomes the UserOperation signature, revealing neither who signed nor the other members.
 *
 * Requires the optional peers (pnpm add @aztec/bb.js @noir-lang/noir_js), the compiled circuits
 * `zk_multi_sig_ecdsa` and `zk_multi_sig_ecdsa_private_state_validation`, and the deployed
 * microchain-zk-signers contracts (see docs/COMPATIBILITY.md).
 */

import type { Address, Client, Hex, LocalAccount } from "viem";
import {
    createBarretenberg,
    createMultiSigState,
    generateStateValidationProof,
    serializeMultiSigState,
    type MultiSigConfig,
} from "zk-smart-account-kit-sdk/zk-multisig";
import {
    createNexusAccount,
    generateNexusUserOperationProof,
    prepareNexusUserOperation,
    sendNexusUserOperation,
} from "zk-smart-account-kit-sdk/zk-multisig/nexus";
import stateCircuit from "../test/fixtures/circuits/zk_multi_sig_ecdsa_private_state_validation.json" with { type: "json" };
import txCircuit from "../test/fixtures/circuits/zk_multi_sig_ecdsa.json" with { type: "json" };

/** Signers sign the raw 32-byte hash (no message prefix). */
function signHash(owner: LocalAccount, hash: Hex): Promise<Hex> {
    if (!owner.sign) throw new Error("This account cannot sign raw hashes.");
    return owner.sign({ hash });
}

export async function main(params: {
    /** A viem client with an account that pays gas (wallet client extended with public actions). */
    client: Client;
    /** Deployed ZKMultiSigValidatorFactory and the ZKMultiSigValidator it installs. */
    factory: Address;
    validator: Address;
    /** The ERC-4337 EntryPoint v0.7 the account is bound to (defaults to the canonical one). */
    entryPoint?: Address;
    /** The private signers' accounts (in production, each one signs in its own wallet or HSM). */
    owners: LocalAccount[];
    threshold: number;
    recipient: Address;
    /** Funds the new account: it pays the UserOperation prefund unless a paymaster does. */
    fundAccount: (account: Address) => Promise<void>;
}) {
    const { client, factory, validator, entryPoint, owners, threshold, recipient, fundAccount } = params;

    // 1. The private configuration. A fresh random salt is generated; keep `backup` encrypted and safe.
    const state = createMultiSigState({ signers: owners.map((o) => o.address), threshold });
    const config: MultiSigConfig = { signers: state.signers, threshold, salt: state.salt };
    const backup = serializeMultiSigState(state); // SECRET: signers + threshold + salt

    // One Barretenberg instance for all proofs of this process.
    const barretenberg = await createBarretenberg();
    try {
        // 2. Create the account.
        const stateProof = await generateStateValidationProof(config, stateCircuit, { barretenberg });
        const { account } = await createNexusAccount(client, {
            factory,
            stateRoot: state.stateRoot,
            stateValidationProof: stateProof.proof,
        });

        await fundAccount(account);

        // 3. A UserOperation: signers sign its hash, a proof replaces their signatures.
        const { userOperation, userOperationHash } = await prepareNexusUserOperation(client, {
            account,
            validator,
            entryPoint,
            call: { to: recipient, value: 1n },
        });
        const signatures = await Promise.all(
            owners.slice(0, threshold).map((owner) => signHash(owner, userOperationHash)),
        );
        const proven = await generateNexusUserOperationProof(client, {
            userOperation,
            validator,
            entryPoint,
            signatures,
            config,
            circuit: txCircuit,
            options: { barretenberg },
        });

        // Submit directly to the EntryPoint (or hand `proven.userOperation` to a bundler).
        const sent = await sendNexusUserOperation(client, { userOperation: proven.userOperation, entryPoint });
        return { backup, account, ...sent };
    } finally {
        await barretenberg.destroy();
    }
}
