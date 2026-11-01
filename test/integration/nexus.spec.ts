/**
 * Integration with the real Nexus account, ZK validator factory and ERC-4337 EntryPoint v0.7 — the
 * production path: factory → account → UserOperation → `handleOps` → validator → verifier.
 *
 * Third-party bytecode is not vendored here, so these tests run against contracts built from source:
 *
 *   node scripts/build-integration-contracts.mjs ../microchain-zk-signers /tmp/zk-int-out
 *   ZK_SIGNERS_OUT=/tmp/zk-int-out pnpm test:integration
 *
 * Skipped when `ZK_SIGNERS_OUT` is unset or Foundry's `anvil` is missing.
 */

import { createBarretenberg } from "../../src/internal/prover.js";
import { Barretenberg } from "@aztec/bb.js";
import { getAddress, parseEther, type Address, type Hex } from "viem";
import { entryPoint07Abi, toPackedUserOperation } from "viem/account-abstraction";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ChainStateError } from "../../src/errors.js";
import { createMultiSigState, generateStateValidationProof, type MultiSigConfig } from "../../src/zk-multisig/index.js";
import {
    computeNexusAccountAddress,
    createNexusAccount,
    encodeExecuteCallData,
    encodeUpdateStateRootCall,
    encodeValidatorInitData,
    encodeValidatorNonceKey,
    generateNexusUserOperationProof,
    getNexusAccountStatus,
    getNexusNonce,
    getNexusUserOperationHash,
    prepareNexusUserOperation,
    sendNexusUserOperation,
    type NexusCall,
    type NexusUserOperation,
} from "../../src/zk-multisig/nexus.js";
import { loadCircuit, testAccounts } from "../helpers.js";
import {
    anvilAvailable,
    deploy,
    deployAll,
    deployForgeArtifact,
    forgeOutDir,
    startChain,
    type Chain,
    type Deployment,
} from "../onchain/harness.js";

const TIMEOUT = 300_000;
const SALT = 0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefn;
const txCircuit = loadCircuit("zk_multi_sig_ecdsa");
const stateCircuit = loadCircuit("zk_multi_sig_ecdsa_private_state_validation");
const recipient: Address = "0x000000000000000000000000000000000000dEaD";

describe.skipIf(!anvilAvailable() || !forgeOutDir())("Nexus + EntryPoint v0.7 (real contracts)", () => {
    let chain: Chain;
    let contracts: Deployment;
    let api: Barretenberg;
    let entryPoint: Address;
    let factory: Address;
    let account: Address;
    let accountProof: Hex;
    let chainId: number;

    const owners = testAccounts(3, "nexus-owners");
    const config: MultiSigConfig = { signers: owners.map((a) => a.address), threshold: 2, salt: SALT };
    const state = createMultiSigState(config);

    const prepare = (call: NexusCall) =>
        prepareNexusUserOperation(chain.publicClient, { account, validator: contracts.validator, call, entryPoint });

    const proveOperation = async (userOperation: NexusUserOperation, hash: Hex, signers: number[], cfg = config) => {
        const signatures = await Promise.all(signers.map((i) => owners[i].sign({ hash })));
        return generateNexusUserOperationProof(chain.publicClient, {
            userOperation,
            validator: contracts.validator,
            signatures,
            config: cfg,
            circuit: txCircuit,
            entryPoint,
            options: { barretenberg: api },
        });
    };

    const submit = (userOperation: NexusUserOperation) =>
        sendNexusUserOperation(chain.walletClient, { userOperation, entryPoint, chain: chain.walletClient.chain });

    beforeAll(async () => {
        chain = await startChain();
        chainId = await chain.publicClient.getChainId();
        api = (await createBarretenberg()) as Barretenberg;
        contracts = await deployAll(chain);

        const stateProof = await generateStateValidationProof(config, stateCircuit, { barretenberg: api });
        const initData = encodeValidatorInitData(state.stateRoot, stateProof.proof);

        entryPoint = await deployForgeArtifact(chain, "EntryPoint.sol", "EntryPoint");
        // Nexus requires a default validator distinct from the one an account installs; in production it is
        // the K1 validator. Any validator works here, so a second ZK validator instance serves. The
        // implementation and the bootstrapper install it on themselves at construction.
        const defaultValidator = await deploy(chain, "ZKMultiSigValidator", [
            contracts.stateAdapter,
            contracts.txAdapter,
        ]);
        const implementation = await deployForgeArtifact(chain, "Nexus.sol", "Nexus", [
            entryPoint,
            defaultValidator,
            initData,
        ]);
        const bootstrapper = await deployForgeArtifact(chain, "NexusBootstrap.sol", "NexusBootstrap", [
            defaultValidator,
            initData,
        ]);
        factory = await deployForgeArtifact(chain, "ZKMultiSigValidatorFactory.sol", "ZKMultiSigValidatorFactory", [
            implementation,
            contracts.validator,
            bootstrapper,
        ]);

        accountProof = stateProof.proof;
        const created = await createNexusAccount(chain.walletClient, {
            factory,
            stateRoot: state.stateRoot,
            stateValidationProof: accountProof,
        });
        account = created.account;
        await chain.testClient.setBalance({ address: account, value: parseEther("10") });
    }, TIMEOUT);

    afterAll(async () => {
        await api.destroy();
        await chain.stop();
    });

    it("creates the account with the validator installed and initialised", async () => {
        expect(await chain.publicClient.getCode({ address: account })).toBeDefined();
        const status = await getNexusAccountStatus(chain.publicClient, { account, validator: contracts.validator });
        expect(status).toMatchObject({ installed: true, initialized: true, stateRoot: state.stateRoot });
        expect(getAddress(status.entryPoint)).toBe(getAddress(entryPoint));
    });

    it("the offline UserOperation hash equals the EntryPoint's getUserOpHash", async () => {
        const { userOperation, userOperationHash } = await prepare({ to: recipient, value: 1n });
        const onChain = await chain.publicClient.readContract({
            address: entryPoint,
            abi: entryPoint07Abi,
            functionName: "getUserOpHash",
            args: [toPackedUserOperation(userOperation)],
        });
        expect(userOperationHash).toBe(onChain);
        expect(getNexusUserOperationHash(userOperation, chainId, entryPoint)).toBe(onChain);
    });

    it("uses the nonce layout Nexus expects (validation mode 0, validator, sequence)", async () => {
        const nonce = await getNexusNonce(chain.publicClient, { account, validator: contracts.validator, entryPoint });
        const bytes = nonce.toString(16).padStart(64, "0");
        expect(bytes.slice(0, 8)).toBe("00000000"); // 3 empty bytes + validation mode 0
        expect(`0x${bytes.slice(8, 48)}`).toBe(contracts.validator.toLowerCase());
        expect(encodeValidatorNonceKey(contracts.validator)).toBe(nonce >> 64n);
    });

    it(
        "executes a UserOperation authorised by a ZK proof, advances the nonce and refuses a replay",
        async () => {
            const { userOperation, userOperationHash } = await prepare({ to: recipient, value: parseEther("1") });
            const signed = await proveOperation(userOperation, userOperationHash, [0, 2]);

            const before = await chain.publicClient.getBalance({ address: recipient });
            const sent = await submit(signed.userOperation);
            expect(sent.success).toBe(true);
            expect(sent.userOperationHash).toBe(userOperationHash);
            expect((await chain.publicClient.getBalance({ address: recipient })) - before).toBe(parseEther("1"));
            expect(
                await getNexusNonce(chain.publicClient, { account, validator: contracts.validator, entryPoint }),
            ).toBe(userOperation.nonce + 1n);

            // The nonce moved: the same operation is refused by the EntryPoint (AA25).
            await expect(submit(signed.userOperation)).rejects.toThrow(/AA25/);
        },
        TIMEOUT,
    );

    it(
        "reports AA24 with its meaning when the proof was made for another operation",
        async () => {
            const first = await prepare({ to: recipient, value: 1n });
            const second = await prepare({ to: recipient, value: 2n });
            const proven = await proveOperation(first.userOperation, first.userOperationHash, [0, 1]);

            const forged = { ...second.userOperation, signature: proven.userOperation.signature };
            const error = await submit(forged).catch((e) => e);
            expect(error).toBeInstanceOf(ChainStateError);
            expect((error as Error).message).toMatch(/AA24: signature error/);
        },
        TIMEOUT,
    );

    it("refuses early when the configuration does not match the chain", async () => {
        const { userOperation, userOperationHash } = await prepare({ to: recipient, value: 1n });
        await expect(
            proveOperation(userOperation, userOperationHash, [0, 1], { ...config, salt: SALT + 1n }),
        ).rejects.toThrow(ChainStateError);
    });

    it(
        "rotates the state root through a UserOperation; the old configuration then stops working",
        async () => {
            const rotated: MultiSigConfig = { signers: config.signers, threshold: 3, salt: SALT + 7n };
            const rotatedState = createMultiSigState(rotated);
            const newProof = await generateStateValidationProof(rotated, stateCircuit, { barretenberg: api });

            const update = await prepare(
                encodeUpdateStateRootCall({
                    validator: contracts.validator,
                    newStateRoot: rotatedState.stateRoot,
                    stateValidationProof: newProof.proof,
                }),
            );
            const signed = await proveOperation(update.userOperation, update.userOperationHash, [0, 1]);
            expect((await submit(signed.userOperation)).success).toBe(true);
            expect(
                (await getNexusAccountStatus(chain.publicClient, { account, validator: contracts.validator }))
                    .stateRoot,
            ).toBe(rotatedState.stateRoot);

            // The old configuration no longer matches the on-chain root …
            const next = await prepare({ to: recipient, value: 1n });
            await expect(proveOperation(next.userOperation, next.userOperationHash, [0, 1])).rejects.toThrow(
                ChainStateError,
            );

            // … the new one (threshold 3, new salt) works.
            const ok = await proveOperation(next.userOperation, next.userOperationHash, [0, 1, 2], rotated);
            expect((await submit(ok.userOperation)).success).toBe(true);
        },
        TIMEOUT,
    );

    it("the factory is deterministic, and the index selects another account", async () => {
        const params = { factory, stateRoot: state.stateRoot, stateValidationProof: accountProof };
        expect(await computeNexusAccountAddress(chain.publicClient, params)).toBe(account);
        expect(await computeNexusAccountAddress(chain.publicClient, { ...params, index: 1n })).not.toBe(account);
        expect(encodeExecuteCallData({ to: recipient })).toMatch(/^0xe9ae5c53/);
    });
});
