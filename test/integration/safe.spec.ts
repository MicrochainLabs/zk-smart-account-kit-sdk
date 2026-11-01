/**
 * Integration with real Safe v1.4.1 contracts. Safe's bytecode is not vendored in this repository, so
 * these tests run against contracts built from source (Safe among them):
 *
 *   OUT="$(mktemp -d)"
 *   node scripts/build-integration-contracts.mjs ../microchain-zk-signers "$OUT"
 *   ZK_SIGNERS_OUT="$OUT" pnpm test:integration
 *
 * Skipped when `ZK_SIGNERS_OUT` is unset or Foundry's `anvil` is missing.
 */

import { createBarretenberg } from "../../src/internal/prover.js";
import { Barretenberg } from "@aztec/bb.js";
import { getAddress, parseEther, type Address, type Hex } from "viem";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createMultiSigState, generateStateValidationProof, type MultiSigConfig } from "../../src/zk-multisig/index.js";
import {
    buildSafeTransaction,
    computeSafeTransactionHash,
    computeZKSignerAddress,
    createZKSigner,
    encodeCreateSafeProxy,
    encodeExecTransaction,
    encodeSafeSetup,
    encodeSafeSignatures,
    generateSafeTransactionProof,
    getSafeInfo,
    parseSafeProxyCreation,
    predictSafeAddress,
    safeAbi,
    signSafeTransaction,
    type SafeTransactionData,
} from "../../src/zk-multisig/safe.js";
import { loadCircuit, testAccounts } from "../helpers.js";
import {
    anvilAvailable,
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

describe.skipIf(!anvilAvailable() || !forgeOutDir())("Safe v1.4.1 (real contracts)", () => {
    let chain: Chain;
    let contracts: Deployment;
    let api: Barretenberg;
    let safeSingleton: Address;
    let proxyFactory: Address;
    let fallbackHandler: Address;
    let zkSigner: Address;
    let chainId: number;

    const owners = testAccounts(3, "safe-owners");
    const config: MultiSigConfig = { signers: owners.map((a) => a.address), threshold: 2, salt: SALT };
    const state = createMultiSigState(config);
    let saltNonce = 1n;

    async function deploySafe(safeOwners: Address[], threshold: number): Promise<Address> {
        const initializer = encodeSafeSetup({ owners: safeOwners, threshold, fallbackHandler });
        const params = { initializer, saltNonce: saltNonce++, singleton: safeSingleton, proxyFactory };
        const predicted = await predictSafeAddress(chain.publicClient, params);
        const { to, data } = encodeCreateSafeProxy(params);
        const hash = await chain.walletClient.sendTransaction({
            to,
            data,
            account: chain.walletClient.account!,
            chain: chain.walletClient.chain,
        });
        const receipt = await chain.publicClient.waitForTransactionReceipt({ hash });
        const created = parseSafeProxyCreation(receipt.logs);
        expect(created).toBe(predicted);
        await chain.testClient.setBalance({ address: created, value: parseEther("10") });
        return created;
    }

    async function execute(safe: Address, tx: SafeTransactionData, signatures: Hex) {
        const hash = await chain.walletClient.sendTransaction({
            to: safe,
            data: encodeExecTransaction(tx, signatures),
            gas: 15_000_000n,
            account: chain.walletClient.account!,
            chain: chain.walletClient.chain,
        });
        return chain.publicClient.waitForTransactionReceipt({ hash });
    }

    const transfer = async (safe: Address, value: bigint) =>
        buildSafeTransaction({ to: recipient, value, nonce: (await getSafeInfo(chain.publicClient, safe)).nonce });

    const prove = async (safe: Address, tx: SafeTransactionData, signers: number[]) => {
        const signatures = await Promise.all(signers.map((i) => signSafeTransaction(owners[i], chainId, safe, tx)));
        return generateSafeTransactionProof(chain.publicClient, {
            safe,
            zkSigner,
            transaction: tx,
            signatures,
            config,
            circuit: txCircuit,
            options: { barretenberg: api },
        });
    };

    beforeAll(async () => {
        chain = await startChain();
        chainId = await chain.publicClient.getChainId();
        api = (await createBarretenberg()) as Barretenberg;
        contracts = await deployAll(chain);
        safeSingleton = await deployForgeArtifact(chain, "Safe.sol", "Safe");
        proxyFactory = await deployForgeArtifact(chain, "SafeProxyFactory.sol", "SafeProxyFactory");
        fallbackHandler = await deployForgeArtifact(
            chain,
            "CompatibilityFallbackHandler.sol",
            "CompatibilityFallbackHandler",
        );

        const stateProof = await generateStateValidationProof(config, stateCircuit, { barretenberg: api });
        ({ signer: zkSigner } = await createZKSigner(chain.walletClient, {
            factory: contracts.safeFactory,
            stateRoot: state.stateRoot,
            verifier: contracts.txAdapter,
            stateValidationProof: stateProof.proof,
        }));
    }, TIMEOUT);

    afterAll(async () => {
        await api.destroy();
        await chain.stop();
    });

    it("predicts the ZK signer address the factory uses", async () => {
        expect(
            await computeZKSignerAddress(chain.publicClient, {
                factory: contracts.safeFactory,
                stateRoot: state.stateRoot,
                verifier: contracts.txAdapter,
            }),
        ).toBe(zkSigner);
    });

    it("the offline transaction hash equals the Safe's own getTransactionHash", async () => {
        const safe = await deploySafe([zkSigner], 1);
        const tx = buildSafeTransaction({
            to: recipient,
            value: 12345n,
            data: "0xdeadbeef",
            operation: 0,
            safeTxGas: 1n,
            baseGas: 2n,
            gasPrice: 3n,
            nonce: 0n,
        });
        const onChain = await chain.publicClient.readContract({
            address: safe,
            abi: safeAbi,
            functionName: "getTransactionHash",
            args: [
                tx.to,
                tx.value,
                tx.data,
                tx.operation,
                tx.safeTxGas,
                tx.baseGas,
                tx.gasPrice,
                tx.gasToken,
                tx.refundReceiver,
                tx.nonce,
            ],
        });
        expect(computeSafeTransactionHash(chainId, safe, tx)).toBe(onChain);
    });

    it("sets the Safe up with the ZK signer as its owner", async () => {
        const safe = await deploySafe([zkSigner], 1);
        const info = await getSafeInfo(chain.publicClient, safe, zkSigner);
        expect(info.owners.map(getAddress)).toEqual([getAddress(zkSigner)]);
        expect(info.threshold).toBe(1n);
        expect(info.nonce).toBe(0n);
        await expect(getSafeInfo(chain.publicClient, safe, recipient)).rejects.toThrow(/not an owner/);
    });

    it(
        "executes a transaction authorised by a ZK proof, and refuses a replay",
        async () => {
            const safe = await deploySafe([zkSigner], 1);
            const tx = await transfer(safe, parseEther("1"));
            const hash = computeSafeTransactionHash(chainId, safe, tx);

            // Two of the three private signers sign the Safe transaction (EIP-712); the proof becomes the
            // ZK signer's contract signature.
            const proven = await prove(safe, tx, [0, 2]);
            expect(proven.safeTxHash).toBe(hash);
            expect(await signSafeTransaction(owners[0], chainId, safe, tx)).toBe(await owners[0].sign({ hash }));

            const before = await chain.publicClient.getBalance({ address: recipient });
            expect((await execute(safe, tx, proven.signatures)).status).toBe("success");
            expect((await chain.publicClient.getBalance({ address: recipient })) - before).toBe(parseEther("1"));
            expect((await getSafeInfo(chain.publicClient, safe)).nonce).toBe(1n);

            // The Safe nonce moved, so the same signatures no longer match the transaction hash.
            expect((await execute(safe, tx, proven.signatures)).status).toBe("reverted");
        },
        TIMEOUT,
    );

    it(
        "rejects a proof made for another transaction",
        async () => {
            const safe = await deploySafe([zkSigner], 1);
            const small = await transfer(safe, 1n);
            const big = await transfer(safe, parseEther("5"));
            const proven = await prove(safe, small, [0, 1]);
            const before = await chain.publicClient.getBalance({ address: recipient });
            expect((await execute(safe, big, proven.signatures)).status).toBe("reverted");
            expect(await chain.publicClient.getBalance({ address: recipient })).toBe(before);
        },
        TIMEOUT,
    );

    it(
        "combines the ZK signer with an ordinary owner (threshold 2), in either list order",
        async () => {
            const [eoa] = testAccounts(1, "safe-eoa");
            const safe = await deploySafe([zkSigner, eoa.address], 2);
            const tx = await transfer(safe, 1000n);
            const hash = computeSafeTransactionHash(chainId, safe, tx);

            const proof = (await prove(safe, tx, [0, 1])).proof.proof;
            const eoaSignature = await eoa.sign({ hash });
            const blob = encodeSafeSignatures([
                { signer: eoa.address, data: eoaSignature, kind: "ecdsa" },
                { signer: zkSigner, data: proof, kind: "contract" },
            ]);
            // The encoder sorts by owner address, as Safe requires, so the list order is irrelevant.
            expect(
                encodeSafeSignatures([
                    { signer: zkSigner, data: proof, kind: "contract" },
                    { signer: eoa.address, data: eoaSignature, kind: "ecdsa" },
                ]),
            ).toBe(blob);

            const before = await chain.publicClient.getBalance({ address: recipient });
            expect((await execute(safe, tx, blob)).status).toBe("success");
            expect((await chain.publicClient.getBalance({ address: recipient })) - before).toBe(1000n);
        },
        TIMEOUT,
    );
});
