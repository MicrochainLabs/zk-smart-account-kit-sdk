/**
 * The multisig examples are documentation that must keep working: run them against real contracts.
 * See safe.spec.ts for how to provide `ZK_SIGNERS_OUT`.
 */

import { parseEther, type Address } from "viem";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { main as nexusExample } from "../../examples/zk-multisig-nexus.js";
import { main as safeExample } from "../../examples/zk-multisig-safe.js";
import { testAccounts } from "../helpers.js";
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
import { createMultiSigState, createBarretenberg, generateStateValidationProof } from "../../src/zk-multisig/index.js";
import { encodeValidatorInitData } from "../../src/zk-multisig/nexus.js";
import { SAFE_V141 } from "../../src/zk-multisig/safe.js";
import { loadCircuit } from "../helpers.js";

const recipient: Address = "0x000000000000000000000000000000000000bEEF";
const owners = testAccounts(3, "examples");

describe.skipIf(!anvilAvailable() || !forgeOutDir())("multisig examples", () => {
    let chain: Chain;
    let contracts: Deployment;

    beforeAll(async () => {
        chain = await startChain();
        contracts = await deployAll(chain);
    }, 300_000);

    afterAll(async () => {
        await chain.stop();
    });

    // The example uses canonical v1.4.1 addresses; put the freshly built Safe contracts there.
    async function placeSafeAtCanonicalAddresses() {
        const singleton = await deployForgeArtifact(chain, "Safe.sol", "Safe");
        const factory = await deployForgeArtifact(chain, "SafeProxyFactory.sol", "SafeProxyFactory");
        const handler = await deployForgeArtifact(
            chain,
            "CompatibilityFallbackHandler.sol",
            "CompatibilityFallbackHandler",
        );
        for (const [from, to] of [
            [singleton, SAFE_V141.singleton],
            [factory, SAFE_V141.proxyFactory],
            [handler, SAFE_V141.fallbackHandler],
        ] as const) {
            const code = await chain.publicClient.getCode({ address: from });
            await chain.testClient.setCode({ address: to, bytecode: code! });
        }
    }

    const fund = (address: Address) => chain.testClient.setBalance({ address, value: parseEther("10") });

    it("zk-multisig-safe", async () => {
        await placeSafeAtCanonicalAddresses();
        const before = await chain.publicClient.getBalance({ address: recipient });
        const result = await safeExample({
            client: chain.walletClient as never,
            factory: contracts.safeFactory,
            verifier: contracts.txAdapter,
            owners,
            threshold: 2,
            recipient,
            fundSafe: fund,
        });
        expect(JSON.parse(result.backup)).toMatchObject({ version: 1, threshold: 2 });
        await chain.publicClient.waitForTransactionReceipt({ hash: result.transactionHash });
        expect((await chain.publicClient.getBalance({ address: recipient })) - before).toBe(1n);
    }, 300_000);

    it("zk-multisig-nexus", async () => {
        const entryPoint = await deployForgeArtifact(chain, "EntryPoint.sol", "EntryPoint");
        // Nexus needs a default validator distinct from the installed one; any validator initialised with
        // some valid configuration will do.
        const defaultValidator = await deploy(chain, "ZKMultiSigValidator", [
            contracts.stateAdapter,
            contracts.txAdapter,
        ]);
        const api = await createBarretenberg();
        const seed = { signers: owners.map((o) => o.address), threshold: 1, salt: 1n };
        const proof = await generateStateValidationProof(
            seed,
            loadCircuit("zk_multi_sig_ecdsa_private_state_validation"),
            {
                barretenberg: api,
            },
        );
        await api.destroy();
        const initData = encodeValidatorInitData(createMultiSigState(seed).stateRoot, proof.proof);
        const implementation = await deployForgeArtifact(chain, "Nexus.sol", "Nexus", [
            entryPoint,
            defaultValidator,
            initData,
        ]);
        const bootstrapper = await deployForgeArtifact(chain, "NexusBootstrap.sol", "NexusBootstrap", [
            defaultValidator,
            initData,
        ]);
        const factory = await deployForgeArtifact(
            chain,
            "ZKMultiSigValidatorFactory.sol",
            "ZKMultiSigValidatorFactory",
            [implementation, contracts.validator, bootstrapper],
        );

        const before = await chain.publicClient.getBalance({ address: recipient });
        const result = await nexusExample({
            client: chain.walletClient as never,
            factory,
            validator: contracts.validator,
            entryPoint,
            owners,
            threshold: 2,
            recipient,
            fundAccount: fund,
        });
        expect(result.success).toBe(true);
        expect(JSON.parse(result.backup)).toMatchObject({ version: 1, threshold: 2 });
        expect((await chain.publicClient.getBalance({ address: recipient })) - before).toBe(1n);
    }, 300_000);
});
