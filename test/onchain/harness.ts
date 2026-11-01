/**
 * Local-chain harness for the on-chain tests: starts Anvil, deploys the Microchain contracts from
 * `test/fixtures/contracts`, and provides funded viem clients. Requires Foundry's `anvil` on PATH;
 * suites skip themselves when it is not installed.
 */

import { execFileSync, spawn, type ChildProcess } from "node:child_process";
import { readFileSync } from "node:fs";
import { createServer } from "node:net";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import {
    createPublicClient,
    createTestClient,
    createWalletClient,
    http,
    type Abi,
    type Address,
    type Hex,
    type PublicClient,
    type WalletClient,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { foundry } from "viem/chains";

const FIXTURES = join(fileURLToPath(new URL(".", import.meta.url)), "..", "fixtures", "contracts");

/** Anvil's well-known first development key (public, test-only). */
const ANVIL_KEY_0 = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

export function anvilAvailable(): boolean {
    try {
        execFileSync("anvil", ["--version"], { stdio: "ignore" });
        return true;
    } catch {
        return false;
    }
}

async function freePort(): Promise<number> {
    return new Promise((resolve, reject) => {
        const server = createServer();
        server.listen(0, "127.0.0.1", () => {
            const { port } = server.address() as { port: number };
            server.close(() => {
                resolve(port);
            });
        });
        server.on("error", reject);
    });
}

export interface Chain {
    url: string;
    publicClient: PublicClient;
    /** Deployer, funded. */
    walletClient: WalletClient;
    deployer: Address;
    /** Impersonation, balance and code manipulation. */
    testClient: ReturnType<typeof createTestClient>;
    stop(): Promise<void>;
}

export async function startChain(): Promise<Chain> {
    const port = await freePort();
    const url = `http://127.0.0.1:${port}`;
    const child: ChildProcess = spawn(
        "anvil",
        ["--port", String(port), "--silent", "--gas-limit", "100000000", "--code-size-limit", "100000"],
        {
            stdio: "ignore",
        },
    );

    const publicClient = createPublicClient({ chain: foundry, transport: http(url) });
    for (let attempt = 0; ; attempt++) {
        try {
            await publicClient.getChainId();
            break;
        } catch (error) {
            if (attempt > 100) {
                child.kill();
                throw error;
            }
            await new Promise((r) => setTimeout(r, 100));
        }
    }

    const account = privateKeyToAccount(ANVIL_KEY_0);
    return {
        url,
        publicClient,
        walletClient: createWalletClient({ account, chain: foundry, transport: http(url) }),
        deployer: account.address,
        testClient: createTestClient({ chain: foundry, mode: "anvil", transport: http(url) }),
        stop: () =>
            new Promise((resolve) => {
                child.once("exit", () => {
                    resolve();
                });
                child.kill();
            }),
    };
}

interface Fixture {
    abi: Abi;
    bytecode?: Hex;
    linkReferences?: Record<string, Record<string, { start: number; length: number }[]>>;
}

export function loadContract(name: string): Fixture & { abi: Abi } {
    return JSON.parse(readFileSync(join(FIXTURES, `${name}.json`), "utf8")) as Fixture;
}

/** Replaces library placeholders with deployed addresses. */
export function linkBytecode(
    bytecode: Hex,
    references: Fixture["linkReferences"],
    libraries: Record<string, Address>,
): Hex {
    let hex = bytecode.slice(2);
    for (const byFile of Object.values(references ?? {})) {
        for (const [library, positions] of Object.entries(byFile)) {
            const address = libraries[library];
            if (!address) throw new Error(`Missing address for library ${library}`);
            for (const { start, length } of positions) {
                hex = hex.slice(0, start * 2) + address.slice(2).toLowerCase() + hex.slice((start + length) * 2);
            }
        }
    }
    if (hex.includes("__$")) throw new Error("Unlinked library placeholders remain");
    return `0x${hex}`;
}

export async function deploy(
    chain: Chain,
    name: string,
    args: unknown[] = [],
    libraries: Record<string, Address> = {},
): Promise<Address> {
    const fixture = loadContract(name);
    if (!fixture.bytecode) throw new Error(`Fixture ${name} has no bytecode`);
    const hash = await chain.walletClient.deployContract({
        abi: fixture.abi,
        bytecode: linkBytecode(fixture.bytecode, fixture.linkReferences, libraries),
        args,
        account: chain.walletClient.account!,
        chain: foundry,
    });
    const receipt = await chain.publicClient.waitForTransactionReceipt({ hash });
    if (receipt.status !== "success" || !receipt.contractAddress) throw new Error(`Deploying ${name} failed`);
    return receipt.contractAddress;
}

/** Deploys a generated HonkVerifier with its two libraries. */
export async function deployHonkVerifier(chain: Chain, prefix: "Tx" | "State"): Promise<Address> {
    const relations = await deploy(chain, `${prefix}RelationsLib`);
    const transcript = await deploy(chain, `${prefix}ZKTranscriptLib`);
    return deploy(chain, `${prefix}HonkVerifier`, [], { RelationsLib: relations, ZKTranscriptLib: transcript });
}

/** Every Microchain contract the tests use, deployed and wired. */
export interface Deployment {
    stateAdapter: Address;
    txAdapter: Address;
    safeFactory: Address;
    validator: Address;
}

export async function deployAll(chain: Chain): Promise<Deployment> {
    const stateHonk = await deployHonkVerifier(chain, "State");
    const txHonk = await deployHonkVerifier(chain, "Tx");
    const stateAdapter = await deploy(chain, "PrivateStateValidationProofVerifier", [stateHonk]);
    const txAdapter = await deploy(chain, "ZKMultiSigEcdsaProofVerifier", [txHonk]);
    const safeFactory = await deploy(chain, "ZKMultiSigEcdsaFactory", [stateAdapter]);
    const validator = await deploy(chain, "ZKMultiSigValidator", [stateAdapter, txAdapter]);
    return { stateAdapter, txAdapter, safeFactory, validator };
}

/**
 * Directory of a Foundry build of microchain-zk-signers (`forge build --out <dir>`), used by the
 * integration tests that need third-party contracts (Safe) which are deliberately not vendored here.
 */
export function forgeOutDir(): string | undefined {
    return process.env.ZK_SIGNERS_OUT;
}

/** Deploys a contract from a Foundry artifact (`<out>/<File>.sol/<Contract>.json`). */
export async function deployForgeArtifact(
    chain: Chain,
    file: string,
    contract: string,
    args: unknown[] = [],
): Promise<Address> {
    const dir = forgeOutDir();
    if (!dir) throw new Error("ZK_SIGNERS_OUT is not set");
    const artifact = JSON.parse(readFileSync(join(dir, file, `${contract}.json`), "utf8")) as {
        abi: Abi;
        bytecode: { object: Hex };
    };
    const hash = await chain.walletClient.deployContract({
        abi: artifact.abi,
        bytecode: artifact.bytecode.object,
        args,
        account: chain.walletClient.account!,
        chain: foundry,
    });
    const receipt = await chain.publicClient.waitForTransactionReceipt({ hash });
    if (receipt.status !== "success" || !receipt.contractAddress) throw new Error(`Deploying ${contract} failed`);
    return receipt.contractAddress;
}
