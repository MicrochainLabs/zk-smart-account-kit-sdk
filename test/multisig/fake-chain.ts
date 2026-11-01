/**
 * A scriptable in-memory JSON-RPC backend for unit-testing the viem-based Safe and Nexus helpers
 * without a node: reads are answered by `calls`, writes are accepted and recorded.
 */

import {
    createWalletClient,
    custom,
    decodeFunctionData,
    encodeFunctionResult,
    keccak256,
    toHex,
    type Abi,
    type Address,
    type Client,
    type Hex,
    type LocalAccount,
} from "viem";
import { foundry } from "viem/chains";

export interface FakeChainOptions {
    chainId?: number;
    /** Answers `eth_call`. Return the ABI-encoded result, or undefined to revert. */
    call?: (to: Address, data: Hex) => Hex | undefined;
    /** Logs attached to every receipt. */
    logs?: { address: Address; topics: Hex[]; data: Hex }[];
    /** Makes `eth_estimateGas` / `eth_sendRawTransaction` fail with this message. */
    sendError?: string;
    /** Receipt status. */
    status?: "success" | "reverted";
}

export interface FakeChain {
    client: Client;
    /** Raw transactions accepted so far. */
    sent: Hex[];
    /** `eth_call` requests seen. */
    calls: { to: Address; data: Hex }[];
}

export function createFakeChain(account: LocalAccount | undefined, options: FakeChainOptions = {}): FakeChain {
    const chainId = options.chainId ?? 31337;
    const sent: Hex[] = [];
    const calls: { to: Address; data: Hex }[] = [];

    const request = async ({ method, params }: { method: string; params?: unknown }): Promise<unknown> => {
        const [first] = (params ?? []) as [Record<string, unknown> | string | undefined];
        switch (method) {
            case "eth_chainId":
                return toHex(chainId);
            case "eth_call": {
                const { to, data } = first as { to: Address; data: Hex };
                calls.push({ to, data });
                const result = options.call?.(to, data);
                if (result === undefined) throw rpcError("execution reverted");
                return result;
            }
            case "eth_estimateGas":
                if (options.sendError) throw rpcError(options.sendError);
                return "0x5208";
            case "eth_gasPrice":
                return "0x3b9aca00";
            case "eth_maxPriorityFeePerGas":
                return "0x3b9aca00";
            case "eth_getBlockByNumber":
                return { number: "0x1", baseFeePerGas: "0x3b9aca00", timestamp: "0x1", transactions: [] };
            case "eth_feeHistory":
                return {
                    oldestBlock: "0x1",
                    baseFeePerGas: ["0x3b9aca00", "0x3b9aca00"],
                    gasUsedRatio: [0.5],
                    reward: [["0x3b9aca00"]],
                };
            case "eth_getTransactionCount":
                return "0x0";
            case "eth_sendRawTransaction": {
                if (options.sendError) throw rpcError(options.sendError);
                const raw = first as Hex;
                sent.push(raw);
                return keccak256(raw);
            }
            case "eth_getTransactionReceipt":
                return {
                    transactionHash: first,
                    blockHash: keccak256("0x01"),
                    blockNumber: "0x1",
                    transactionIndex: "0x0",
                    from: account?.address,
                    to: "0x0000000000000000000000000000000000000001",
                    cumulativeGasUsed: "0x5208",
                    gasUsed: "0x5208",
                    effectiveGasPrice: "0x3b9aca00",
                    contractAddress: null,
                    logs: (options.logs ?? []).map((log, i) => ({
                        ...log,
                        blockHash: keccak256("0x01"),
                        blockNumber: "0x1",
                        transactionHash: first,
                        transactionIndex: "0x0",
                        logIndex: toHex(i),
                        removed: false,
                    })),
                    logsBloom: `0x${"00".repeat(256)}`,
                    status: options.status === "reverted" ? "0x0" : "0x1",
                    type: "0x2",
                };
            default:
                throw rpcError(`unsupported method ${method}`);
        }
    };

    const client = createWalletClient({
        account,
        chain: foundry,
        transport: custom({ request: request as never }),
    }) as Client;
    return { client, sent, calls };
}

function rpcError(message: string): Error {
    return Object.assign(new Error(message), { code: -32000, details: message });
}

/**
 * Builds a `call` handler from per-function responders: decodes the calldata with `abi`, finds the
 * responder for the function name and ABI-encodes what it returns.
 */
export function abiResponder(
    abi: Abi,
    responders: Record<string, (args: readonly unknown[], to: Address) => unknown>,
): NonNullable<FakeChainOptions["call"]> {
    return (to, data) => {
        const decoded = decodeFunctionData({ abi, data });
        const responder = responders[decoded.functionName];
        if (!responder) return undefined;
        return encodeFunctionResult({
            abi,
            functionName: decoded.functionName,
            result: responder(decoded.args ?? [], to) as never,
        } as never);
    };
}
