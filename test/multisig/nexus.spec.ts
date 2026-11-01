import {
    concat,
    decodeAbiParameters,
    decodeFunctionData,
    encodeAbiParameters,
    encodeEventTopics,
    getAddress,
    keccak256,
    pad,
    parseAbiParameters,
    toHex,
    type Abi,
    type Address,
    type Hex,
} from "viem";
import { entryPoint07Abi } from "viem/account-abstraction";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ChainStateError, InvalidArgumentError } from "../../src/errors.js";
import { createMultiSigState, type MultiSigConfig } from "../../src/zk-multisig/index.js";
import {
    DEFAULT_GAS,
    ENTRY_POINT_V07,
    MODULE_TYPE_VALIDATOR,
    computeNexusAccountAddress,
    createNexusAccount,
    describeEntryPointError,
    encodeExecuteCallData,
    encodeHandleOps,
    encodeInstallValidatorCall,
    encodeUpdateStateRootCall,
    encodeValidatorInitData,
    encodeValidatorNonceKey,
    getNexusAccountStatus,
    getNexusNonce,
    getNexusUserOperationHash,
    getValidatorStateRoot,
    nexusAccountAbi,
    prepareNexusUserOperation,
    sendNexusUserOperation,
    zkMultiSigValidatorAbi,
    zkMultiSigValidatorFactoryAbi,
    type NexusUserOperation,
} from "../../src/zk-multisig/nexus.js";
import { loadContract } from "../onchain/harness.js";
import { ADDRESSES, testAccounts } from "../helpers.js";
import { abiResponder, createFakeChain } from "./fake-chain.js";

const SALT = 0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefn;
const account: Address = "0x4444444444444444444444444444444444444444";
const validator: Address = "0x5555555555555555555555555555555555555555";
const factory: Address = "0x6666666666666666666666666666666666666666";
const owners = testAccounts(3, "nexus-unit");
const config: MultiSigConfig = { signers: owners.map((a) => a.address), threshold: 2, salt: SALT };
const state = createMultiSigState(config);
const abi = [
    ...nexusAccountAbi,
    ...zkMultiSigValidatorAbi,
    ...zkMultiSigValidatorFactoryAbi,
    ...entryPoint07Abi,
] as Abi;

const operation: NexusUserOperation = {
    sender: account,
    nonce: 5n,
    callData: "0xdeadbeef",
    callGasLimit: 111n,
    verificationGasLimit: 222n,
    preVerificationGas: 333n,
    maxFeePerGas: 444n,
    maxPriorityFeePerGas: 55n,
    signature: "0x",
};

afterEach(() => {
    vi.doUnmock("../../src/zk-multisig/prove.js");
    vi.resetModules();
});

describe("encodeExecuteCallData", () => {
    it("is ERC-7579 execute(mode 0, to ‖ value ‖ data)", () => {
        const data = encodeExecuteCallData({ to: ADDRESSES[1], value: 1000n, data: "0xcafebabe" });
        const decoded = decodeFunctionData({ abi: nexusAccountAbi, data });
        expect(data.slice(0, 10)).toBe("0xe9ae5c53");
        expect(decoded.functionName).toBe("execute");
        const [mode, execution] = decoded.args as [Hex, Hex];
        expect(mode).toBe(`0x${"00".repeat(32)}`);
        expect(execution).toBe(concat([ADDRESSES[1], pad(toHex(1000n), { size: 32 }), "0xcafebabe"]).toLowerCase());
    });

    it("defaults to a zero-value call without data", () => {
        const [, execution] = decodeFunctionData({
            abi: nexusAccountAbi,
            data: encodeExecuteCallData({ to: ADDRESSES[1] }),
        }).args as [Hex, Hex];
        expect(execution).toBe(concat([ADDRESSES[1], pad("0x00", { size: 32 })]).toLowerCase());
    });

    it.each([
        ["an invalid target", { to: "0x12" as Address }],
        ["a negative value", { to: ADDRESSES[1], value: -1n }],
        ["a value above uint256", { to: ADDRESSES[1], value: 1n << 256n }],
        ["malformed data", { to: ADDRESSES[1], data: "0xabc" as Hex }],
    ])("rejects %s", (_name, call) => {
        expect(() => encodeExecuteCallData(call)).toThrow(InvalidArgumentError);
    });
});

describe("validator calls", () => {
    it("encodes the init data as abi.encode(bytes32, bytes)", () => {
        const initData = encodeValidatorInitData(state.stateRoot, "0xabcd");
        const [root, proof] = decodeAbiParameters(parseAbiParameters("bytes32, bytes"), initData);
        expect([BigInt(root), proof]).toEqual([state.stateRoot, "0xabcd"]);
        expect(encodeValidatorInitData(toHex(state.stateRoot), "0xabcd")).toBe(initData);
        expect(() => encodeValidatorInitData(1n << 255n, "0xab")).toThrow(InvalidArgumentError);
        expect(() => encodeValidatorInitData(1n, "0xabc" as Hex)).toThrow(InvalidArgumentError);
    });

    it("encodeInstallValidatorCall targets the account's installModule", () => {
        const call = encodeInstallValidatorCall({
            account,
            validator,
            stateRoot: state.stateRoot,
            stateValidationProof: "0xabcd",
        });
        expect(call.to).toBe(account);
        expect(call.value).toBe(0n);
        expect(decodeFunctionData({ abi: nexusAccountAbi, data: call.data }).args).toEqual([
            MODULE_TYPE_VALIDATOR,
            validator,
            encodeValidatorInitData(state.stateRoot, "0xabcd"),
        ]);
        expect(() =>
            encodeInstallValidatorCall({
                account: "0x1" as Address,
                validator,
                stateRoot: 1n,
                stateValidationProof: "0xab",
            }),
        ).toThrow(InvalidArgumentError);
        expect(() =>
            encodeInstallValidatorCall({
                account,
                validator: "0x1" as Address,
                stateRoot: 1n,
                stateValidationProof: "0xab",
            }),
        ).toThrow(InvalidArgumentError);
    });

    it("encodeUpdateStateRootCall targets the validator's updateStateRoot", () => {
        const call = encodeUpdateStateRootCall({
            validator,
            newStateRoot: state.stateRoot,
            stateValidationProof: "0xabcd",
        });
        expect(call.to).toBe(validator);
        expect(decodeFunctionData({ abi: zkMultiSigValidatorAbi, data: call.data })).toEqual({
            functionName: "updateStateRoot",
            args: [toHex(state.stateRoot, { size: 32 }), "0xabcd"],
        });
        expect(() =>
            encodeUpdateStateRootCall({ validator: "0x1" as Address, newStateRoot: 1n, stateValidationProof: "0xab" }),
        ).toThrow(InvalidArgumentError);
        expect(() => encodeUpdateStateRootCall({ validator, newStateRoot: -1n, stateValidationProof: "0xab" })).toThrow(
            InvalidArgumentError,
        );
    });

    it("the nonce key is the validator address (Nexus nonce layout: 3 empty bytes, mode 0, validator, sequence)", () => {
        expect(encodeValidatorNonceKey(validator)).toBe(BigInt(validator));
        expect(() => encodeValidatorNonceKey("0x1" as Address)).toThrow(InvalidArgumentError);
    });
});

// ERC-4337 v0.7: keccak(abi.encode(keccak(abi.encode(sender, nonce, keccak(initCode), keccak(callData),
// accountGasLimits, preVerificationGas, gasFees, keccak(paymasterAndData))), entryPoint, chainId)).
function referenceUserOpHash(op: NexusUserOperation, entryPoint: Address, chainId: bigint): Hex {
    const pack = (high: bigint, low: bigint) => concat([pad(toHex(high), { size: 16 }), pad(toHex(low), { size: 16 })]);
    const inner = keccak256(
        encodeAbiParameters(
            parseAbiParameters("address, uint256, bytes32, bytes32, bytes32, uint256, bytes32, bytes32"),
            [
                op.sender,
                op.nonce,
                keccak256("0x"),
                keccak256(op.callData),
                pack(op.verificationGasLimit, op.callGasLimit),
                op.preVerificationGas,
                pack(op.maxPriorityFeePerGas, op.maxFeePerGas),
                keccak256("0x"),
            ],
        ),
    );
    return keccak256(
        encodeAbiParameters(parseAbiParameters("bytes32, address, uint256"), [inner, entryPoint, chainId]),
    );
}

describe("UserOperation hash", () => {
    it("equals an independent EntryPoint v0.7 implementation", () => {
        for (const chainId of [1n, 137n, 31337n]) {
            expect(getNexusUserOperationHash(operation, chainId, ADDRESSES[2])).toBe(
                referenceUserOpHash(operation, ADDRESSES[2], chainId),
            );
        }
        expect(getNexusUserOperationHash(operation, 1)).toBe(referenceUserOpHash(operation, ENTRY_POINT_V07, 1n));
    });

    it("ignores the signature but binds every other field", () => {
        const base = getNexusUserOperationHash(operation, 1);
        expect(getNexusUserOperationHash({ ...operation, signature: "0xdead" }, 1)).toBe(base);
        for (const patch of [
            { nonce: 6n },
            { callData: "0x00" as Hex },
            { callGasLimit: 1n },
            { verificationGasLimit: 1n },
            { preVerificationGas: 1n },
            { maxFeePerGas: 1n },
            { maxPriorityFeePerGas: 1n },
            { sender: ADDRESSES[3] },
        ]) {
            expect(getNexusUserOperationHash({ ...operation, ...patch }, 1)).not.toBe(base);
        }
        expect(getNexusUserOperationHash(operation, 2)).not.toBe(base);
    });
});

describe("encodeHandleOps", () => {
    it("packs the operations for handleOps", () => {
        const data = encodeHandleOps([operation, { ...operation, nonce: 6n }], ADDRESSES[1]);
        const decoded = decodeFunctionData({ abi: entryPoint07Abi, data });
        expect(decoded.functionName).toBe("handleOps");
        const [ops, beneficiary] = decoded.args as unknown as [
            { sender: Address; nonce: bigint; callData: Hex }[],
            Address,
        ];
        expect(ops.map((o) => o.nonce)).toEqual([5n, 6n]);
        expect(ops[0].sender).toBe(getAddress(account));
        expect(beneficiary).toBe(ADDRESSES[1]);
        expect(() => encodeHandleOps([operation], "0x1" as Address)).toThrow(InvalidArgumentError);
    });
});

describe("reads", () => {
    const status = (over: Partial<{ installed: boolean; initialized: boolean; root: bigint }> = {}) =>
        createFakeChain(undefined, {
            call: abiResponder(abi, {
                isModuleInstalled: () => over.installed ?? true,
                isInitialized: () => over.initialized ?? true,
                getStateRoot: () => toHex(over.root ?? state.stateRoot, { size: 32 }),
                entryPoint: () => ENTRY_POINT_V07,
            }),
        });

    it("getNexusAccountStatus combines installation, initialisation, root and entry point", async () => {
        const { client, calls } = status();
        expect(await getNexusAccountStatus(client, { account, validator })).toEqual({
            installed: true,
            initialized: true,
            stateRoot: state.stateRoot,
            entryPoint: getAddress(ENTRY_POINT_V07),
        });
        expect(calls).toHaveLength(4);
        await expect(getNexusAccountStatus(client, { account: "0x1" as Address, validator })).rejects.toThrow(
            InvalidArgumentError,
        );
        await expect(getNexusAccountStatus(client, { account, validator: "0x1" as Address })).rejects.toThrow(
            InvalidArgumentError,
        );
    });

    it("getValidatorStateRoot refuses an account without the validator, or an uninitialised one", async () => {
        expect(await getValidatorStateRoot(status().client, { account, validator })).toBe(state.stateRoot);
        await expect(
            getValidatorStateRoot(status({ installed: false }).client, { account, validator }),
        ).rejects.toThrow(/not installed/);
        await expect(
            getValidatorStateRoot(status({ initialized: false }).client, { account, validator }),
        ).rejects.toThrow(/not initialised/);
        await expect(
            getValidatorStateRoot(status({ installed: false }).client, { account, validator }),
        ).rejects.toThrow(ChainStateError);
    });

    it("getNexusNonce reads the EntryPoint with the validator as nonce key", async () => {
        let seen: readonly unknown[] = [];
        const { client, calls } = createFakeChain(undefined, {
            call: abiResponder(abi, { getNonce: (args) => ((seen = args), 42n) }),
        });
        expect(await getNexusNonce(client, { account, validator })).toBe(42n);
        expect(seen).toEqual([getAddress(account), BigInt(validator)]);
        expect(calls[0].to.toLowerCase()).toBe(ENTRY_POINT_V07.toLowerCase());
        await getNexusNonce(client, { account, validator, entryPoint: ADDRESSES[4] });
        expect(calls[1].to.toLowerCase()).toBe(ADDRESSES[4].toLowerCase());
        await expect(getNexusNonce(client, { account: "0x1" as Address, validator })).rejects.toThrow(
            InvalidArgumentError,
        );
    });
});

describe("account creation", () => {
    const created = (address: Address) => {
        const [topic0, accountTopic, rootTopic] = encodeEventTopics({
            abi: zkMultiSigValidatorFactoryAbi,
            eventName: "ZKMultiSigAccountCreated",
            args: { account: address, stateRoot: toHex(state.stateRoot, { size: 32 }) },
        });
        return {
            address: factory,
            topics: [topic0, accountTopic as Hex, rootTopic as Hex],
            data: pad("0x00", { size: 32 }),
        };
    };
    const call = abiResponder(abi, { computeAccountAddress: () => ADDRESSES[6] });
    const params = { factory, stateRoot: state.stateRoot, stateValidationProof: "0xabcd" as Hex };

    it("computeNexusAccountAddress asks the factory with the root, proof and index", async () => {
        let seen: readonly unknown[] = [];
        const { client } = createFakeChain(undefined, {
            call: abiResponder(abi, { computeAccountAddress: (args) => ((seen = args), ADDRESSES[6]) }),
        });
        expect(await computeNexusAccountAddress(client, { ...params, index: 3n })).toBe(getAddress(ADDRESSES[6]));
        expect(seen).toEqual([toHex(state.stateRoot, { size: 32 }), "0xabcd", 3n]);
        await expect(computeNexusAccountAddress(client, { ...params, stateValidationProof: "0x" })).rejects.toThrow(
            /must not be empty/,
        );
        await expect(computeNexusAccountAddress(client, { ...params, factory: "0x1" as Address })).rejects.toThrow(
            InvalidArgumentError,
        );
        await expect(
            computeNexusAccountAddress(client, { ...params, stateValidationProof: "0xabc" as Hex }),
        ).rejects.toThrow(InvalidArgumentError);
    });

    it("createNexusAccount sends createAccount and returns the predicted address", async () => {
        const { client, sent } = createFakeChain(owners[0], { call, logs: [created(ADDRESSES[6])] });
        const result = await createNexusAccount(client, params);
        expect(result.account).toBe(getAddress(ADDRESSES[6]));
        expect(sent).toHaveLength(1);
        expect(result.transactionHash).toBe(keccak256(sent[0]));
    });

    it("createNexusAccount is idempotent: no event (already deployed) still returns the account", async () => {
        const { client } = createFakeChain(owners[0], { call, logs: [] });
        expect((await createNexusAccount(client, params)).account).toBe(getAddress(ADDRESSES[6]));
    });

    it("createNexusAccount fails if the factory deployed somewhere else than predicted", async () => {
        const { client } = createFakeChain(owners[0], { call, logs: [created(ADDRESSES[7])] });
        await expect(createNexusAccount(client, params)).rejects.toThrow(/was predicted/);
    });

    it("createNexusAccount ignores unrelated logs and needs an account", async () => {
        const unrelated = { address: factory, topics: [keccak256("0x01")] as Hex[], data: "0x" as Hex };
        const { client } = createFakeChain(owners[0], { call, logs: [unrelated] });
        expect((await createNexusAccount(client, params)).account).toBe(getAddress(ADDRESSES[6]));

        const anonymous = createFakeChain(undefined, { call });
        await expect(createNexusAccount(anonymous.client, params)).rejects.toThrow(/needs a client with an account/);
        const named = createFakeChain(undefined, { call });
        await expect(createNexusAccount(named.client, { ...params, account: owners[0] })).resolves.toBeDefined();
    });
});

describe("prepareNexusUserOperation", () => {
    const call = { to: ADDRESSES[1], value: 1n };
    const reads = abiResponder(abi, { getNonce: () => 9n });

    it("builds an unsigned operation with the supplied fees and the nonce from the EntryPoint", async () => {
        const { client } = createFakeChain(undefined, { chainId: 137, call: reads });
        const prepared = await prepareNexusUserOperation(client, {
            account,
            validator,
            call,
            maxFeePerGas: 100n,
            maxPriorityFeePerGas: 10n,
        });
        expect(prepared.entryPoint).toBe(ENTRY_POINT_V07);
        expect(prepared.userOperation).toEqual({
            sender: account,
            nonce: 9n,
            callData: encodeExecuteCallData(call),
            callGasLimit: DEFAULT_GAS.callGasLimit,
            verificationGasLimit: DEFAULT_GAS.verificationGasLimit,
            preVerificationGas: DEFAULT_GAS.preVerificationGas,
            maxFeePerGas: 100n,
            maxPriorityFeePerGas: 10n,
            signature: "0x",
        });
        expect(prepared.userOperationHash).toBe(getNexusUserOperationHash(prepared.userOperation, 137n));
    });

    it("honours overrides and an explicit entry point and nonce", async () => {
        const { client, calls } = createFakeChain(undefined, { call: reads });
        const prepared = await prepareNexusUserOperation(client, {
            account,
            validator,
            call,
            entryPoint: ADDRESSES[4],
            nonce: 77n,
            callGasLimit: 1n,
            verificationGasLimit: 2n,
            preVerificationGas: 3n,
            maxFeePerGas: 100n,
            maxPriorityFeePerGas: 10n,
        });
        expect(prepared.userOperation).toMatchObject({
            nonce: 77n,
            callGasLimit: 1n,
            verificationGasLimit: 2n,
            preVerificationGas: 3n,
        });
        expect(prepared.entryPoint).toBe(ADDRESSES[4]);
        expect(calls).toHaveLength(0); // nonce supplied: no EntryPoint read
        expect(prepared.userOperationHash).toBe(
            getNexusUserOperationHash(prepared.userOperation, 31337n, ADDRESSES[4]),
        );
    });

    it("estimates the fees from the network when they are not supplied", async () => {
        const { client } = createFakeChain(undefined, { call: reads });
        const { userOperation } = await prepareNexusUserOperation(client, { account, validator, call });
        expect(userOperation.maxFeePerGas).toBeGreaterThan(0n);
        expect(userOperation.maxPriorityFeePerGas).toBeGreaterThan(0n);
        expect(userOperation.maxFeePerGas).toBeGreaterThanOrEqual(userOperation.maxPriorityFeePerGas);
    });

    it("validates the account and the call", async () => {
        const { client } = createFakeChain(undefined, { call: reads });
        const fees = { maxFeePerGas: 1n, maxPriorityFeePerGas: 1n };
        await expect(
            prepareNexusUserOperation(client, { account: "0x1" as Address, validator, call, ...fees }),
        ).rejects.toThrow(InvalidArgumentError);
        await expect(
            prepareNexusUserOperation(client, { account, validator, call: { to: "0x1" as Address }, ...fees }),
        ).rejects.toThrow(InvalidArgumentError);
    });
});

describe("generateNexusUserOperationProof", () => {
    it("proves against the validator's on-chain root and installs the proof as the signature", async () => {
        vi.resetModules();
        const generateMultiSigProof = vi
            .fn()
            .mockResolvedValue({ proof: "0xfeedface", publicInputs: [], txnHash: "0x", stateRoot: "0x" });
        vi.doMock("../../src/zk-multisig/prove.js", () => ({ generateMultiSigProof }));
        const nexus = await import("../../src/zk-multisig/nexus.js");

        const { client } = createFakeChain(undefined, {
            chainId: 137,
            call: abiResponder(abi, {
                isModuleInstalled: () => true,
                isInitialized: () => true,
                getStateRoot: () => toHex(state.stateRoot, { size: 32 }),
                entryPoint: () => ENTRY_POINT_V07,
            }),
        });
        const signatures: Hex[] = ["0x01", "0x02"];
        const circuit = { bytecode: "AAAA" };
        const options = { verify: false };

        const result = await nexus.generateNexusUserOperationProof(client, {
            userOperation: operation,
            validator,
            signatures,
            config,
            circuit,
            options,
            entryPoint: ADDRESSES[4],
        });

        const hash = getNexusUserOperationHash(operation, 137n, ADDRESSES[4]);
        expect(result.userOperationHash).toBe(hash);
        expect(generateMultiSigProof).toHaveBeenCalledWith(config, hash, signatures, state.stateRoot, circuit, options);
        expect(result.userOperation).toEqual({ ...operation, signature: "0xfeedface" });
        expect(result.proof.proof).toBe("0xfeedface");
    });
});

describe("sendNexusUserOperation", () => {
    const userOpEvent = (success: boolean) => {
        const [topic0, ...topics] = encodeEventTopics({
            abi: entryPoint07Abi,
            eventName: "UserOperationEvent",
            args: { userOpHash: keccak256("0x01"), sender: account, paymaster: ADDRESSES[0] },
        });
        return {
            address: ENTRY_POINT_V07,
            topics: [topic0, ...topics] as Hex[],
            data: encodeAbiParameters(parseAbiParameters("uint256, bool, uint256, uint256"), [5n, success, 1n, 1n]),
        };
    };
    const revertReason = () => {
        const [topic0, ...topics] = encodeEventTopics({
            abi: entryPoint07Abi,
            eventName: "UserOperationRevertReason",
            args: { userOpHash: keccak256("0x01"), sender: account },
        });
        return {
            address: ENTRY_POINT_V07,
            topics: [topic0, ...topics] as Hex[],
            data: encodeAbiParameters(parseAbiParameters("uint256, bytes"), [5n, "0x08c379a0"]),
        };
    };

    it("submits handleOps and reports the account's execution result", async () => {
        const { client, sent } = createFakeChain(owners[0], { logs: [userOpEvent(true)] });
        const result = await sendNexusUserOperation(client, { userOperation: operation });
        expect(result.success).toBe(true);
        expect(result.revertReason).toBeUndefined();
        expect(result.transactionHash).toBe(keccak256(sent[0]));
        expect(result.userOperationHash).toBe(getNexusUserOperationHash(operation, 31337n));
    });

    it("reports an execution that reverted inside the account, with the revert data", async () => {
        const { client } = createFakeChain(owners[0], { logs: [userOpEvent(false), revertReason()] });
        const result = await sendNexusUserOperation(client, { userOperation: operation });
        expect(result.success).toBe(false);
        expect(result.revertReason).toBe("0x08c379a0");
    });

    it("falls back to the receipt status when no UserOperationEvent is present", async () => {
        const ok = await sendNexusUserOperation(createFakeChain(owners[0]).client, { userOperation: operation });
        expect(ok.success).toBe(true);
        const bad = await sendNexusUserOperation(createFakeChain(owners[0], { status: "reverted" }).client, {
            userOperation: operation,
        });
        expect(bad.success).toBe(false);
    });

    it("explains EntryPoint validation failures", async () => {
        const { client } = createFakeChain(owners[0], {
            sendError: "execution reverted: FailedOp(0, AA24 signature error)",
        });
        const error = await sendNexusUserOperation(client, { userOperation: operation }).catch((e) => e);
        expect(error).toBeInstanceOf(ChainStateError);
        expect((error as Error).message).toMatch(/^AA24: signature error — the ZK proof was rejected/);
        expect((error as ChainStateError).cause).toBeInstanceOf(Error);
    });

    it("rethrows failures that are not EntryPoint errors, and needs an account", async () => {
        const { client } = createFakeChain(owners[0], { sendError: "insufficient funds" });
        await expect(sendNexusUserOperation(client, { userOperation: operation })).rejects.toThrow(
            /insufficient funds/,
        );
        await expect(
            sendNexusUserOperation(createFakeChain(undefined).client, { userOperation: operation }),
        ).rejects.toThrow(/needs a client with an account/);
    });

    it("accepts an explicit account, beneficiary and gas", async () => {
        const { client, sent } = createFakeChain(owners[0]);
        await sendNexusUserOperation(client, {
            userOperation: operation,
            account: owners[1],
            beneficiary: ADDRESSES[2],
            gas: 12_000_000n,
        });
        expect(sent).toHaveLength(1);
    });
});

describe("describeEntryPointError", () => {
    it.each([
        ["FailedOp(0, AA24 signature error)", "AA24"],
        ["AA25 invalid account nonce", "AA25"],
        ["reverted: AA21 didn't pay prefund", "AA21"],
        ["AA99 something unknown", "AA99"],
    ])("finds the code in %s", (message, code) => {
        expect(describeEntryPointError(new Error(message))?.code).toBe(code);
    });

    it("explains known codes and degrades gracefully for unknown ones", () => {
        expect(describeEntryPointError(new Error("AA25"))?.description).toMatch(/invalid account nonce/);
        expect(describeEntryPointError(new Error("AA21"))?.description).toMatch(/prefund/);
        expect(describeEntryPointError(new Error("AA99"))?.description).toMatch(/error codes/);
    });

    it("reads viem's details and shortMessage, and non-Error values", () => {
        expect(describeEntryPointError(Object.assign(new Error("boom"), { details: "AA23 reverted" }))?.code).toBe(
            "AA23",
        );
        expect(describeEntryPointError(Object.assign(new Error("boom"), { shortMessage: "AA26 over" }))?.code).toBe(
            "AA26",
        );
        expect(describeEntryPointError("AA10 sender already constructed")?.code).toBe("AA10");
        expect(describeEntryPointError(new Error("nothing here"))).toBeUndefined();
        expect(describeEntryPointError(undefined)).toBeUndefined();
        expect(describeEntryPointError(new Error("AAA24 AA244 aa24"))).toBeUndefined();
    });
});

describe("ABI conformance with the compiled contracts", () => {
    type Item = {
        type: string;
        name?: string;
        inputs?: { type: string; components?: unknown }[];
        outputs?: { type: string }[];
    };
    const sig = (i: Item) => `${i.type} ${i.name}(${(i.inputs ?? []).map((x) => x.type).join(",")})`;

    const conforms = (sdk: Abi, fixture: string) => {
        const compiled = new Set((loadContract(fixture).abi as unknown as Item[]).map(sig));
        for (const item of sdk as unknown as Item[]) {
            if (item.type !== "function" && item.type !== "event") continue;
            expect(compiled.has(sig(item)), `${fixture} has ${sig(item)}`).toBe(true);
        }
    };

    it("the validator", () => {
        conforms(zkMultiSigValidatorAbi as Abi, "ZKMultiSigValidator");
    });

    it("the account factory", () => {
        conforms(zkMultiSigValidatorFactoryAbi as Abi, "ZKMultiSigValidatorFactory");
    });
});
