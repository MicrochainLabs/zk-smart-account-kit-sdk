/**
 * Nexus (ERC-7579) integration for ZK MultiSig accounts (`zk-smart-account-kit-sdk/zk-multisig/nexus`).
 *
 * A Nexus smart account uses `ZKMultiSigValidator` as its validator module: the UserOperation
 * signature is the ZK proof, verified against the account's state root. This module builds on viem
 * only — no Hardhat — and works with any viem client and any ERC-4337 EntryPoint v0.7.
 *
 * Flow:
 *   1. {@link createNexusAccount} — deploy the account with the validator and a state-validation proof.
 *   2. Per transaction: {@link prepareNexusUserOperation}; signers sign the returned
 *      `userOperationHash` with `account.sign({ hash })`; {@link generateNexusUserOperationProof}
 *      produces the signed UserOperation; {@link sendNexusUserOperation} submits it
 *      (or hand `userOperation` to a bundler).
 */

import {
    concat,
    decodeEventLog,
    encodeAbiParameters,
    encodeFunctionData,
    pad,
    parseAbi,
    parseEventLogs,
    toHex,
    type Account,
    type Address,
    type Chain,
    type Client,
    type Hex,
} from "viem";
import {
    entryPoint07Abi,
    entryPoint07Address,
    getUserOperationHash,
    toPackedUserOperation,
    type UserOperation,
} from "viem/account-abstraction";
import { estimateFeesPerGas, getChainId, readContract, waitForTransactionReceipt, writeContract } from "viem/actions";
import { ChainStateError, InvalidArgumentError } from "../errors.js";
import type { ProveOptions } from "../internal/prover.js";
import { assertAddress, assertHex, toFieldElement } from "../internal/validation.js";
import { generateMultiSigProof } from "./prove.js";
import { fieldToBytes32 } from "./state-root.js";
import type { MultiSigConfig, MultiSigProofData } from "./types.js";

const hexConcat = (parts: Hex[]): Hex => concat(parts);

// ─── Constants ────────────────────────────────────────────────────────────────

/** ERC-7579 module type id of validators. */
export const MODULE_TYPE_VALIDATOR = 1n;

/** The canonical ERC-4337 EntryPoint v0.7 (the version Nexus accounts built for the validator use). */
export const ENTRY_POINT_V07: Address = entryPoint07Address;

/** `execute(bytes32 mode, bytes executionCalldata)` of ERC-7579. */
const EXECUTE_SELECTOR: Hex = "0xe9ae5c53";

/** Mode of a single call that reverts on failure: callType 0x00, execType 0x00, rest zero. */
const MODE_SINGLE_REVERT: Hex = `0x${"00".repeat(32)}`;

/**
 * Gas defaults for a UserOperation validated by the ZK validator. On-chain UltraHonk verification is
 * expensive; the limits are deliberately generous. `updateStateRoot` verifies a proof inside the call and
 * needs about 3.7M gas on current EVM versions. Keep `verificationGasLimit + callGasLimit +
 * preVerificationGas` under the 16.7M per-transaction cap of Osaka (EIP-7825).
 */
export const DEFAULT_GAS = {
    verificationGasLimit: 10_000_000n,
    callGasLimit: 5_000_000n,
    preVerificationGas: 300_000n,
} as const;

// ─── ABIs ─────────────────────────────────────────────────────────────────────

/** `ZKMultiSigValidatorFactory` — deploys Nexus accounts with the ZK validator pre-installed. */
export const zkMultiSigValidatorFactoryAbi = parseAbi([
    "function ACCOUNT_IMPLEMENTATION() view returns (address)",
    "function ZK_MULTISIG_VALIDATOR() view returns (address)",
    "function BOOTSTRAPPER() view returns (address)",
    "function createAccount(bytes32 stateRoot, bytes stateValidationProof, uint256 index) payable returns (address account)",
    "function computeAccountAddress(bytes32 stateRoot, bytes stateValidationProof, uint256 index) view returns (address expectedAddress)",
    "event ZKMultiSigAccountCreated(address indexed account, bytes32 indexed stateRoot, uint256 index)",
]);

/** `ZKMultiSigValidator` — the ERC-7579 validator module. */
export const zkMultiSigValidatorAbi = parseAbi([
    "function stateValidator() view returns (address)",
    "function userOpValidator() view returns (address)",
    "function accountStateRoots(address smartAccount) view returns (bytes32)",
    "function getStateRoot(address smartAccount) view returns (bytes32 stateRoot)",
    "function isInitialized(address smartAccount) view returns (bool)",
    "function onInstall(bytes data)",
    "function onUninstall(bytes data)",
    "function updateStateRoot(bytes32 newStateRoot, bytes stateValidationProof)",
    "function validateUserOp((address sender, uint256 nonce, bytes initCode, bytes callData, bytes32 accountGasLimits, uint256 preVerificationGas, bytes32 gasFees, bytes paymasterAndData, bytes signature) userOp, bytes32 userOpHash) returns (uint256)",
    "function isModuleType(uint256 typeId) pure returns (bool)",
    "function name() pure returns (string)",
    "function version() pure returns (string)",
    "event ZKMultiSigConfigured(address indexed smartAccount, bytes32 stateRoot)",
]);

/** The parts of a Nexus account this module uses. */
export const nexusAccountAbi = parseAbi([
    "function entryPoint() view returns (address)",
    "function isModuleInstalled(uint256 moduleTypeId, address module, bytes additionalContext) view returns (bool)",
    "function installModule(uint256 moduleTypeId, address module, bytes initData) payable",
    "function execute(bytes32 mode, bytes executionCalldata) payable",
]);

// ─── Account creation and state ───────────────────────────────────────────────

/** Input shared by the factory calls. */
export interface NexusAccountParams {
    factory: Address;
    stateRoot: bigint | Hex;
    /** Proof from `generateStateValidationProof`. */
    stateValidationProof: Hex;
    /** Salt index: different indices give different accounts for the same state root. Defaults to 0. */
    index?: bigint;
}

function factoryArgs(params: NexusAccountParams): readonly [Hex, Hex, bigint] {
    assertAddress(params.factory, "factory");
    assertHex(params.stateValidationProof, "stateValidationProof");
    if (params.stateValidationProof === "0x") {
        throw new InvalidArgumentError("stateValidationProof must not be empty.");
    }
    return [
        fieldToBytes32(toFieldElement(params.stateRoot, "stateRoot")),
        params.stateValidationProof,
        params.index ?? 0n,
    ];
}

/** The deterministic address of the Nexus account for a state root, proof and index. */
export async function computeNexusAccountAddress(client: Client, params: NexusAccountParams): Promise<Address> {
    return readContract(client, {
        address: params.factory,
        abi: zkMultiSigValidatorFactoryAbi,
        functionName: "computeAccountAddress",
        args: factoryArgs(params),
    });
}

/**
 * Deploys a Nexus account with the ZK validator installed and initialised with `stateRoot`. The
 * validator verifies `stateValidationProof` on-chain, so a root that does not commit to a valid
 * configuration cannot be installed. Idempotent: an existing account is returned unchanged.
 *
 * @param client Wallet client with an account (or pass `params.account`).
 */
export async function createNexusAccount(
    client: Client,
    params: NexusAccountParams & { account?: Account | Address; chain?: Chain | null },
): Promise<{ account: Address; transactionHash: Hex }> {
    const args = factoryArgs(params);
    const sender = params.account ?? client.account;
    if (sender === undefined) {
        throw new InvalidArgumentError("createNexusAccount needs a client with an account, or params.account.");
    }

    const predicted = await computeNexusAccountAddress(client, params);
    const transactionHash = await writeContract(client, {
        address: params.factory,
        abi: zkMultiSigValidatorFactoryAbi,
        functionName: "createAccount",
        args,
        account: sender,
        chain: params.chain ?? client.chain,
    });
    const receipt = await waitForTransactionReceipt(client, { hash: transactionHash });

    for (const log of receipt.logs) {
        try {
            const event = decodeEventLog({
                abi: zkMultiSigValidatorFactoryAbi,
                data: log.data,
                topics: log.topics,
            });
            if (event.eventName === "ZKMultiSigAccountCreated" && event.args.account !== predicted) {
                throw new ChainStateError(`The factory deployed ${event.args.account} but ${predicted} was predicted.`);
            }
        } catch (error) {
            if (error instanceof ChainStateError) throw error;
        }
    }
    return { account: predicted, transactionHash };
}

/** The validator's view of a Nexus account. */
export interface NexusAccountStatus {
    /** The validator module is installed on the account. */
    installed: boolean;
    /** The validator holds a state root for the account. */
    initialized: boolean;
    /** The account's state root (0 when not initialised). */
    stateRoot: bigint;
    /** The EntryPoint the account is bound to (immutable). */
    entryPoint: Address;
}

/** Reads the account's validator state in one call. */
export async function getNexusAccountStatus(
    client: Client,
    params: { account: Address; validator: Address },
): Promise<NexusAccountStatus> {
    assertAddress(params.account, "account");
    assertAddress(params.validator, "validator");
    const [installed, initialized, stateRoot, entryPoint] = await Promise.all([
        readContract(client, {
            address: params.account,
            abi: nexusAccountAbi,
            functionName: "isModuleInstalled",
            args: [MODULE_TYPE_VALIDATOR, params.validator, "0x"],
        }),
        readContract(client, {
            address: params.validator,
            abi: zkMultiSigValidatorAbi,
            functionName: "isInitialized",
            args: [params.account],
        }),
        readContract(client, {
            address: params.validator,
            abi: zkMultiSigValidatorAbi,
            functionName: "getStateRoot",
            args: [params.account],
        }),
        readContract(client, { address: params.account, abi: nexusAccountAbi, functionName: "entryPoint" }),
    ]);
    return { installed, initialized, stateRoot: BigInt(stateRoot), entryPoint };
}

/**
 * Reads the state root the validator holds for `account`.
 *
 * @throws {ChainStateError} if the validator is not initialised for the account.
 */
export async function getValidatorStateRoot(
    client: Client,
    params: { account: Address; validator: Address },
): Promise<bigint> {
    const status = await getNexusAccountStatus(client, params);
    if (!status.installed) {
        throw new ChainStateError(`The ZK validator ${params.validator} is not installed on ${params.account}.`);
    }
    if (!status.initialized) {
        throw new ChainStateError(`The ZK validator ${params.validator} is not initialised for ${params.account}.`);
    }
    return status.stateRoot;
}

// ─── Calls (executed by the account itself) ───────────────────────────────────

/** A call the account executes. */
export interface NexusCall {
    to: Address;
    value?: bigint;
    data?: Hex;
}

/**
 * ERC-7579 `execute` calldata for a single call that reverts on failure. This is the `callData` of a
 * UserOperation.
 */
export function encodeExecuteCallData(call: NexusCall): Hex {
    assertAddress(call.to, "to");
    const value = call.value ?? 0n;
    if (typeof value !== "bigint" || value < 0n || value >= 1n << 256n) {
        throw new InvalidArgumentError("value must be a non-negative uint256 bigint.");
    }
    const data = call.data ?? "0x";
    assertHex(data, "data");

    const executionCalldata = hexConcat([call.to, pad(toHex(value), { size: 32 }), data]);
    return hexConcat([
        EXECUTE_SELECTOR,
        encodeAbiParameters(
            [
                { name: "mode", type: "bytes32" },
                { name: "executionCalldata", type: "bytes" },
            ],
            [MODE_SINGLE_REVERT, executionCalldata],
        ),
    ]);
}

/**
 * The `initData` of the validator: `abi.encode(bytes32 stateRoot, bytes stateValidationProof)`. It is
 * what `installModule` forwards to the validator's `onInstall`, and what the factory passes when it
 * creates an account.
 */
export function encodeValidatorInitData(stateRoot: bigint | Hex, stateValidationProof: Hex): Hex {
    assertHex(stateValidationProof, "stateValidationProof");
    return encodeAbiParameters(
        [
            { name: "stateRoot", type: "bytes32" },
            { name: "stateValidationProof", type: "bytes" },
        ],
        [fieldToBytes32(toFieldElement(stateRoot, "stateRoot")), stateValidationProof],
    );
}

/**
 * The call that installs the ZK validator on an existing Nexus account. It must be executed by the
 * account itself (for example in a UserOperation validated by another installed validator).
 */
export function encodeInstallValidatorCall(params: {
    account: Address;
    validator: Address;
    stateRoot: bigint | Hex;
    stateValidationProof: Hex;
}): Required<NexusCall> {
    assertAddress(params.account, "account");
    assertAddress(params.validator, "validator");
    const initData = encodeValidatorInitData(params.stateRoot, params.stateValidationProof);
    return {
        to: params.account,
        value: 0n,
        data: encodeFunctionData({
            abi: nexusAccountAbi,
            functionName: "installModule",
            args: [MODULE_TYPE_VALIDATOR, params.validator, initData],
        }),
    };
}

/**
 * The call that replaces the account's state root (rotating signers, threshold or salt). The new root
 * needs a state-validation proof. Execute it as a UserOperation of the account, authorised by the
 * current configuration.
 */
export function encodeUpdateStateRootCall(params: {
    validator: Address;
    newStateRoot: bigint | Hex;
    stateValidationProof: Hex;
}): Required<NexusCall> {
    assertAddress(params.validator, "validator");
    assertHex(params.stateValidationProof, "stateValidationProof");
    return {
        to: params.validator,
        value: 0n,
        data: encodeFunctionData({
            abi: zkMultiSigValidatorAbi,
            functionName: "updateStateRoot",
            args: [fieldToBytes32(toFieldElement(params.newStateRoot, "newStateRoot")), params.stateValidationProof],
        }),
    };
}

// ─── UserOperations (EntryPoint v0.7) ─────────────────────────────────────────

/** An ERC-4337 v0.7 UserOperation. */
export type NexusUserOperation = UserOperation<"0.7">;

/**
 * The nonce key of the ZK validator: the validator address. Nexus reads the validator from the nonce,
 * laid out as `[3 empty bytes][1 byte validation mode][20 bytes validator][8 bytes sequence]`; with
 * validation mode 0 (the default) the 192-bit EntryPoint nonce key is exactly the validator address.
 */
export function encodeValidatorNonceKey(validator: Address): bigint {
    assertAddress(validator, "validator");
    return BigInt(validator.toLowerCase());
}

/** The account's next nonce for the ZK validator, read from the EntryPoint. */
export async function getNexusNonce(
    client: Client,
    params: { account: Address; validator: Address; entryPoint?: Address },
): Promise<bigint> {
    assertAddress(params.account, "account");
    return readContract(client, {
        address: params.entryPoint ?? ENTRY_POINT_V07,
        abi: entryPoint07Abi,
        functionName: "getNonce",
        args: [params.account, encodeValidatorNonceKey(params.validator)],
    });
}

/** The UserOperation hash the EntryPoint computes and the signers sign (EntryPoint v0.7, offline). */
export function getNexusUserOperationHash(
    userOperation: NexusUserOperation,
    chainId: number | bigint,
    entryPoint: Address = ENTRY_POINT_V07,
): Hex {
    return getUserOperationHash({
        chainId: Number(chainId),
        entryPointAddress: entryPoint,
        entryPointVersion: "0.7",
        userOperation: { ...userOperation, signature: "0x" },
    });
}

/** Input of {@link prepareNexusUserOperation}. */
export interface PrepareNexusUserOperationParams {
    /** The Nexus account (the UserOperation sender). */
    account: Address;
    /** The ZK validator installed on it. */
    validator: Address;
    /** What the account should do. */
    call: NexusCall;
    entryPoint?: Address;
    /** Override the nonce (otherwise read from the EntryPoint). */
    nonce?: bigint;
    verificationGasLimit?: bigint;
    callGasLimit?: bigint;
    preVerificationGas?: bigint;
    /** Defaults to the network's current estimate. */
    maxFeePerGas?: bigint;
    maxPriorityFeePerGas?: bigint;
}

/** A prepared UserOperation and the hash its owners sign. */
export interface PreparedNexusUserOperation {
    /** Unsigned: `signature` is empty until the proof is attached. */
    userOperation: NexusUserOperation;
    /** Every signer signs this 32-byte hash with `account.sign({ hash })` (raw, no message prefix). */
    userOperationHash: Hex;
    entryPoint: Address;
}

/**
 * Builds an unsigned UserOperation for a call and returns the hash the owners must sign. Reads the
 * nonce from the EntryPoint and fee data from the network unless supplied.
 */
export async function prepareNexusUserOperation(
    client: Client,
    params: PrepareNexusUserOperationParams,
): Promise<PreparedNexusUserOperation> {
    assertAddress(params.account, "account");
    const entryPoint = params.entryPoint ?? ENTRY_POINT_V07;
    const callData = encodeExecuteCallData(params.call);

    const [chainId, nonce, fees] = await Promise.all([
        getChainId(client),
        params.nonce ?? getNexusNonce(client, { ...params, entryPoint }),
        params.maxFeePerGas !== undefined && params.maxPriorityFeePerGas !== undefined
            ? Promise.resolve({ maxFeePerGas: params.maxFeePerGas, maxPriorityFeePerGas: params.maxPriorityFeePerGas })
            : estimateFeesPerGas(client),
    ]);

    const userOperation: NexusUserOperation = {
        sender: params.account,
        nonce,
        callData,
        callGasLimit: params.callGasLimit ?? DEFAULT_GAS.callGasLimit,
        verificationGasLimit: params.verificationGasLimit ?? DEFAULT_GAS.verificationGasLimit,
        preVerificationGas: params.preVerificationGas ?? DEFAULT_GAS.preVerificationGas,
        maxFeePerGas: params.maxFeePerGas ?? fees.maxFeePerGas,
        maxPriorityFeePerGas: params.maxPriorityFeePerGas ?? fees.maxPriorityFeePerGas,
        signature: "0x",
    };
    return {
        userOperation,
        userOperationHash: getNexusUserOperationHash(userOperation, chainId, entryPoint),
        entryPoint,
    };
}

/** Output of {@link generateNexusUserOperationProof}. */
export interface NexusUserOperationProof {
    /** The UserOperation with the proof as its signature, ready for the EntryPoint or a bundler. */
    userOperation: NexusUserOperation;
    userOperationHash: Hex;
    proof: MultiSigProofData;
}

/**
 * Proves that `threshold` of the private signers signed the UserOperation and returns it with the
 * proof as its signature. Reads the account's on-chain state root and refuses early if the private
 * configuration does not match it.
 *
 * @param params.signatures Owners' 65-byte signatures of the UserOperation hash.
 * @param params.config     The private configuration (signers, threshold, salt).
 * @param params.circuit    Compiled `zk_multi_sig_ecdsa` artifact.
 * @throws {ChainStateError} if the validator is not installed/initialised, or the configuration does not match its state root.
 */
export async function generateNexusUserOperationProof(
    client: Client,
    params: {
        userOperation: NexusUserOperation;
        validator: Address;
        signatures: readonly Hex[];
        config: MultiSigConfig;
        circuit: unknown;
        entryPoint?: Address;
        options?: ProveOptions;
    },
): Promise<NexusUserOperationProof> {
    const entryPoint = params.entryPoint ?? ENTRY_POINT_V07;
    const chainId = await getChainId(client);
    const userOperationHash = getNexusUserOperationHash(params.userOperation, chainId, entryPoint);
    const stateRoot = await getValidatorStateRoot(client, {
        account: params.userOperation.sender,
        validator: params.validator,
    });

    const proof = await generateMultiSigProof(
        params.config,
        userOperationHash,
        params.signatures,
        stateRoot,
        params.circuit,
        params.options,
    );
    return { userOperation: { ...params.userOperation, signature: proof.proof }, userOperationHash, proof };
}

/** `handleOps` calldata for the EntryPoint. */
export function encodeHandleOps(userOperations: readonly NexusUserOperation[], beneficiary: Address): Hex {
    assertAddress(beneficiary, "beneficiary");
    return encodeFunctionData({
        abi: entryPoint07Abi,
        functionName: "handleOps",
        args: [userOperations.map((op) => toPackedUserOperation(op)), beneficiary],
    });
}

// ─── Submission ───────────────────────────────────────────────────────────────

/** Result of {@link sendNexusUserOperation}. */
export interface SentNexusUserOperation {
    transactionHash: Hex;
    userOperationHash: Hex;
    /** The account's execution succeeded (validation succeeded or `handleOps` would have reverted). */
    success: boolean;
    /** Revert data of the account's execution when `success` is false. */
    revertReason?: Hex;
}

/**
 * Submits a signed UserOperation directly to the EntryPoint (`handleOps`) and waits for the result.
 * Validation failures are reported with the EntryPoint's `AAxx` code and its meaning.
 *
 * @param client Wallet client with an account, which pays gas and receives the bundler fee.
 * @throws {ChainStateError} when the EntryPoint rejects the operation (e.g. AA24 signature error).
 */
export async function sendNexusUserOperation(
    client: Client,
    params: {
        userOperation: NexusUserOperation;
        entryPoint?: Address;
        beneficiary?: Address;
        account?: Account | Address;
        chain?: Chain | null;
        gas?: bigint;
    },
): Promise<SentNexusUserOperation> {
    const entryPoint = params.entryPoint ?? ENTRY_POINT_V07;
    const sender = params.account ?? client.account;
    if (sender === undefined) {
        throw new InvalidArgumentError("sendNexusUserOperation needs a client with an account, or params.account.");
    }
    const beneficiary = params.beneficiary ?? (typeof sender === "string" ? sender : sender.address);
    const chainId = await getChainId(client);
    const userOperationHash = getNexusUserOperationHash(params.userOperation, chainId, entryPoint);

    let transactionHash: Hex;
    try {
        transactionHash = await writeContract(client, {
            address: entryPoint,
            abi: entryPoint07Abi,
            functionName: "handleOps",
            args: [[toPackedUserOperation(params.userOperation)], beneficiary],
            account: sender,
            chain: params.chain ?? client.chain,
            gas: params.gas,
        });
    } catch (error) {
        const failure = describeEntryPointError(error);
        if (failure) {
            throw new ChainStateError(`${failure.code}: ${failure.description}`, error);
        }
        throw error;
    }

    const receipt = await waitForTransactionReceipt(client, { hash: transactionHash });
    const events = parseEventLogs({ abi: entryPoint07Abi, logs: receipt.logs });

    const result = events.find((e) => e.eventName === "UserOperationEvent");
    const revert = events.find((e) => e.eventName === "UserOperationRevertReason");
    return {
        transactionHash,
        userOperationHash,
        success: result?.eventName === "UserOperationEvent" ? result.args.success : receipt.status === "success",
        revertReason: revert?.eventName === "UserOperationRevertReason" ? revert.args.revertReason : undefined,
    };
}

// ─── EntryPoint errors ────────────────────────────────────────────────────────

const ENTRY_POINT_ERRORS: Record<string, string> = {
    AA10: "sender already constructed",
    AA13: "initCode failed or out of gas",
    AA14: "initCode must return the sender address",
    AA15: "initCode must create the sender",
    AA20: "account not deployed",
    AA21: "the account did not pay the prefund — fund the account or use a paymaster",
    AA22: "the UserOperation expired or is not yet valid",
    AA23: "the account validation reverted or ran out of gas",
    AA24: "signature error — the ZK proof was rejected: check that it was generated for this exact UserOperation hash, the account's current state root and the right EntryPoint",
    AA25: "invalid account nonce — another operation was executed after this one was prepared; prepare and sign again",
    AA26: "the account validation exceeded verificationGasLimit — raise it",
    AA30: "paymaster not deployed",
    AA31: "paymaster deposit too low",
    AA32: "paymaster expired or not yet valid",
    AA33: "paymaster validation reverted or ran out of gas",
    AA34: "paymaster signature error",
    AA36: "the paymaster validation exceeded its gas limit",
    AA40: "over verificationGasLimit",
    AA41: "too little verificationGas",
    AA50: "postOp reverted",
    AA51: "prefund below the actual gas cost",
};

/**
 * Extracts the EntryPoint `AAxx` code from an error thrown by a `handleOps` call and explains it.
 * Returns `undefined` when the error does not carry one.
 */
export function describeEntryPointError(error: unknown): { code: string; description: string } | undefined {
    const text =
        error instanceof Error
            ? [
                  error.message,
                  (error as { details?: string }).details,
                  (error as { shortMessage?: string }).shortMessage,
              ]
                  .filter(Boolean)
                  .join(" ")
            : String(error);
    const match = /\bAA\d{2}\b/.exec(text);
    if (!match) return undefined;
    return { code: match[0], description: ENTRY_POINT_ERRORS[match[0]] ?? "see the ERC-4337 EntryPoint error codes" };
}
