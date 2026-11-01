/**
 * Safe integration for ZK MultiSig accounts (`zk-smart-account-kit-sdk/zk-multisig/safe`).
 *
 * A Safe is controlled by a ZK signer: a minimal proxy created by `ZKMultiSigEcdsaFactory` that
 * implements ERC-1271 by verifying a ZK proof against the account's state root. The Safe lists that
 * proxy as an owner, and the proof is submitted as the proxy's contract signature (Safe signature type
 * `v = 0`). This module builds on viem only — no Safe SDK and no Hardhat — and works with any viem client.
 *
 * Flow:
 *   1. {@link createZKSigner} — deploy the ZK signer for a state root (needs a state-validation proof).
 *   2. Deploy a Safe owned by it ({@link encodeSafeSetup}, {@link encodeCreateSafeProxy}).
 *   3. Per transaction: {@link computeSafeTransactionHash}; signers sign it with `account.sign({ hash })`
 *      or {@link signSafeTransaction}; {@link generateSafeTransactionProof} yields the Safe signature;
 *      {@link encodeExecTransaction} (or `writeContract`) executes it.
 */

import {
    concat,
    encodeFunctionData,
    encodePacked,
    getContractAddress,
    hashTypedData,
    keccak256,
    pad,
    parseAbi,
    toHex,
    zeroAddress,
    type Account,
    type Address,
    type Chain,
    type Client,
    type Hex,
    type LocalAccount,
    decodeEventLog,
} from "viem";
import { getChainId, readContract, waitForTransactionReceipt, writeContract } from "viem/actions";
import { ChainStateError, InvalidArgumentError } from "../errors.js";
import type { ProveOptions } from "../internal/prover.js";
import {
    assertAddress,
    assertHex,
    assertHexBytes,
    assertInteger,
    assertNonEmptyArray,
    toFieldElement,
} from "../internal/validation.js";
import { fieldToBytes32 } from "./state-root.js";
import { generateMultiSigProof } from "./prove.js";
import type { MultiSigConfig, MultiSigProofData } from "./types.js";

const hexConcat = (parts: Hex[]): Hex => concat(parts);

// ─── ABIs ─────────────────────────────────────────────────────────────────────

/** `ZKMultiSigEcdsaFactory` — creates ZK signers. */
export const zkMultiSigEcdsaFactoryAbi = parseAbi([
    "function SINGLETON() view returns (address)",
    "function STATE_VALIDATOR() view returns (address)",
    "function getSigner(bytes32 stateRoot, address zkMultiSigEcdsaVerifier) view returns (address signer)",
    "function createSigner(bytes32 stateRoot, address zkMultiSigEcdsaVerifier, bytes privateStateValidationProof) returns (address signer)",
    "function isValidSignatureForSigner(bytes32 message, bytes signature, bytes32 stateRoot, address verifier) view returns (bytes4 magicValue)",
    "event SignerCreated(address indexed signer, bytes32 indexed stateRoot, address indexed zkMultiSigEcdsaVerifier)",
]);

/** A ZK signer proxy (an owner of the Safe). */
export const zkMultiSigEcdsaSignerAbi = parseAbi([
    "function getConfiguration() view returns (bytes32 stateRoot, address verifierAddress)",
    "function isValidSignature(bytes32 hash, bytes signature) view returns (bytes4 magicValue)",
]);

/** The parts of Safe v1.3.0+ this module uses. */
export const safeAbi = parseAbi([
    "function VERSION() view returns (string)",
    "function nonce() view returns (uint256)",
    "function getOwners() view returns (address[])",
    "function getThreshold() view returns (uint256)",
    "function getTransactionHash(address to, uint256 value, bytes data, uint8 operation, uint256 safeTxGas, uint256 baseGas, uint256 gasPrice, address gasToken, address refundReceiver, uint256 _nonce) view returns (bytes32)",
    "function execTransaction(address to, uint256 value, bytes data, uint8 operation, uint256 safeTxGas, uint256 baseGas, uint256 gasPrice, address gasToken, address refundReceiver, bytes signatures) payable returns (bool success)",
    "function setup(address[] _owners, uint256 _threshold, address to, bytes data, address fallbackHandler, address paymentToken, uint256 payment, address paymentReceiver)",
]);

/** `SafeProxyFactory` v1.3.0+. */
export const safeProxyFactoryAbi = parseAbi([
    "function createProxyWithNonce(address _singleton, bytes initializer, uint256 saltNonce) returns (address proxy)",
    "function proxyCreationCode() pure returns (bytes)",
    "event ProxyCreation(address indexed proxy, address singleton)",
]);

/** ERC-1271 magic value returned by `isValidSignature(bytes32,bytes)` on success. */
export const ERC1271_MAGIC_VALUE: Hex = "0x1626ba7e";

/** Canonical Safe v1.4.1 deployment addresses (identical on every chain they are deployed to). */
export const SAFE_V141 = {
    singleton: "0x41675C099F32341bf84BFc5382aF534df5C7461a",
    singletonL2: "0x29fcB43b46531BcA003ddC8FCB67FFE91900C762",
    proxyFactory: "0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67",
    fallbackHandler: "0xfd0732Dc9E303f09fCEf3a7388Ad10A83459Ec99",
} as const satisfies Record<string, Address>;

// ─── Safe transactions ────────────────────────────────────────────────────────

/** A Safe transaction as signed by the owners. */
export interface SafeTransactionData {
    to: Address;
    value: bigint;
    data: Hex;
    /** 0 = CALL, 1 = DELEGATECALL. */
    operation: 0 | 1;
    safeTxGas: bigint;
    baseGas: bigint;
    gasPrice: bigint;
    gasToken: Address;
    refundReceiver: Address;
    nonce: bigint;
}

/** Input of {@link buildSafeTransaction}; everything but `to` and `nonce` has a sensible default. */
export type SafeTransactionInput = Pick<SafeTransactionData, "to" | "nonce"> &
    Partial<Omit<SafeTransactionData, "to" | "nonce">>;

/** Fills the defaults of a Safe transaction (CALL, no value or data, no gas refund) and validates it. */
export function buildSafeTransaction(input: SafeTransactionInput): SafeTransactionData {
    assertAddress(input.to, "to");
    const tx: SafeTransactionData = {
        to: input.to,
        value: input.value ?? 0n,
        data: input.data ?? "0x",
        operation: input.operation ?? 0,
        safeTxGas: input.safeTxGas ?? 0n,
        baseGas: input.baseGas ?? 0n,
        gasPrice: input.gasPrice ?? 0n,
        gasToken: input.gasToken ?? zeroAddress,
        refundReceiver: input.refundReceiver ?? zeroAddress,
        nonce: input.nonce,
    };
    assertHex(tx.data, "data");
    assertAddress(tx.gasToken, "gasToken");
    assertAddress(tx.refundReceiver, "refundReceiver");
    if (tx.operation !== 0 && tx.operation !== 1)
        throw new InvalidArgumentError("operation must be 0 (CALL) or 1 (DELEGATECALL).");
    for (const [name, value] of [
        ["value", tx.value],
        ["safeTxGas", tx.safeTxGas],
        ["baseGas", tx.baseGas],
        ["gasPrice", tx.gasPrice],
        ["nonce", tx.nonce],
    ] as const) {
        if (typeof value !== "bigint" || value < 0n || value >= 1n << 256n) {
            throw new InvalidArgumentError(`${name} must be a non-negative uint256 bigint.`);
        }
    }
    return tx;
}

const SAFE_TX_TYPES = {
    SafeTx: [
        { name: "to", type: "address" },
        { name: "value", type: "uint256" },
        { name: "data", type: "bytes" },
        { name: "operation", type: "uint8" },
        { name: "safeTxGas", type: "uint256" },
        { name: "baseGas", type: "uint256" },
        { name: "gasPrice", type: "uint256" },
        { name: "gasToken", type: "address" },
        { name: "refundReceiver", type: "address" },
        { name: "nonce", type: "uint256" },
    ],
} as const;

function safeTypedData(chainId: number | bigint, safe: Address, tx: SafeTransactionData) {
    return {
        domain: { chainId: BigInt(chainId), verifyingContract: safe },
        types: SAFE_TX_TYPES,
        primaryType: "SafeTx",
        message: tx,
    } as const;
}

/**
 * The EIP-712 hash of a Safe transaction (`getTransactionHash` of Safe v1.3.0+), computed offline.
 * This is the 32-byte value the ZK proof authorises and that every signer signs.
 */
export function computeSafeTransactionHash(chainId: number | bigint, safe: Address, tx: SafeTransactionData): Hex {
    assertAddress(safe, "safe");
    return hashTypedData(safeTypedData(chainId, safe, buildSafeTransaction(tx)));
}

/**
 * Signs a Safe transaction (EIP-712) with a viem account, producing the 65-byte `r || s || v`
 * signature that `generateMultiSigProof` expects. Equivalent to `account.sign({ hash })` on
 * {@link computeSafeTransactionHash}.
 */
export async function signSafeTransaction(
    account: Pick<LocalAccount, "signTypedData">,
    chainId: number | bigint,
    safe: Address,
    tx: SafeTransactionData,
): Promise<Hex> {
    assertAddress(safe, "safe");
    return account.signTypedData(safeTypedData(chainId, safe, buildSafeTransaction(tx)));
}

// ─── Safe signatures ──────────────────────────────────────────────────────────

/** One signature of a Safe `signatures` blob. */
export interface SafeSignature {
    /** The owner this signature is for (an EOA, or the ZK signer for a contract signature). */
    signer: Address;
    /** `ecdsa`: a 65-byte `r || s || v`. `contract`: the data the owner's `isValidSignature` receives (the ZK proof). */
    data: Hex;
    kind: "ecdsa" | "contract";
}

/**
 * Packs signatures in the layout Safe's `checkNSignatures` expects: static 65-byte slots ordered by
 * ascending owner address, then the dynamic data of contract signatures (a 32-byte length, then the data).
 *
 * @throws {InvalidArgumentError} on an empty list, a duplicate signer, or a malformed signature.
 */
export function encodeSafeSignatures(signatures: readonly SafeSignature[]): Hex {
    assertNonEmptyArray(signatures, "signatures");
    signatures.forEach((entry, i) => {
        assertAddress(entry.signer, `signatures[${i}].signer`);
    });
    const sorted = [...signatures].sort((a, b) => {
        const x = BigInt(a.signer.toLowerCase());
        const y = BigInt(b.signer.toLowerCase());
        return x < y ? -1 : x > y ? 1 : 0;
    });
    for (let i = 1; i < sorted.length; i++) {
        if (sorted[i].signer.toLowerCase() === sorted[i - 1].signer.toLowerCase()) {
            throw new InvalidArgumentError(`Owner ${sorted[i].signer} appears more than once.`);
        }
    }

    const staticLength = 65 * sorted.length;
    const staticParts: Hex[] = [];
    const dynamicParts: Hex[] = [];
    let dynamicLength = 0;

    for (const { signer, data, kind } of sorted) {
        if (kind === "ecdsa") {
            staticParts.push(assertHexBytes(data, 65, "ECDSA signature"));
        } else if (kind === "contract") {
            assertHex(data, "contract signature data");
            const offset = staticLength + dynamicLength;
            staticParts.push(
                hexConcat([pad(signer.toLowerCase() as Hex, { size: 32 }), toHex(offset, { size: 32 }), "0x00"]),
            );
            const part = hexConcat([toHex((data.length - 2) / 2, { size: 32 }), data]);
            dynamicParts.push(part);
            dynamicLength += (part.length - 2) / 2;
        } else {
            throw new InvalidArgumentError('signature kind must be "ecdsa" or "contract".');
        }
    }
    return hexConcat([...staticParts, ...dynamicParts]);
}

/**
 * The Safe `signatures` blob for a transaction authorised by a ZK signer alone (the Safe's only
 * owner, or the only one needed): the proof as the ZK signer's contract signature.
 */
export function encodeZKSignerSignature(zkSigner: Address, proof: Hex): Hex {
    return encodeSafeSignatures([{ signer: zkSigner, data: proof, kind: "contract" }]);
}

/** `execTransaction` calldata for a Safe transaction and its packed signatures. */
export function encodeExecTransaction(tx: SafeTransactionData, signatures: Hex): Hex {
    const t = buildSafeTransaction(tx);
    assertHex(signatures, "signatures");
    return encodeFunctionData({
        abi: safeAbi,
        functionName: "execTransaction",
        args: [
            t.to,
            t.value,
            t.data,
            t.operation,
            t.safeTxGas,
            t.baseGas,
            t.gasPrice,
            t.gasToken,
            t.refundReceiver,
            signatures,
        ],
    });
}

// ─── Proving ──────────────────────────────────────────────────────────────────

/** Output of {@link generateSafeTransactionProof}. */
export interface SafeTransactionProof {
    /** The ZK proof and its public inputs. */
    proof: MultiSigProofData;
    /** The Safe transaction hash that was authorised. */
    safeTxHash: Hex;
    /** The `signatures` argument for `execTransaction`: the proof as the ZK signer's contract signature. */
    signatures: Hex;
}

/**
 * Generates the Safe signature for a transaction: reads the ZK signer's on-chain state root, hashes
 * the transaction, proves that `threshold` of the private signers signed it, and wraps the proof as
 * the ZK signer's contract signature.
 *
 * @param client     Any viem client able to read the chain.
 * @param params.safe        The Safe address.
 * @param params.zkSigner    The ZK signer (a Safe owner) created by `ZKMultiSigEcdsaFactory`.
 * @param params.transaction The Safe transaction (build it with {@link buildSafeTransaction}).
 * @param params.signatures  Owners' 65-byte signatures of the transaction hash (see {@link signSafeTransaction}).
 * @param params.config      The private configuration (signers, threshold, salt).
 * @param params.circuit     Compiled `zk_multi_sig_ecdsa` artifact.
 * @throws {ChainStateError} if the configuration does not match the ZK signer's on-chain state root.
 */
export async function generateSafeTransactionProof(
    client: Client,
    params: {
        safe: Address;
        zkSigner: Address;
        transaction: SafeTransactionData;
        signatures: readonly Hex[];
        config: MultiSigConfig;
        circuit: unknown;
        options?: ProveOptions;
    },
): Promise<SafeTransactionProof> {
    const chainId = await getChainId(client);
    const safeTxHash = computeSafeTransactionHash(chainId, params.safe, params.transaction);
    const { stateRoot } = await getZKSignerConfiguration(client, params.zkSigner);

    const proof = await generateMultiSigProof(
        params.config,
        safeTxHash,
        params.signatures,
        stateRoot,
        params.circuit,
        params.options,
    );
    return { proof, safeTxHash, signatures: encodeZKSignerSignature(params.zkSigner, proof.proof) };
}

// ─── ZK signer: reads and creation ────────────────────────────────────────────

/** Reads the state root and transaction verifier a ZK signer was created with (through the proxy). */
export async function getZKSignerConfiguration(
    client: Client,
    zkSigner: Address,
): Promise<{ stateRoot: bigint; verifier: Address }> {
    assertAddress(zkSigner, "zkSigner");
    const [stateRoot, verifier] = await readContract(client, {
        address: zkSigner,
        abi: zkMultiSigEcdsaSignerAbi,
        functionName: "getConfiguration",
    });
    return { stateRoot: BigInt(stateRoot), verifier };
}

/** The deterministic address of the ZK signer for a state root and transaction verifier. */
export async function computeZKSignerAddress(
    client: Client,
    params: { factory: Address; stateRoot: bigint | Hex; verifier: Address },
): Promise<Address> {
    assertAddress(params.factory, "factory");
    assertAddress(params.verifier, "verifier");
    return readContract(client, {
        address: params.factory,
        abi: zkMultiSigEcdsaFactoryAbi,
        functionName: "getSigner",
        args: [fieldToBytes32(toFieldElement(params.stateRoot, "stateRoot")), params.verifier],
    });
}

/**
 * Deploys the ZK signer for a state root (idempotent: an existing signer is returned unchanged).
 * The factory verifies `stateValidationProof` on-chain, so a root that does not commit to a valid
 * configuration cannot be deployed.
 *
 * @param client Wallet client with an account (or pass `params.account`).
 */
export async function createZKSigner(
    client: Client,
    params: {
        factory: Address;
        stateRoot: bigint | Hex;
        verifier: Address;
        stateValidationProof: Hex;
        account?: Account | Address;
        chain?: Chain | null;
    },
): Promise<{ signer: Address; transactionHash: Hex }> {
    assertAddress(params.factory, "factory");
    assertAddress(params.verifier, "verifier");
    assertHex(params.stateValidationProof, "stateValidationProof");
    const stateRoot = fieldToBytes32(toFieldElement(params.stateRoot, "stateRoot"));
    const account = params.account ?? client.account;
    if (account === undefined) {
        throw new InvalidArgumentError("createZKSigner needs a client with an account, or params.account.");
    }

    const predicted = await computeZKSignerAddress(client, { ...params, stateRoot });
    const transactionHash = await writeContract(client, {
        address: params.factory,
        abi: zkMultiSigEcdsaFactoryAbi,
        functionName: "createSigner",
        args: [stateRoot, params.verifier, params.stateValidationProof],
        account,
        chain: params.chain ?? client.chain,
    });
    await waitForTransactionReceipt(client, { hash: transactionHash });
    return { signer: predicted, transactionHash };
}

/**
 * Asks the factory whether `proof` is a valid ERC-1271 signature of `hash` for a ZK signer, without
 * the Safe — a cheap on-chain pre-check before submitting a transaction.
 */
export async function isValidZKSignature(
    client: Client,
    params: { factory: Address; hash: Hex; proof: Hex; stateRoot: bigint | Hex; verifier: Address },
): Promise<boolean> {
    assertHexBytes(params.hash, 32, "hash");
    assertHex(params.proof, "proof");
    const magic = await readContract(client, {
        address: params.factory,
        abi: zkMultiSigEcdsaFactoryAbi,
        functionName: "isValidSignatureForSigner",
        args: [
            params.hash,
            params.proof,
            fieldToBytes32(toFieldElement(params.stateRoot, "stateRoot")),
            params.verifier,
        ],
    });
    return magic.toLowerCase() === ERC1271_MAGIC_VALUE;
}

// ─── Safe: reads and deployment ───────────────────────────────────────────────

/** Reads the Safe's owners, threshold, nonce and version, and checks that `zkSigner` is an owner. */
export async function getSafeInfo(
    client: Client,
    safe: Address,
    zkSigner?: Address,
): Promise<{ owners: readonly Address[]; threshold: bigint; nonce: bigint; version: string }> {
    assertAddress(safe, "safe");
    const [owners, threshold, nonce, version] = await Promise.all([
        readContract(client, { address: safe, abi: safeAbi, functionName: "getOwners" }),
        readContract(client, { address: safe, abi: safeAbi, functionName: "getThreshold" }),
        readContract(client, { address: safe, abi: safeAbi, functionName: "nonce" }),
        readContract(client, { address: safe, abi: safeAbi, functionName: "VERSION" }),
    ]);

    if (zkSigner !== undefined && !owners.some((o) => o.toLowerCase() === zkSigner.toLowerCase())) {
        throw new ChainStateError(`${zkSigner} is not an owner of the Safe ${safe}.`);
    }
    return { owners, threshold, nonce, version };
}

/** Input of {@link encodeSafeSetup}. */
export interface SafeSetupParams {
    /** The owners — typically just the ZK signer. */
    owners: readonly Address[];
    threshold: number;
    /** Defaults to the canonical v1.4.1 compatibility fallback handler. */
    fallbackHandler?: Address;
}

/** `setup(...)` initializer calldata for a new Safe (no setup delegatecall, no payment). */
export function encodeSafeSetup(params: SafeSetupParams): Hex {
    assertNonEmptyArray(params.owners, "owners");
    params.owners.forEach((owner, i) => {
        assertAddress(owner, `owners[${i}]`);
    });
    if (new Set(params.owners.map((o) => o.toLowerCase())).size !== params.owners.length) {
        throw new InvalidArgumentError("owners contains duplicates.");
    }
    assertInteger(params.threshold, "threshold", 1, params.owners.length);
    return encodeFunctionData({
        abi: safeAbi,
        functionName: "setup",
        args: [
            params.owners,
            BigInt(params.threshold),
            zeroAddress,
            "0x",
            params.fallbackHandler ?? SAFE_V141.fallbackHandler,
            zeroAddress,
            0n,
            zeroAddress,
        ],
    });
}

/** Input of {@link encodeCreateSafeProxy} and {@link predictSafeAddress}. */
export interface SafeProxyParams {
    /** `setup` initializer (see {@link encodeSafeSetup}). */
    initializer: Hex;
    saltNonce: bigint;
    /** Defaults to the canonical v1.4.1 singleton. */
    singleton?: Address;
    /** Defaults to the canonical v1.4.1 proxy factory. */
    proxyFactory?: Address;
}

/** The `{ to, data }` of the transaction that deploys the Safe via `createProxyWithNonce`. */
export function encodeCreateSafeProxy(params: SafeProxyParams): { to: Address; data: Hex } {
    assertHex(params.initializer, "initializer");
    return {
        to: params.proxyFactory ?? SAFE_V141.proxyFactory,
        data: encodeFunctionData({
            abi: safeProxyFactoryAbi,
            functionName: "createProxyWithNonce",
            args: [params.singleton ?? SAFE_V141.singleton, params.initializer, params.saltNonce],
        }),
    };
}

/**
 * The address `createProxyWithNonce` will deploy the Safe at, computed from the factory's
 * `proxyCreationCode()` (one read) and the CREATE2 formula.
 */
export async function predictSafeAddress(client: Client, params: SafeProxyParams): Promise<Address> {
    const factory = params.proxyFactory ?? SAFE_V141.proxyFactory;
    const singleton = params.singleton ?? SAFE_V141.singleton;
    const creationCode = await readContract(client, {
        address: factory,
        abi: safeProxyFactoryAbi,
        functionName: "proxyCreationCode",
    });
    return getContractAddress({
        opcode: "CREATE2",
        from: factory,
        salt: keccak256(hexConcat([keccak256(params.initializer), pad(toHex(params.saltNonce), { size: 32 })])),
        bytecode: encodePacked(["bytes", "uint256"], [creationCode, BigInt(singleton)]),
    });
}

/** Reads the address of the Safe created by a `createProxyWithNonce` transaction from its logs. */
export function parseSafeProxyCreation(logs: readonly { data: Hex; topics: readonly Hex[] }[]): Address {
    for (const log of logs) {
        try {
            const event = decodeEventLog({
                abi: safeProxyFactoryAbi,
                data: log.data,
                topics: log.topics as [Hex, ...Hex[]],
            });
            if (event.eventName === "ProxyCreation") return event.args.proxy;
        } catch {
            continue;
        }
    }
    throw new ChainStateError("No ProxyCreation event found in the transaction logs.");
}
