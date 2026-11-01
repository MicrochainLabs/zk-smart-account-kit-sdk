import {
    concat,
    decodeFunctionData,
    encodeAbiParameters,
    encodeEventTopics,
    encodePacked,
    getAddress,
    getContractAddress,
    hexToBigInt,
    hexToBytes,
    keccak256,
    pad,
    parseAbiParameters,
    toBytes,
    toHex,
    zeroAddress,
    type Abi,
    type Address,
    type Hex,
} from "viem";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ChainStateError, InvalidArgumentError } from "../../src/errors.js";
import { createMultiSigState, type MultiSigConfig } from "../../src/zk-multisig/index.js";
import {
    ERC1271_MAGIC_VALUE,
    SAFE_V141,
    buildSafeTransaction,
    computeSafeTransactionHash,
    computeZKSignerAddress,
    createZKSigner,
    encodeCreateSafeProxy,
    encodeExecTransaction,
    encodeSafeSetup,
    encodeSafeSignatures,
    encodeZKSignerSignature,
    getSafeInfo,
    getZKSignerConfiguration,
    isValidZKSignature,
    parseSafeProxyCreation,
    predictSafeAddress,
    safeAbi,
    safeProxyFactoryAbi,
    signSafeTransaction,
    zkMultiSigEcdsaFactoryAbi,
    zkMultiSigEcdsaSignerAbi,
} from "../../src/zk-multisig/safe.js";
import { loadContract } from "../onchain/harness.js";
import { ADDRESSES, testAccounts } from "../helpers.js";
import { abiResponder, createFakeChain } from "./fake-chain.js";

const SALT = 0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefn;
const safe: Address = "0x1111111111111111111111111111111111111111";
const factory: Address = "0x2222222222222222222222222222222222222222";
const verifier: Address = "0x3333333333333333333333333333333333333333";
const owners = testAccounts(3, "safe-unit");
const config: MultiSigConfig = { signers: owners.map((a) => a.address), threshold: 2, salt: SALT };
const state = createMultiSigState(config);

afterEach(() => {
    vi.doUnmock("../../src/zk-multisig/prove.js");
    vi.resetModules();
});

describe("buildSafeTransaction", () => {
    it("fills the defaults: a plain CALL without gas refund", () => {
        expect(buildSafeTransaction({ to: ADDRESSES[0], nonce: 7n })).toEqual({
            to: ADDRESSES[0],
            value: 0n,
            data: "0x",
            operation: 0,
            safeTxGas: 0n,
            baseGas: 0n,
            gasPrice: 0n,
            gasToken: zeroAddress,
            refundReceiver: zeroAddress,
            nonce: 7n,
        });
    });

    it.each([
        ["an invalid target", { to: "0x12" as Address }],
        ["a negative value", { value: -1n }],
        ["a value above uint256", { value: 1n << 256n }],
        ["a number nonce", { nonce: 1 as unknown as bigint }],
        ["bad data", { data: "0xabc" as Hex }],
        ["a bad operation", { operation: 2 as 0 }],
        ["a bad gas token", { gasToken: "0x1" as Address }],
        ["a bad refund receiver", { refundReceiver: "nope" as Address }],
    ])("rejects %s", (_name, patch) => {
        expect(() => buildSafeTransaction({ to: ADDRESSES[0], nonce: 0n, ...patch })).toThrow(InvalidArgumentError);
    });
});

// Safe v1.3.0+ EIP-712 constants, written out independently of viem's typed-data encoder.
const DOMAIN_SEPARATOR_TYPEHASH = "0x47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218";
const SAFE_TX_TYPEHASH = "0xbb8310d486368db6bd6f849402fdd73ad53d316b5a4b2644ad6efe0f941286d8";

function referenceSafeTxHash(chainId: bigint, safeAddress: Address, tx: ReturnType<typeof buildSafeTransaction>): Hex {
    const domainSeparator = keccak256(
        encodeAbiParameters(parseAbiParameters("bytes32, uint256, address"), [
            DOMAIN_SEPARATOR_TYPEHASH,
            chainId,
            safeAddress,
        ]),
    );
    const structHash = keccak256(
        encodeAbiParameters(
            parseAbiParameters(
                "bytes32, address, uint256, bytes32, uint8, uint256, uint256, uint256, address, address, uint256",
            ),
            [
                SAFE_TX_TYPEHASH,
                tx.to,
                tx.value,
                keccak256(tx.data),
                tx.operation,
                tx.safeTxGas,
                tx.baseGas,
                tx.gasPrice,
                tx.gasToken,
                tx.refundReceiver,
                tx.nonce,
            ],
        ),
    );
    return keccak256(
        encodePacked(["bytes1", "bytes1", "bytes32", "bytes32"], ["0x19", "0x01", domainSeparator, structHash]),
    );
}

describe("computeSafeTransactionHash", () => {
    const tx = buildSafeTransaction({
        to: ADDRESSES[1],
        value: 12345n,
        data: "0xdeadbeef",
        operation: 1,
        safeTxGas: 1n,
        baseGas: 2n,
        gasPrice: 3n,
        gasToken: ADDRESSES[2],
        refundReceiver: ADDRESSES[3],
        nonce: 9n,
    });

    it("equals an independent EIP-712 implementation (the one Safe's getTransactionHash uses)", () => {
        for (const chainId of [1, 137, 31337, 8453]) {
            expect(computeSafeTransactionHash(chainId, safe, tx)).toBe(referenceSafeTxHash(BigInt(chainId), safe, tx));
        }
        expect(computeSafeTransactionHash(1n, safe, buildSafeTransaction({ to: safe, nonce: 0n }))).toBe(
            referenceSafeTxHash(1n, safe, buildSafeTransaction({ to: safe, nonce: 0n })),
        );
    });

    it("binds the chain, the Safe and every field", () => {
        const base = computeSafeTransactionHash(1, safe, tx);
        expect(computeSafeTransactionHash(2, safe, tx)).not.toBe(base);
        expect(computeSafeTransactionHash(1, ADDRESSES[5], tx)).not.toBe(base);
        for (const patch of [
            { nonce: 10n },
            { value: 1n },
            { data: "0x" as Hex },
            { operation: 0 as const },
            { to: ADDRESSES[6] },
        ]) {
            expect(computeSafeTransactionHash(1, safe, { ...tx, ...patch })).not.toBe(base);
        }
    });

    it("rejects an invalid Safe address", () => {
        expect(() => computeSafeTransactionHash(1, "0x12" as Address, tx)).toThrow(InvalidArgumentError);
    });

    it("signSafeTransaction signs exactly that hash", async () => {
        const hash = computeSafeTransactionHash(31337, safe, tx);
        expect(await signSafeTransaction(owners[0], 31337, safe, tx)).toBe(await owners[0].sign({ hash }));
        await expect(signSafeTransaction(owners[0], 31337, "0x1" as Address, tx)).rejects.toThrow(InvalidArgumentError);
    });
});

/** A parser written from the semantics of Safe's `checkNSignatures`, to check the encoder against. */
function parseSafeSignatures(blob: Hex, count: number) {
    const bytes = hexToBytes(blob);
    const word = (offset: number) => hexToBigInt(toHex(bytes.slice(offset, offset + 32)));
    const out: ({ kind: "ecdsa"; signature: Hex } | { kind: "contract"; owner: Address; data: Hex })[] = [];
    for (let i = 0; i < count; i++) {
        const pos = 65 * i;
        const v = bytes[pos + 64];
        if (v === 0) {
            const owner = getAddress(toHex(bytes.slice(pos + 12, pos + 32)));
            const offset = Number(word(pos + 32));
            expect(offset).toBeGreaterThanOrEqual(65 * count); // GS021
            expect(offset + 32).toBeLessThanOrEqual(bytes.length); // GS022
            const length = Number(word(offset));
            expect(offset + 32 + length).toBeLessThanOrEqual(bytes.length); // GS023
            out.push({ kind: "contract", owner, data: toHex(bytes.slice(offset + 32, offset + 32 + length)) });
        } else {
            out.push({ kind: "ecdsa", signature: toHex(bytes.slice(pos, pos + 65)) });
        }
    }
    return out;
}

describe("encodeSafeSignatures", () => {
    const proof = `0x${"ab".repeat(100)}` as Hex;
    const signer = ADDRESSES[4];

    it("encodes a lone contract signature as static slot + length-prefixed data", () => {
        const blob = encodeZKSignerSignature(signer, proof);
        expect(blob).toBe(encodeSafeSignatures([{ signer, data: proof, kind: "contract" }]));
        expect((blob.length - 2) / 2).toBe(65 + 32 + 100);
        expect(blob.slice(2, 66)).toBe(pad(signer.toLowerCase() as Hex, { size: 32 }).slice(2)); // lower-case owner word
        expect(parseSafeSignatures(blob, 1)).toEqual([{ kind: "contract", owner: getAddress(signer), data: proof }]);
    });

    it("sorts by owner address and points every contract signature at its own data", () => {
        const eoaSig = `0x${"11".repeat(64)}1b` as Hex;
        const proofB = `0x${"cd".repeat(33)}` as Hex;
        const entries = [
            { signer: ADDRESSES[7], data: proofB, kind: "contract" as const },
            { signer: ADDRESSES[8], data: eoaSig, kind: "ecdsa" as const },
            { signer: ADDRESSES[9], data: proof, kind: "contract" as const },
        ];
        const blob = encodeSafeSignatures(entries);
        const order = [...entries].sort((a, b) =>
            BigInt(a.signer.toLowerCase()) < BigInt(b.signer.toLowerCase()) ? -1 : 1,
        );

        const parsed = parseSafeSignatures(blob, 3);
        parsed.forEach((p, i) => {
            if (order[i].kind === "ecdsa") expect(p).toEqual({ kind: "ecdsa", signature: order[i].data });
            else expect(p).toEqual({ kind: "contract", owner: getAddress(order[i].signer), data: order[i].data });
        });
        // Any input order gives the same blob.
        expect(encodeSafeSignatures([...entries].reverse())).toBe(blob);
    });

    it("rejects empty lists, duplicates, malformed data and unknown kinds", () => {
        expect(() => encodeSafeSignatures([])).toThrow(InvalidArgumentError);
        expect(() => encodeSafeSignatures(undefined as never)).toThrow(InvalidArgumentError);
        expect(() =>
            encodeSafeSignatures([
                { signer, data: proof, kind: "contract" },
                { signer: signer.toLowerCase() as Address, data: proof, kind: "contract" },
            ]),
        ).toThrow(/more than once/);
        expect(() => encodeSafeSignatures([{ signer, data: "0x1234", kind: "ecdsa" }])).toThrow(InvalidArgumentError);
        expect(() => encodeSafeSignatures([{ signer, data: "0xabc" as Hex, kind: "contract" }])).toThrow(
            InvalidArgumentError,
        );
        expect(() => encodeSafeSignatures([{ signer, data: proof, kind: "other" as never }])).toThrow(
            InvalidArgumentError,
        );
        expect(() => encodeSafeSignatures([{ signer: "0x12" as Address, data: proof, kind: "contract" }])).toThrow(
            InvalidArgumentError,
        );
    });

    it("handles an empty contract signature", () => {
        const blob = encodeSafeSignatures([{ signer, data: "0x", kind: "contract" }]);
        expect(parseSafeSignatures(blob, 1)).toEqual([{ kind: "contract", owner: getAddress(signer), data: "0x" }]);
    });
});

describe("encodeExecTransaction", () => {
    it("is the ABI encoding of execTransaction with the transaction fields and signatures", () => {
        const tx = buildSafeTransaction({ to: ADDRESSES[1], value: 5n, data: "0xdeadbeef", nonce: 3n, operation: 1 });
        const signatures = encodeZKSignerSignature(ADDRESSES[2], "0x1234");
        const decoded = decodeFunctionData({ abi: safeAbi, data: encodeExecTransaction(tx, signatures) });
        expect(decoded.functionName).toBe("execTransaction");
        expect(decoded.args).toEqual([
            tx.to,
            tx.value,
            tx.data,
            tx.operation,
            tx.safeTxGas,
            tx.baseGas,
            tx.gasPrice,
            tx.gasToken,
            tx.refundReceiver,
            signatures,
        ]);
        expect(() => encodeExecTransaction(tx, "0xabc" as Hex)).toThrow(InvalidArgumentError);
    });
});

describe("Safe deployment helpers", () => {
    it("encodeSafeSetup encodes setup(owners, threshold, …) with the canonical fallback handler", () => {
        const decoded = decodeFunctionData({
            abi: safeAbi,
            data: encodeSafeSetup({ owners: [ADDRESSES[0], ADDRESSES[1]], threshold: 2 }),
        });
        expect(decoded.functionName).toBe("setup");
        expect(decoded.args).toEqual([
            [ADDRESSES[0], ADDRESSES[1]],
            2n,
            zeroAddress,
            "0x",
            SAFE_V141.fallbackHandler,
            zeroAddress,
            0n,
            zeroAddress,
        ]);
        const custom = decodeFunctionData({
            abi: safeAbi,
            data: encodeSafeSetup({ owners: [ADDRESSES[0]], threshold: 1, fallbackHandler: ADDRESSES[5] }),
        });
        expect(custom.args?.[4]).toBe(ADDRESSES[5]);
    });

    it.each([
        ["no owners", { owners: [], threshold: 1 }],
        ["duplicate owners", { owners: [ADDRESSES[0], ADDRESSES[0].toLowerCase() as Address], threshold: 1 }],
        ["an invalid owner", { owners: ["0x1" as Address], threshold: 1 }],
        ["threshold 0", { owners: [ADDRESSES[0]], threshold: 0 }],
        ["threshold above the owner count", { owners: [ADDRESSES[0]], threshold: 2 }],
    ])("encodeSafeSetup rejects %s", (_name, params) => {
        expect(() => encodeSafeSetup(params)).toThrow(InvalidArgumentError);
    });

    it("encodeCreateSafeProxy targets the canonical factory and singleton by default", () => {
        const initializer = encodeSafeSetup({ owners: [ADDRESSES[0]], threshold: 1 });
        const call = encodeCreateSafeProxy({ initializer, saltNonce: 42n });
        expect(call.to).toBe(SAFE_V141.proxyFactory);
        const decoded = decodeFunctionData({ abi: safeProxyFactoryAbi, data: call.data });
        expect(decoded.args).toEqual([SAFE_V141.singleton, initializer, 42n]);

        const custom = encodeCreateSafeProxy({
            initializer,
            saltNonce: 1n,
            singleton: ADDRESSES[1],
            proxyFactory: ADDRESSES[2],
        });
        expect(custom.to).toBe(ADDRESSES[2]);
        expect(() => encodeCreateSafeProxy({ initializer: "0xabc" as Hex, saltNonce: 1n })).toThrow(
            InvalidArgumentError,
        );
    });

    it("predictSafeAddress is CREATE2(factory, keccak(keccak(initializer) ‖ saltNonce), keccak(proxyCreationCode ‖ singleton))", async () => {
        const creationCode: Hex = "0x608060405234801561001057600080fd5b50";
        const { client } = createFakeChain(undefined, {
            call: abiResponder(safeProxyFactoryAbi as Abi, { proxyCreationCode: () => creationCode }),
        });
        const initializer = encodeSafeSetup({ owners: [ADDRESSES[0]], threshold: 1 });
        const params = { initializer, saltNonce: 77n, singleton: ADDRESSES[1], proxyFactory: ADDRESSES[2] };

        const salt = keccak256(concat([keccak256(initializer), pad(toHex(77n), { size: 32 })]));
        const expected = getContractAddress({
            opcode: "CREATE2",
            from: ADDRESSES[2],
            salt,
            bytecode: concat([creationCode, pad(ADDRESSES[1].toLowerCase() as Hex, { size: 32 })]),
        });
        expect(await predictSafeAddress(client, params)).toBe(expected);
    });

    it("parseSafeProxyCreation finds the ProxyCreation event and fails clearly without it", () => {
        const [topic0, proxyTopic] = encodeEventTopics({
            abi: safeProxyFactoryAbi,
            eventName: "ProxyCreation",
            args: { proxy: ADDRESSES[3] },
        });
        const log = { data: pad(ADDRESSES[1].toLowerCase() as Hex, { size: 32 }), topics: [topic0, proxyTopic as Hex] };
        const noise = { data: "0x" as Hex, topics: [keccak256(toBytes("Other()"))] };
        expect(parseSafeProxyCreation([noise, log])).toBe(getAddress(ADDRESSES[3]));
        expect(() => parseSafeProxyCreation([noise])).toThrow(ChainStateError);
        expect(() => parseSafeProxyCreation([])).toThrow(/No ProxyCreation event/);
    });
});

describe("ZK signer reads and creation", () => {
    const abi = [...zkMultiSigEcdsaFactoryAbi, ...zkMultiSigEcdsaSignerAbi, ...safeAbi] as Abi;

    it("getZKSignerConfiguration returns the root and verifier from the proxy", async () => {
        const { client, calls } = createFakeChain(undefined, {
            call: abiResponder(abi, { getConfiguration: () => [toHex(state.stateRoot, { size: 32 }), verifier] }),
        });
        expect(await getZKSignerConfiguration(client, ADDRESSES[0])).toEqual({
            stateRoot: state.stateRoot,
            verifier: getAddress(verifier),
        });
        expect(calls[0].to.toLowerCase()).toBe(ADDRESSES[0].toLowerCase());
        await expect(getZKSignerConfiguration(client, "0x1" as Address)).rejects.toThrow(InvalidArgumentError);
    });

    it("computeZKSignerAddress asks the factory with a 32-byte root", async () => {
        let seen: readonly unknown[] = [];
        const { client } = createFakeChain(undefined, {
            call: abiResponder(abi, { getSigner: (args) => ((seen = args), ADDRESSES[6]) }),
        });
        expect(await computeZKSignerAddress(client, { factory, stateRoot: state.stateRoot, verifier })).toBe(
            getAddress(ADDRESSES[6]),
        );
        expect(seen).toEqual([toHex(state.stateRoot, { size: 32 }), getAddress(verifier)]);
        await expect(
            computeZKSignerAddress(client, { factory: "0x1" as Address, stateRoot: 1n, verifier }),
        ).rejects.toThrow(InvalidArgumentError);
        await expect(
            computeZKSignerAddress(client, { factory, stateRoot: 1n, verifier: "0x1" as Address }),
        ).rejects.toThrow(InvalidArgumentError);
    });

    it("isValidZKSignature is true only for the ERC-1271 magic value", async () => {
        const answer = (magic: Hex) =>
            createFakeChain(undefined, { call: abiResponder(abi, { isValidSignatureForSigner: () => magic }) }).client;
        const params = {
            factory,
            hash: keccak256("0x01"),
            proof: "0xabcd" as Hex,
            stateRoot: state.stateRoot,
            verifier,
        };
        expect(await isValidZKSignature(answer(ERC1271_MAGIC_VALUE), params)).toBe(true);
        expect(await isValidZKSignature(answer("0x00000000"), params)).toBe(false);
        await expect(isValidZKSignature(answer(ERC1271_MAGIC_VALUE), { ...params, hash: "0x12" })).rejects.toThrow(
            InvalidArgumentError,
        );
        await expect(
            isValidZKSignature(answer(ERC1271_MAGIC_VALUE), { ...params, proof: "0xabc" as Hex }),
        ).rejects.toThrow(InvalidArgumentError);
    });

    it("createZKSigner sends createSigner and returns the predicted address", async () => {
        const { client, sent } = createFakeChain(owners[0], {
            call: abiResponder(abi, { getSigner: () => ADDRESSES[6] }),
        });
        const result = await createZKSigner(client, {
            factory,
            stateRoot: state.stateRoot,
            verifier,
            stateValidationProof: "0xabcd",
        });
        expect(result.signer).toBe(getAddress(ADDRESSES[6]));
        expect(sent).toHaveLength(1);
        expect(result.transactionHash).toBe(keccak256(sent[0]));
    });

    it("createZKSigner needs an account and valid inputs", async () => {
        const { client } = createFakeChain(undefined, { call: abiResponder(abi, { getSigner: () => ADDRESSES[6] }) });
        await expect(
            createZKSigner(client, { factory, stateRoot: 1n, verifier, stateValidationProof: "0xabcd" }),
        ).rejects.toThrow(/needs a client with an account/);
        await expect(
            createZKSigner(client, { factory, stateRoot: 1n, verifier, stateValidationProof: "0xabc" as Hex }),
        ).rejects.toThrow(InvalidArgumentError);
        await expect(
            createZKSigner(client, {
                factory: "0x1" as Address,
                stateRoot: 1n,
                verifier,
                stateValidationProof: "0xab",
            }),
        ).rejects.toThrow(InvalidArgumentError);
        await expect(
            createZKSigner(client, {
                factory,
                stateRoot: 1n,
                verifier: "0x1" as Address,
                stateValidationProof: "0xab",
            }),
        ).rejects.toThrow(InvalidArgumentError);
    });

    it("createZKSigner uses params.account when the client has none", async () => {
        const { client, sent } = createFakeChain(owners[0], {
            call: abiResponder(abi, { getSigner: () => ADDRESSES[6] }),
        });
        await createZKSigner(client, {
            factory,
            stateRoot: 1n,
            verifier,
            stateValidationProof: "0xab",
            account: owners[1],
        });
        expect(sent).toHaveLength(1);
    });

    it("getSafeInfo reads owners, threshold, nonce and version, and checks ownership", async () => {
        const { client } = createFakeChain(undefined, {
            call: abiResponder(abi, {
                getOwners: () => [ADDRESSES[0], ADDRESSES[1]],
                getThreshold: () => 2n,
                nonce: () => 5n,
                VERSION: () => "1.4.1",
            }),
        });
        expect(await getSafeInfo(client, safe)).toEqual({
            owners: [getAddress(ADDRESSES[0]), getAddress(ADDRESSES[1])],
            threshold: 2n,
            nonce: 5n,
            version: "1.4.1",
        });
        expect((await getSafeInfo(client, safe, ADDRESSES[1].toLowerCase() as Address)).nonce).toBe(5n);
        await expect(getSafeInfo(client, safe, ADDRESSES[9])).rejects.toThrow(ChainStateError);
        await expect(getSafeInfo(client, "0x1" as Address)).rejects.toThrow(InvalidArgumentError);
    });
});

describe("generateSafeTransactionProof", () => {
    it("hashes the transaction for the client's chain, proves against the on-chain root and wraps the proof", async () => {
        vi.resetModules();
        const generateMultiSigProof = vi
            .fn()
            .mockResolvedValue({ proof: "0xfeedface", publicInputs: [], txnHash: "0x", stateRoot: "0x" });
        vi.doMock("../../src/zk-multisig/prove.js", () => ({ generateMultiSigProof }));
        const safeModule = await import("../../src/zk-multisig/safe.js");

        const abi = [...zkMultiSigEcdsaSignerAbi] as Abi;
        const { client } = createFakeChain(undefined, {
            chainId: 137,
            call: abiResponder(abi, { getConfiguration: () => [toHex(state.stateRoot, { size: 32 }), verifier] }),
        });
        const tx = safeModule.buildSafeTransaction({ to: ADDRESSES[1], value: 1n, nonce: 4n });
        const circuit = { bytecode: "AAAA" };
        const options = { verify: false };
        const signatures = await Promise.all(
            [0, 1].map((i) => safeModule.signSafeTransaction(owners[i], 137, safe, tx)),
        );

        const result = await safeModule.generateSafeTransactionProof(client, {
            safe,
            zkSigner: ADDRESSES[5],
            transaction: tx,
            signatures,
            config,
            circuit,
            options,
        });

        const expectedHash = computeSafeTransactionHash(137, safe, tx);
        expect(result.safeTxHash).toBe(expectedHash);
        expect(generateMultiSigProof).toHaveBeenCalledWith(
            config,
            expectedHash,
            signatures,
            state.stateRoot,
            circuit,
            options,
        );
        expect(result.signatures).toBe(encodeZKSignerSignature(ADDRESSES[5], "0xfeedface"));
        expect(result.proof.proof).toBe("0xfeedface");
    });
});

describe("ABI conformance with the compiled contracts", () => {
    type Item = { type: string; name?: string; inputs?: { type: string }[]; outputs?: { type: string }[] };
    const signature = (i: Item) =>
        `${i.type} ${i.name}(${(i.inputs ?? []).map((x) => x.type).join(",")})${(i.outputs ?? []).length ? `->(${(i.outputs ?? []).map((x) => x.type).join(",")})` : ""}`;

    function conforms(sdk: Abi, fixture: string, ignoreOutputsFor: string[] = []) {
        const compiled = loadContract(fixture).abi as unknown as Item[];
        const known = new Set(compiled.map((i) => signature(i)));
        const inputsOnly = new Set(compiled.map((i) => signature({ ...i, outputs: [] })));
        for (const item of sdk as unknown as Item[]) {
            if (item.type !== "function" && item.type !== "event") continue;
            const ok = ignoreOutputsFor.includes(item.name ?? "")
                ? inputsOnly.has(signature({ ...item, outputs: [] }))
                : known.has(signature(item));
            expect(ok, `${fixture} has ${signature(item)}`).toBe(true);
        }
    }

    it("the ZK signer factory", () => {
        conforms(zkMultiSigEcdsaFactoryAbi as Abi, "ZKMultiSigEcdsaFactory");
    });

    it("the ZK signer singleton (functions used through the proxy)", () => {
        conforms(zkMultiSigEcdsaSignerAbi as Abi, "ZKMultiSigEcdsaSingleton");
    });
});
