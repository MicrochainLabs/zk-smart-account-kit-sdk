import { secp256k1 } from "@noble/curves/secp256k1";
import { decodeAbiParameters, hexToBytes, keccak256, toBytes, toHex, type Hex } from "viem";
import { publicKeyToAddress } from "viem/utils";
import { describe, expect, it } from "vitest";
import { ChainStateError, InvalidArgumentError, NotFoundError } from "../../src/errors.js";
import { SECP256K1_ORDER } from "../../src/internal/validation.js";
import {
    MAX_SIGNERS,
    MULTISIG_PUBLIC_INPUTS,
    NIL_SIGNATURE,
    buildMultiSigCircuitInput,
    buildMultiSigPublicInputs,
    buildStateValidationCircuitInput,
    buildStateValidationPublicInputs,
    computeStateRoot,
    createMultiSigState,
    encodeMultiSigPublicInputs,
    encodeStateValidationPublicInputs,
    recoverMultiSigSigner,
    sortSigners,
    type MultiSigConfig,
} from "../../src/zk-multisig/index.js";
import { NIL_PUBKEY } from "../../src/zk-signer/index.js";
import { testAccounts } from "../helpers.js";

const SALT = 0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefn;
const accounts = testAccounts(5);
const hashOf = (label: string) => keccak256(toBytes(label));

function config(count: number, threshold: number): MultiSigConfig {
    return { signers: accounts.slice(0, count).map((a) => a.address), threshold, salt: SALT };
}

const sign = (indices: number[], hash: Hex) => Promise.all(indices.map((i) => accounts[i].sign({ hash })));

describe("recoverMultiSigSigner", () => {
    const hash = hashOf("recover");

    it("recovers address, public key and r||s for v in {27, 28} and {0, 1}", async () => {
        const [account] = accounts;
        const signature = await account.sign({ hash });
        const recovered = recoverMultiSigSigner(hash, signature);
        expect(recovered.address).toBe(account.address);
        expect(recovered.signature).toEqual(Array.from(hexToBytes(signature).slice(0, 64)));
        expect(recovered.pubKey.x).toHaveLength(32);

        const v = hexToBytes(signature)[64];
        const raw = `${signature.slice(0, 130)}${(v - 27).toString(16).padStart(2, "0")}` as Hex;
        expect(recoverMultiSigSigner(hash, raw).address).toBe(account.address);
    });

    it("accepts the hash as hex, bytes or number[]", async () => {
        const signature = await accounts[0].sign({ hash });
        const bytes = hexToBytes(hash);
        expect(recoverMultiSigSigner(bytes, signature).address).toBe(accounts[0].address);
        expect(recoverMultiSigSigner(Array.from(bytes), signature).address).toBe(accounts[0].address);
    });

    it("recovers a different address for the wrong recovery bit or the wrong hash", async () => {
        const signature = await accounts[0].sign({ hash });
        const flipped = `${signature.slice(0, 130)}${hexToBytes(signature)[64] === 27 ? "1c" : "1b"}` as Hex;
        expect(recoverMultiSigSigner(hash, flipped).address).not.toBe(accounts[0].address);
        expect(recoverMultiSigSigner(hashOf("other"), signature).address).not.toBe(accounts[0].address);
    });

    it("rejects malformed signatures", async () => {
        const signature = await accounts[0].sign({ hash });
        const bad = (value: unknown) => () => recoverMultiSigSigner(hash, value as Hex);
        expect(bad(signature.slice(0, 130))).toThrow(InvalidArgumentError); // 64 bytes
        expect(bad(`${signature}00`)).toThrow(InvalidArgumentError); // 66 bytes
        expect(bad(undefined)).toThrow(InvalidArgumentError);
        expect(bad(`${signature.slice(0, 130)}1f`)).toThrow(/recovery byte/);
        expect(bad(`0x${"00".repeat(32)}${signature.slice(66, 130)}1b`)).toThrow(/r is out of range/);
        expect(bad(`0x${SECP256K1_ORDER.toString(16)}${signature.slice(66, 130)}1b`)).toThrow(/r is out of range/);
        expect(bad(`${signature.slice(0, 66)}${"00".repeat(32)}1b`)).toThrow(/low-S/);
        const highS = (SECP256K1_ORDER - BigInt(`0x${signature.slice(66, 130)}`)).toString(16).padStart(64, "0");
        expect(bad(`${signature.slice(0, 66)}${highS}1b`)).toThrow(/low-S/);
    });

    it("rejects a signature that is not on the curve for any public key", () => {
        // r that is not an x-coordinate of a curve point.
        let r = 5n;
        while (tryPoint(r)) r++;
        const sig = `0x${r.toString(16).padStart(64, "0")}${"00".repeat(31)}01${"1b"}` as Hex;
        expect(() => recoverMultiSigSigner(hash, sig)).toThrow(/does not recover/);
    });

    it("rejects a hash of the wrong length", async () => {
        const signature = await accounts[0].sign({ hash });
        expect(() => recoverMultiSigSigner("0x1234", signature)).toThrow(InvalidArgumentError);
        expect(() => recoverMultiSigSigner(new Uint8Array(31), signature)).toThrow(InvalidArgumentError);
    });
});

function tryPoint(x: bigint): boolean {
    try {
        secp256k1.ProjectivePoint.fromHex(`02${x.toString(16).padStart(64, "0")}`);
        return true;
    } catch {
        return false;
    }
}

describe("buildMultiSigCircuitInput", () => {
    const hash = hashOf("transfer");

    it("builds a fully padded, circuit-shaped input", async () => {
        const cfg = config(3, 2);
        const state = createMultiSigState(cfg);
        const input = buildMultiSigCircuitInput(cfg, hash, await sign([2, 0], hash), state.stateRoot);

        expect(input.threshold).toBe(2);
        expect(input.signers_root).toBe(toHex(state.signersRoot));
        expect(input.salt).toBe(toHex(SALT));
        expect(input.on_chain_state_root).toBe(toHex(state.stateRoot));
        expect(input.txn_hash).toEqual(Array.from(hexToBytes(hash)));

        for (const field of ["signers", "merkle_proof_length", "indices", "siblings", "signatures"] as const) {
            expect(input[field]).toHaveLength(MAX_SIGNERS);
        }
        // Unused slots are NIL: generator public key and signature, zero-length proofs.
        for (const slot of [2, 3, 4]) {
            expect(input.signers[slot]).toEqual(NIL_PUBKEY);
            expect(input.signatures[slot]).toEqual([...NIL_SIGNATURE]);
            expect(input.merkle_proof_length[slot]).toBe(0);
            expect(input.indices[slot]).toEqual([false, false, false, false]);
            expect(input.siblings[slot]).toEqual(["0x0", "0x0", "0x0", "0x0"]);
        }
    });

    it("orders the active slots by ascending signer address, whatever the order supplied", async () => {
        const cfg = config(4, 3);
        const signatures = await sign([3, 0, 2], hash);
        const forward = buildMultiSigCircuitInput(cfg, hash, signatures);
        const reversed = buildMultiSigCircuitInput(cfg, hash, [...signatures].reverse());
        expect(forward).toEqual(reversed);

        const order = [3, 0, 2].map((i) => accounts[i].address);
        const expected = sortSigners(order);
        const addresses = forward.signers.slice(0, 3).map((pub) => recoverFromKey(pub));
        expect(addresses).toEqual(expected.map((a) => a.toLowerCase()));
    });

    it("accepts a state root as bigint or hex and rejects a mismatch with ChainStateError", async () => {
        const cfg = config(3, 2);
        const root = createMultiSigState(cfg).stateRoot;
        const sigs = await sign([0, 1], hash);
        expect(() => buildMultiSigCircuitInput(cfg, hash, sigs, root)).not.toThrow();
        expect(() => buildMultiSigCircuitInput(cfg, hash, sigs, toHex(root))).not.toThrow();
        expect(() => buildMultiSigCircuitInput(cfg, hash, sigs, root + 1n)).toThrow(ChainStateError);
        expect(() => buildMultiSigCircuitInput({ ...cfg, salt: SALT + 1n }, hash, sigs, root)).toThrow(ChainStateError);
        expect(() => buildMultiSigCircuitInput({ ...cfg, threshold: 1 }, hash, sigs, root)).toThrow(ChainStateError);
        expect(() => buildMultiSigCircuitInput(cfg, hash, sigs, 1n << 255n)).toThrow(InvalidArgumentError);
    });

    it("refuses signature sets that cannot satisfy the circuit", async () => {
        const cfg = config(3, 2);
        const [s0, s1] = await sign([0, 1], hash);

        expect(() => buildMultiSigCircuitInput(cfg, hash, [])).toThrow(/At least one signature/);
        expect(() => buildMultiSigCircuitInput(cfg, hash, undefined as never)).toThrow(InvalidArgumentError);
        expect(() => buildMultiSigCircuitInput(cfg, hash, [s0])).toThrow(/threshold is 2/);
        expect(() => buildMultiSigCircuitInput(cfg, hash, [s0, s0])).toThrow(/more than once/);

        // The same signer with the recovery byte in the other notation is still the same signer.
        const v = hexToBytes(s0)[64] - 27;
        const rawV = `${s0.slice(0, 130)}${v.toString(16).padStart(2, "0")}` as Hex;
        expect(() => buildMultiSigCircuitInput(cfg, hash, [s0, rawV])).toThrow(/more than once/);

        const [outsider] = testAccounts(1, "outsider");
        const foreign = await outsider.sign({ hash });
        expect(() => buildMultiSigCircuitInput(cfg, hash, [s0, foreign])).toThrow(NotFoundError);

        // A signature over another hash recovers to an unrelated address.
        const wrongHash = await accounts[1].sign({ hash: hashOf("other") });
        expect(() => buildMultiSigCircuitInput(cfg, hash, [s0, wrongHash])).toThrow(NotFoundError);

        const six = Array.from({ length: 6 }, () => s1);
        expect(() => buildMultiSigCircuitInput(config(5, 2), hash, six)).toThrow(/At most 5/);
    });

    it("rejects an invalid or unprovable configuration before looking at signatures", async () => {
        const sigs = await sign([0, 1], hash);
        expect(() => buildMultiSigCircuitInput({ ...config(2, 2), threshold: 3 }, hash, sigs)).toThrow(
            /no proof could ever/,
        );
        expect(() => buildMultiSigCircuitInput({ ...config(2, 2), salt: 0n }, hash, sigs)).toThrow(
            InvalidArgumentError,
        );
        expect(() => buildMultiSigCircuitInput(config(2, 2), "0x12", sigs)).toThrow(InvalidArgumentError);
    });

    it("works for every (signers, threshold) combination up to 5-of-5", async () => {
        for (let count = 1; count <= MAX_SIGNERS; count++) {
            for (let threshold = 1; threshold <= count; threshold++) {
                const cfg = config(count, threshold);
                const sigs = await sign(
                    Array.from({ length: threshold }, (_, i) => i),
                    hash,
                );
                const input = buildMultiSigCircuitInput(cfg, hash, sigs);
                expect(input.threshold).toBe(threshold);
                expect(input.merkle_proof_length.slice(0, threshold).every((n) => n <= 3)).toBe(true);
            }
        }
    });
});

function recoverFromKey(pub: { x: number[]; y: number[] }): string {
    return publicKeyToAddress(toHex(Uint8Array.from([4, ...pub.x, ...pub.y]))).toLowerCase();
}

describe("buildStateValidationCircuitInput", () => {
    it("exposes the private configuration and the matching public root", () => {
        const cfg = config(3, 2);
        const state = createMultiSigState(cfg);
        expect(buildStateValidationCircuitInput(cfg)).toEqual({
            signers_root: toHex(state.signersRoot),
            threshold: 2,
            salt: toHex(SALT),
            on_chain_state_root: toHex(computeStateRoot(state.signersRoot, 2, SALT)),
        });
    });

    it("rejects unprovable configurations", () => {
        expect(() => buildStateValidationCircuitInput({ ...config(2, 2), threshold: 3 })).toThrow(InvalidArgumentError);
    });
});

describe("public inputs", () => {
    const hash = hashOf("public inputs");
    const root = 123456789n;

    it("lays out one word per hash byte, then the root", () => {
        const inputs = buildMultiSigPublicInputs(hash, root);
        expect(inputs).toHaveLength(MULTISIG_PUBLIC_INPUTS);
        const bytes = hexToBytes(hash);
        inputs.slice(0, 32).forEach((word, i) => {
            expect(word).toBe(toHex(bytes[i], { size: 32 }));
        });
        expect(inputs[32]).toBe(toHex(root, { size: 32 }));
        expect(buildMultiSigPublicInputs(Array.from(bytes), toHex(root))).toEqual(inputs);
    });

    it("encodes as abi.encode(bytes32[]) with the layout the verifier adapter checks", () => {
        const encoded = encodeMultiSigPublicInputs(hash, root);
        // offset 0x20, length 33, then 33 words: 32 * (2 + 33) bytes in total.
        expect((encoded.length - 2) / 2).toBe(32 * (2 + 33));
        expect(BigInt(`0x${encoded.slice(2, 66)}`)).toBe(0x20n);
        expect(BigInt(`0x${encoded.slice(66, 130)}`)).toBe(33n);
        const [decoded] = decodeAbiParameters([{ type: "bytes32[]" }], encoded);
        expect(decoded).toEqual(buildMultiSigPublicInputs(hash, root));
    });

    it("the state-validation input is the single root word", () => {
        expect(buildStateValidationPublicInputs(root)).toEqual([toHex(root, { size: 32 })]);
        const encoded = encodeStateValidationPublicInputs(root);
        expect((encoded.length - 2) / 2).toBe(32 * (2 + 1));
        expect(BigInt(`0x${encoded.slice(66, 130)}`)).toBe(1n);
    });

    it.each([
        ["a short hash", () => buildMultiSigPublicInputs("0x1234", root)],
        ["a root outside the field", () => buildMultiSigPublicInputs(hash, 1n << 255n)],
        ["a negative root", () => buildStateValidationPublicInputs(-1n)],
        ["a malformed root", () => encodeStateValidationPublicInputs("0xzz" as Hex)],
    ])("rejects %s", (_name, call) => {
        expect(call).toThrow(InvalidArgumentError);
    });
});
