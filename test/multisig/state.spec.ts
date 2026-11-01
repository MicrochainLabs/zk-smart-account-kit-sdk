import { poseidon } from "@iden3/js-crypto";
import { LeanIMT as UpstreamLeanIMT } from "@zk-kit/lean-imt";
import { toHex } from "viem";
import { afterEach, describe, expect, it, vi } from "vitest";
import { InvalidArgumentError, NotFoundError, UnsupportedEnvironmentError } from "../../src/errors.js";
import { BN254_FIELD_MODULUS } from "../../src/internal/validation.js";
import {
    MAX_SIGNERS,
    buildMultiSigTree,
    computeStateRoot,
    createMultiSigState,
    fieldToBytes32,
    generateSalt,
    getMultiSigMerkleProof,
    parseMultiSigState,
    parseSalt,
    saltToHex,
    serializeMultiSigState,
    sortSigners,
} from "../../src/zk-multisig/index.js";
import { computeSignerLeaf, signersHash } from "../../src/zk-signer/index.js";
import { ADDRESSES } from "../helpers.js";

// Shared vector with the Noir circuits (TEST_* in noir/zk_multi_sig_ecdsa*/src/main.nr).
const SIGNERS_ROOT = 16223743289759414337474221898890222788896083712324022742978151074941795950178n;
const SALT = 0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefn;
const STATE_ROOT = 20321389246711366214573318284446720008267991448836355782945972567979658685784n;
const LEGACY_UNSALTED_ROOT = 10223786790855367822232839749406742084971735911793673331153158573476372880461n;

describe("computeStateRoot", () => {
    it("matches the Noir compute_state_root test vector", () => {
        expect(computeStateRoot(SIGNERS_ROOT, 2, SALT)).toBe(STATE_ROOT);
        expect(computeStateRoot(SIGNERS_ROOT, 2n, SALT)).toBe(STATE_ROOT);
    });

    it("is Poseidon3(root, Poseidon1(threshold), salt) and differs from the legacy unsalted root", () => {
        expect(STATE_ROOT).toBe(poseidon.hash([SIGNERS_ROOT, poseidon.hash([2n]), SALT]));
        expect(STATE_ROOT).not.toBe(LEGACY_UNSALTED_ROOT);
    });

    it("depends on every input", () => {
        expect(computeStateRoot(SIGNERS_ROOT, 2, SALT + 1n)).not.toBe(STATE_ROOT);
        expect(computeStateRoot(SIGNERS_ROOT, 3, SALT)).not.toBe(STATE_ROOT);
        expect(computeStateRoot(SIGNERS_ROOT + 1n, 2, SALT)).not.toBe(STATE_ROOT);
    });

    it.each([
        ["zero salt", SIGNERS_ROOT, 2, 0n],
        ["salt at the modulus", SIGNERS_ROOT, 2, BN254_FIELD_MODULUS],
        ["negative salt", SIGNERS_ROOT, 2, -1n],
        ["threshold 0", SIGNERS_ROOT, 0, SALT],
        ["threshold 6", SIGNERS_ROOT, 6, SALT],
        ["fractional threshold", SIGNERS_ROOT, 1.5, SALT],
        ["root above the field", BN254_FIELD_MODULUS, 2, SALT],
    ])("rejects %s", (_name, root, threshold, salt) => {
        expect(() => computeStateRoot(root, threshold, salt)).toThrow(InvalidArgumentError);
    });
});

describe("salt", () => {
    afterEach(() => {
        vi.unstubAllGlobals();
    });

    it("generates distinct non-zero field elements of at most 248 bits", () => {
        const salts = Array.from({ length: 50 }, generateSalt);
        expect(new Set(salts).size).toBe(50);
        for (const salt of salts) {
            expect(salt).toBeGreaterThan(0n);
            expect(salt).toBeLessThan(1n << 248n);
            expect(salt).toBeLessThan(BN254_FIELD_MODULUS);
        }
    });

    it("never returns zero even if the random source does", () => {
        let calls = 0;
        vi.stubGlobal("crypto", {
            getRandomValues: (bytes: Uint8Array) => {
                bytes.fill(calls++ === 0 ? 0 : 7);
                return bytes;
            },
        });
        expect(generateSalt()).not.toBe(0n);
        expect(calls).toBe(2);
    });

    it("fails clearly without a secure random source", () => {
        vi.stubGlobal("crypto", undefined);
        expect(() => generateSalt()).toThrow(UnsupportedEnvironmentError);
    });

    it("parses hex, decimal, padded and bigint salts", () => {
        expect(parseSalt("0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")).toBe(SALT);
        expect(parseSalt(SALT.toString())).toBe(SALT);
        expect(parseSalt(`  ${SALT.toString()}  `)).toBe(SALT);
        expect(parseSalt(SALT)).toBe(SALT);
    });

    it.each([
        undefined,
        "",
        "   ",
        "0",
        "0x0",
        BN254_FIELD_MODULUS.toString(),
        "not-a-number",
        "0xzz",
        "-1",
        "1e3",
        0n,
        -5n,
    ])("rejects %s", (value) => {
        expect(() => parseSalt(value as never)).toThrow(InvalidArgumentError);
    });

    it("formats salts and roots as 32-byte words", () => {
        expect(saltToHex(SALT)).toBe(toHex(SALT, { size: 32 }));
        expect(fieldToBytes32(1n)).toBe(`0x${"00".repeat(31)}01`);
        expect(() => saltToHex(0n)).toThrow(InvalidArgumentError);
        expect(() => fieldToBytes32(BN254_FIELD_MODULUS)).toThrow(InvalidArgumentError);
    });
});

describe("buildMultiSigTree", () => {
    const [a, b, c, d, e, f] = ADDRESSES;

    it("sorts numerically, ignoring input order and case", () => {
        const sorted = sortSigners([a, b, c]);
        const root = buildMultiSigTree([a, b, c]).signersRoot;
        expect(buildMultiSigTree([c, a, b]).signersRoot).toBe(root);
        expect(buildMultiSigTree([c, b, a].map((s) => s.toLowerCase())).signersRoot).toBe(root);

        // Independent computation: Poseidon leaves in ascending address order, LeanIMT shape (3 leaves).
        const [l0, l1, l2] = sorted.map(computeSignerLeaf);
        expect(root).toBe(signersHash(signersHash(l0, l1), l2));
    });

    it("agrees with the upstream LeanIMT for every supported size", () => {
        for (let n = 1; n <= MAX_SIGNERS; n++) {
            const signers = ADDRESSES.slice(0, n);
            const upstream = new UpstreamLeanIMT(signersHash);
            for (const s of sortSigners(signers)) upstream.insert(computeSignerLeaf(s));
            expect(buildMultiSigTree(signers).signersRoot).toBe(upstream.root);
        }
    });

    it("for a single signer the root is the leaf", () => {
        const tree = buildMultiSigTree([a]);
        expect(tree.signersRoot).toBe(computeSignerLeaf(a));
        expect(tree.leaves).toEqual([computeSignerLeaf(a)]);
    });

    it("rejects empty, oversized, duplicate and invalid sets", () => {
        expect(() => buildMultiSigTree([])).toThrow(InvalidArgumentError);
        expect(() => buildMultiSigTree([a, b, c, d, e, f])).toThrow(InvalidArgumentError);
        expect(() => buildMultiSigTree([a, a])).toThrow(/duplicate/);
        expect(() => buildMultiSigTree([a, a.toLowerCase()])).toThrow(/duplicate/);
        expect(() => buildMultiSigTree([a, "0x1234"])).toThrow(InvalidArgumentError);
        expect(() => buildMultiSigTree(undefined as never)).toThrow(InvalidArgumentError);
        expect(() => buildMultiSigTree([a], "nope" as never)).toThrow(/signersFormat/);
    });

    it("accepts Poseidon leaves, sorted by their own value, and validates them", () => {
        const leaves = [a, b, c].map((s) => computeSignerLeaf(s));
        const hashed = leaves.map((l) => toHex(l));
        const tree = buildMultiSigTree(hashed, "poseidon-hash");
        const sortedLeaves = [...leaves].sort((x, y) => (x < y ? -1 : 1));
        expect(tree.leaves).toEqual(sortedLeaves);
        expect(buildMultiSigTree(leaves.map(String), "poseidon-hash").signersRoot).toBe(tree.signersRoot);

        // A member is still found by its address.
        expect(() => getMultiSigMerkleProof(tree.tree, a)).not.toThrow();
        expect(() => buildMultiSigTree([toHex(BN254_FIELD_MODULUS)], "poseidon-hash")).toThrow(InvalidArgumentError);
        expect(() => buildMultiSigTree(["abc"], "poseidon-hash")).toThrow(InvalidArgumentError);
        expect(() => buildMultiSigTree([toHex(1n), "1"], "poseidon-hash")).toThrow(/duplicate/);
    });

    it("produces valid membership proofs for every member and rejects outsiders", () => {
        for (let n = 1; n <= MAX_SIGNERS; n++) {
            const signers = ADDRESSES.slice(0, n);
            const tree = buildMultiSigTree(signers);
            for (const signer of signers) {
                const proof = getMultiSigMerkleProof(tree.tree, signer);
                let node = computeSignerLeaf(signer);
                for (let i = 0; i < proof.merkle_proof_length; i++) {
                    const sibling = BigInt(proof.merkle_proof_siblings[i]);
                    node = proof.merkle_proof_indices[i] ? signersHash(sibling, node) : signersHash(node, sibling);
                }
                expect(node).toBe(tree.signersRoot);
            }
            expect(() => getMultiSigMerkleProof(tree.tree, ADDRESSES[10])).toThrow(NotFoundError);
        }
    });

    it("a 5-signer set fits the circuit depth", () => {
        expect(buildMultiSigTree(ADDRESSES.slice(0, MAX_SIGNERS)).tree.depth).toBeLessThanOrEqual(4);
    });
});

describe("createMultiSigState", () => {
    const signers = ADDRESSES.slice(0, 3);

    it("derives the tree, roots and canonical signer order", () => {
        const state = createMultiSigState({ signers: [...signers].reverse(), threshold: 2, salt: SALT });
        expect(state.signers).toEqual(sortSigners(signers));
        expect(state.signersRoot).toBe(buildMultiSigTree(signers).signersRoot);
        expect(state.stateRoot).toBe(computeStateRoot(state.signersRoot, 2, SALT));
        expect(state.signersFormat).toBe("address");
        expect(state.salt).toBe(SALT);
    });

    it("generates a fresh salt when none is given", () => {
        const a = createMultiSigState({ signers, threshold: 1 });
        const b = createMultiSigState({ signers, threshold: 1 });
        expect(a.salt).not.toBe(b.salt);
        expect(a.stateRoot).not.toBe(b.stateRoot);
    });

    it("rejects thresholds the circuit could never satisfy", () => {
        expect(() => createMultiSigState({ signers, threshold: 4, salt: SALT })).toThrow(/no proof could ever/);
        expect(() => createMultiSigState({ signers, threshold: 0, salt: SALT })).toThrow(InvalidArgumentError);
        expect(() => createMultiSigState({ signers, threshold: 6, salt: SALT })).toThrow(InvalidArgumentError);
        expect(() => createMultiSigState({ signers, threshold: 2, salt: 0n })).toThrow(InvalidArgumentError);
    });

    it("round-trips through the backup format", () => {
        const state = createMultiSigState({ signers, threshold: 2, salt: SALT });
        const json = serializeMultiSigState(state);
        const restored = parseMultiSigState(json);
        expect(restored.stateRoot).toBe(state.stateRoot);
        expect(restored.salt).toBe(SALT);
        expect(restored.signers).toEqual(state.signers);
        expect(JSON.parse(json)).toMatchObject({ version: 1, threshold: 2, signersFormat: "address" });
    });

    it("round-trips Poseidon-leaf configurations", () => {
        const leaves = signers.map((s) => toHex(computeSignerLeaf(s)));
        const state = createMultiSigState({
            signers: leaves,
            threshold: 2,
            salt: SALT,
            signersFormat: "poseidon-hash",
        });
        expect(parseMultiSigState(serializeMultiSigState(state)).stateRoot).toBe(state.stateRoot);
    });

    it("detects a corrupted or inconsistent backup at restore time", () => {
        const state = createMultiSigState({ signers, threshold: 2, salt: SALT });
        const data = JSON.parse(serializeMultiSigState(state)) as Record<string, unknown>;
        const parse = (patch: Record<string, unknown>) => () =>
            parseMultiSigState(JSON.stringify({ ...data, ...patch }));

        expect(parse({ stateRoot: toHex(state.stateRoot + 1n, { size: 32 }) })).toThrow(/inconsistent/);
        expect(parse({ salt: saltToHex(SALT + 1n) })).toThrow(/inconsistent/);
        expect(parse({ threshold: 3 })).toThrow(/inconsistent/);
        expect(parse({ stateRoot: "garbage" })).toThrow(/inconsistent/);
        expect(parse({ version: 2 })).toThrow(/Unsupported backup version/);
        expect(parse({ salt: undefined })).toThrow(/Missing private salt/);
        expect(parse({ signers: "nope" })).toThrow(/missing signers/);
        expect(() => parseMultiSigState("{not json")).toThrow(/not valid JSON/);
        expect(() => parseMultiSigState("null")).toThrow(/JSON object/);

        // Without a stored root the backup is still accepted.
        const { stateRoot: _omit, ...withoutRoot } = data;
        expect(parseMultiSigState(JSON.stringify(withoutRoot)).stateRoot).toBe(state.stateRoot);
    });

    it("never serialises accidentally: bigint fields make JSON.stringify of the raw state throw", () => {
        const state = createMultiSigState({ signers, threshold: 2, salt: SALT });
        expect(() => JSON.stringify(state)).toThrow(TypeError);
    });
});
