import { LeanIMT as UpstreamLeanIMT } from "@zk-kit/lean-imt";
import { poseidon } from "@iden3/js-crypto";
import { describe, expect, it } from "vitest";
import { InvalidArgumentError, NotFoundError, TreeCapacityError } from "../src/errors.js";
import {
    LeanIMT,
    assertPaddedProof,
    assertTreeCapacity,
    buildTree,
    generatePaddedProof,
} from "../src/internal/merkle.js";

const hash = (a: bigint, b: bigint) => poseidon.hash([a, b]);
const leaf = (i: number) => BigInt(i + 1) * 1_000_003n;

describe("LeanIMT (differential vs @zk-kit/lean-imt)", () => {
    it.each(Array.from({ length: 70 }, (_, i) => i + 1))("matches upstream for %i leaves", (n) => {
        const ours = new LeanIMT(hash);
        const upstream = new UpstreamLeanIMT(hash);
        for (let i = 0; i < n; i++) {
            ours.insert(leaf(i));
            upstream.insert(leaf(i));
            expect(ours.root).toBe(upstream.root);
        }

        expect(ours.depth).toBe(upstream.depth);
        expect(ours.size).toBe(upstream.size);
        expect(ours.leaves).toEqual(upstream.leaves);

        for (let i = 0; i < n; i++) {
            expect(ours.indexOf(leaf(i))).toBe(i);
            expect(ours.has(leaf(i))).toBe(true);
            expect(ours.generateProof(i)).toEqual(upstream.generateProof(i));
        }
    });

    it("reports missing leaves", () => {
        const tree = new LeanIMT(hash);
        tree.insert(1n);
        expect(tree.indexOf(2n)).toBe(-1);
        expect(tree.has(2n)).toBe(false);
    });

    it("throws a typed error for an empty tree root", () => {
        expect(() => new LeanIMT(hash).root).toThrow(InvalidArgumentError);
    });

    it("rejects non-bigint leaves", () => {
        expect(() => new LeanIMT(hash).insert(1 as unknown as bigint)).toThrow(InvalidArgumentError);
    });

    it.each([-1, 1, 0.5, Number.NaN])("rejects proof index %s", (index) => {
        const tree = new LeanIMT(hash);
        tree.insert(1n);
        expect(() => tree.generateProof(index)).toThrow(NotFoundError);
    });

    it("returns a copy of the leaves", () => {
        const tree = new LeanIMT(hash);
        tree.insert(1n);
        tree.leaves.push(99n);
        expect(tree.size).toBe(1);
    });
});

describe("proof verification against the circuit's hashing rule", () => {
    it("recomputes the root from a padded proof (mirrors merkle_root_with_depth)", () => {
        const tree = buildTree(
            Array.from({ length: 11 }, (_, i) => leaf(i)),
            hash,
            4,
            "t",
        );

        for (let i = 0; i < 11; i++) {
            const proof = generatePaddedProof(tree, leaf(i), 4, () => "missing");
            let node = leaf(i);
            for (let level = 0; level < proof.merkle_proof_length; level++) {
                const sibling = BigInt(proof.merkle_proof_siblings[level]);
                node = proof.merkle_proof_indices[level] ? hash(sibling, node) : hash(node, sibling);
            }
            expect(node).toBe(tree.root);
        }
    });
});

describe("generatePaddedProof", () => {
    const tree = buildTree([leaf(0), leaf(1), leaf(2)], hash, 4, "t");

    it("pads siblings with 0x0 and indices with false", () => {
        const proof = generatePaddedProof(tree, leaf(0), 4, () => "missing");
        expect(proof.merkle_proof_siblings).toHaveLength(4);
        expect(proof.merkle_proof_indices).toHaveLength(4);
        expect(proof.merkle_proof_siblings.slice(proof.merkle_proof_length).every((s) => s === "0x0")).toBe(true);
        expect(proof.merkle_proof_indices.slice(proof.merkle_proof_length).every((b) => b === false)).toBe(true);
    });

    it("uses a compact proof for a promoted (sibling-less) node", () => {
        // Leaf 2 of 3 has no sibling at level 0, so its proof has a single hash.
        expect(generatePaddedProof(tree, leaf(2), 4, () => "missing").merkle_proof_length).toBe(1);
    });

    it("throws NotFoundError with the supplied message", () => {
        expect(() => generatePaddedProof(tree, 12345n, 4, () => "nope")).toThrow(new NotFoundError("nope"));
    });

    it("throws TreeCapacityError when the proof is deeper than the circuit", () => {
        const deep = new LeanIMT(hash);
        for (let i = 0; i < 17; i++) deep.insert(leaf(i));
        expect(() => generatePaddedProof(deep, leaf(0), 4, () => "missing")).toThrow(TreeCapacityError);
    });
});

describe("buildTree / assertTreeCapacity", () => {
    it("rejects an empty leaf set", () => {
        expect(() => buildTree([], hash, 4, "Signers tree")).toThrow(/at least one entry/);
    });

    it("accepts exactly 2 ** depth leaves and rejects one more", () => {
        expect(() =>
            buildTree(
                Array.from({ length: 16 }, (_, i) => leaf(i)),
                hash,
                4,
                "t",
            ),
        ).not.toThrow();
        expect(() =>
            buildTree(
                Array.from({ length: 17 }, (_, i) => leaf(i)),
                hash,
                4,
                "t",
            ),
        ).toThrow(TreeCapacityError);
    });

    it("assertTreeCapacity names the offending structure", () => {
        expect(() => assertTreeCapacity(65, 6, "Scope tree")).toThrow(/Scope tree.*65.*64/);
    });
});

describe("assertPaddedProof", () => {
    const valid = {
        merkle_proof_length: 1,
        merkle_proof_indices: [false, false, false, false],
        merkle_proof_siblings: ["0x1", "0x0", "0x0", "0x0"] as `0x${string}`[],
    };

    it("accepts a well-formed proof", () => {
        expect(() => assertPaddedProof(valid, 4)).not.toThrow();
    });

    it.each([
        ["undefined proof", undefined],
        ["negative length", { ...valid, merkle_proof_length: -1 }],
        ["length above depth", { ...valid, merkle_proof_length: 5 }],
        ["fractional length", { ...valid, merkle_proof_length: 0.5 }],
        ["short indices", { ...valid, merkle_proof_indices: [false] }],
        ["short siblings", { ...valid, merkle_proof_siblings: ["0x1"] as `0x${string}`[] }],
    ])("rejects %s", (_name, proof) => {
        expect(() => assertPaddedProof(proof as never, 4)).toThrow(InvalidArgumentError);
    });
});
