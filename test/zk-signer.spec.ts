import { secp256k1 } from "@noble/curves/secp256k1";
import { poseidon } from "@iden3/js-crypto";
import { decodeAbiParameters, parseAbiParameters, toHex, type Hex } from "viem";
import { describe, expect, it } from "vitest";
import { InvalidArgumentError, NotFoundError, TreeCapacityError } from "../src/errors.js";
import {
    NIL_PUBKEY,
    SIGNERS_MAX_DEPTH,
    buildSignersTree,
    buildZKSignerCircuitInput,
    buildZKSignerCircuitInputFromProof,
    computeSignerLeaf,
    encodeSignersInitData,
    encodeZKSignerProofCalldata,
    encodeZKSignerPublicInputs,
    getSignerMerkleProof,
    parsePubKey,
    parseSignature,
    signerToField,
    signersHash,
    type SignersTree,
} from "../src/zk-signer/index.js";
import { ADDRESSES, HARDHAT_0, signRaw, testHash, testKey } from "./helpers.js";

const alice = testKey("alice");
const bob = testKey("bob");
const hash = testHash("tx-1");

function treeOf(...addresses: `0x${string}`[]): SignersTree {
    return buildSignersTree(addresses.map((signer) => ({ signer })));
}

describe("leaf encoding", () => {
    it("matches the golden vector in the Noir zk_signers test (Hardhat #0)", () => {
        // From noir/circuits/zk_signers/src/main.nr :: test_ceo_single_signer
        expect(computeSignerLeaf(HARDHAT_0)).toBe(
            7883074409468045280407067478175608582487155714151013737870117867970375847717n,
        );
    });

    it("encodes the address as a big-endian field element, case-insensitively", () => {
        expect(signerToField(HARDHAT_0)).toBe(0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266n);
        expect(signerToField(HARDHAT_0.toLowerCase() as `0x${string}`)).toBe(signerToField(HARDHAT_0));
    });

    it("leaf is Poseidon1(address) and node hash is Poseidon2", () => {
        expect(computeSignerLeaf(alice.address)).toBe(poseidon.hash([signerToField(alice.address)]));
        expect(signersHash(1n, 2n)).toBe(poseidon.hash([1n, 2n]));
    });

    it("rejects invalid addresses before hashing", () => {
        expect(() => computeSignerLeaf("0x1234")).toThrow(InvalidArgumentError);
        expect(() => signerToField("nope" as never)).toThrow(InvalidArgumentError);
    });
});

describe("buildSignersTree", () => {
    it("for a single signer the root equals the leaf (depth 0)", () => {
        const tree = treeOf(HARDHAT_0);
        expect(tree.signersRoot).toBe(computeSignerLeaf(HARDHAT_0));
        expect(tree.leaves).toEqual([computeSignerLeaf(HARDHAT_0)]);
    });

    it("is deterministic and order-sensitive", () => {
        const a = treeOf(alice.address, bob.address).signersRoot;
        expect(treeOf(alice.address, bob.address).signersRoot).toBe(a);
        expect(treeOf(bob.address, alice.address).signersRoot).not.toBe(a);
        expect(a).toBe(signersHash(computeSignerLeaf(alice.address), computeSignerLeaf(bob.address)));
    });

    it("rejects an empty signer set instead of returning an undefined root", () => {
        expect(() => buildSignersTree([])).toThrow(InvalidArgumentError);
    });

    it("supports the maximum of 2 ** SIGNERS_MAX_DEPTH signers and rejects more", () => {
        const max = 2 ** SIGNERS_MAX_DEPTH;
        expect(() => treeOf(...ADDRESSES.slice(0, max))).not.toThrow();
        expect(() => treeOf(...ADDRESSES.slice(0, max + 1))).toThrow(TreeCapacityError);
    });

    it("rejects an invalid address anywhere in the list", () => {
        expect(() => buildSignersTree([{ signer: alice.address }, { signer: "0xdead" as never }])).toThrow(
            InvalidArgumentError,
        );
    });
});

describe("getSignerMerkleProof", () => {
    it("returns padded, circuit-shaped proofs for every member", () => {
        const signers = ADDRESSES.slice(0, 7);
        const tree = treeOf(...signers);

        for (const signer of signers) {
            const proof = getSignerMerkleProof(tree.tree, signer);
            expect(proof.merkle_proof_indices).toHaveLength(SIGNERS_MAX_DEPTH);
            expect(proof.merkle_proof_siblings).toHaveLength(SIGNERS_MAX_DEPTH);

            let node = computeSignerLeaf(signer);
            for (let i = 0; i < proof.merkle_proof_length; i++) {
                const sibling = BigInt(proof.merkle_proof_siblings[i]);
                node = proof.merkle_proof_indices[i] ? signersHash(sibling, node) : signersHash(node, sibling);
            }
            expect(node).toBe(tree.signersRoot);
        }
    });

    it("has length 0 for a single-signer tree", () => {
        const proof = getSignerMerkleProof(treeOf(HARDHAT_0).tree, HARDHAT_0);
        expect(proof.merkle_proof_length).toBe(0);
        expect(proof.merkle_proof_siblings).toEqual(["0x0", "0x0", "0x0", "0x0"]);
    });

    it("throws NotFoundError for a non-member", () => {
        expect(() => getSignerMerkleProof(treeOf(alice.address).tree, bob.address)).toThrow(NotFoundError);
    });
});

describe("buildZKSignerCircuitInput", () => {
    const tree = treeOf(alice.address, bob.address);
    const signature = signRaw(alice.privateKey, Uint8Array.from(hash));

    it("builds the full circuit input for a valid signature", () => {
        const input = buildZKSignerCircuitInput(alice.pubKey, signature, alice.address, tree, hash);
        expect(input.pubkey).toEqual(alice.pubKey);
        expect(input.signature).toEqual(signature);
        expect(input.txn_hash).toEqual(hash);
        expect(input.signers_root).toBe(toHex(tree.signersRoot));
        expect(input.proof_length).toBe(1);
        expect(input.proof_index).toHaveLength(SIGNERS_MAX_DEPTH);
    });

    it("accepts a lower-case signer address", () => {
        expect(() =>
            buildZKSignerCircuitInput(alice.pubKey, signature, alice.address.toLowerCase() as Hex, tree, hash),
        ).not.toThrow();
    });

    it("rejects a signer that is not in the tree", () => {
        const sig = signRaw(bob.privateKey, Uint8Array.from(hash));
        expect(() => buildZKSignerCircuitInput(bob.pubKey, sig, bob.address, treeOf(alice.address), hash)).toThrow(
            NotFoundError,
        );
    });

    it("rejects a public key that does not derive to the declared signer", () => {
        expect(() => buildZKSignerCircuitInput(bob.pubKey, signature, alice.address, tree, hash)).toThrow(/derives to/);
    });

    it("rejects a signature over a different hash", () => {
        expect(() =>
            buildZKSignerCircuitInput(alice.pubKey, signature, alice.address, tree, testHash("another-tx")),
        ).toThrow(/not a valid ECDSA signature/);
    });

    it("rejects a signature by a different key", () => {
        const forged = signRaw(bob.privateKey, Uint8Array.from(hash));
        expect(() => buildZKSignerCircuitInput(alice.pubKey, forged, alice.address, tree, hash)).toThrow(
            /not a valid ECDSA signature/,
        );
    });

    it("rejects a high-S (malleable) signature", () => {
        const n = secp256k1.CURVE.n;
        const s = BigInt("0x" + Buffer.from(signature.slice(32)).toString("hex"));
        const highS = Array.from(Buffer.from((n - s).toString(16).padStart(64, "0"), "hex"));
        expect(() =>
            buildZKSignerCircuitInput(alice.pubKey, [...signature.slice(0, 32), ...highS], alice.address, tree, hash),
        ).toThrow(/low-S/);
    });

    it("rejects a zero s value", () => {
        expect(() =>
            buildZKSignerCircuitInput(
                alice.pubKey,
                [...signature.slice(0, 32), ...new Array(32).fill(0)],
                alice.address,
                tree,
                hash,
            ),
        ).toThrow(/low-S/);
    });

    it("rejects a public key that is not on the curve", () => {
        const offCurve = { x: new Array(32).fill(1), y: new Array(32).fill(2) };
        expect(() => buildZKSignerCircuitInput(offCurve, signature, alice.address, tree, hash)).toThrow(
            InvalidArgumentError,
        );
    });

    it("rejects an invalid signer address", () => {
        expect(() => buildZKSignerCircuitInput(alice.pubKey, signature, "0x1" as never, tree, hash)).toThrow(
            InvalidArgumentError,
        );
    });
});

describe("buildZKSignerCircuitInputFromProof (shape validation)", () => {
    const tree = treeOf(alice.address);
    const proof = getSignerMerkleProof(tree.tree, alice.address);
    const signature = signRaw(alice.privateKey, Uint8Array.from(hash));
    const build = (overrides: Partial<Record<"pubKey" | "signature" | "proof" | "root" | "hash", unknown>> = {}) =>
        buildZKSignerCircuitInputFromProof(
            (overrides.pubKey ?? alice.pubKey) as never,
            (overrides.signature ?? signature) as never,
            (overrides.proof ?? proof) as never,
            (overrides.root ?? tree.signersRoot) as never,
            (overrides.hash ?? hash) as never,
        );

    it("accepts valid inputs", () => {
        expect(build().signers_root).toBe(toHex(tree.signersRoot));
    });

    it.each([
        ["63-byte signature", { signature: signature.slice(0, 63) }],
        ["65-byte signature", { signature: [...signature, 0] }],
        ["31-byte hash", { hash: hash.slice(0, 31) }],
        ["short pubKey.x", { pubKey: { x: [1], y: alice.pubKey.y } }],
        ["missing pubKey", { pubKey: undefined, signature: "x" }],
        ["byte out of range", { signature: [...signature.slice(0, 63), 300] }],
        ["root above the field", { root: 1n << 255n }],
        ["root as number", { root: 5 }],
        ["oversized proof length", { proof: { ...proof, merkle_proof_length: 5 } }],
        ["short sibling array", { proof: { ...proof, merkle_proof_siblings: [] } }],
    ])("rejects %s", (_name, overrides) => {
        expect(() => build(overrides)).toThrow(InvalidArgumentError);
    });
});

describe("parsePubKey / parseSignature", () => {
    const uncompressed = secp256k1.getPublicKey(alice.privateKey, false);

    it("parses an uncompressed key", () => {
        expect(parsePubKey(uncompressed)).toEqual(alice.pubKey);
        expect(parsePubKey(Array.from(uncompressed))).toEqual(alice.pubKey);
    });

    it("rejects compressed, truncated and mis-prefixed keys", () => {
        expect(() => parsePubKey(secp256k1.getPublicKey(alice.privateKey, true))).toThrow(InvalidArgumentError);
        expect(() => parsePubKey(uncompressed.slice(0, 64))).toThrow(InvalidArgumentError);
        expect(() => parsePubKey(Uint8Array.from([0x02, ...uncompressed.slice(1)]))).toThrow(/0x04/);
        expect(() => parsePubKey(null as never)).toThrow(InvalidArgumentError);
    });

    it("splits r and s from 64 or 65 bytes, ignoring v", () => {
        const sig = Uint8Array.from(signRaw(alice.privateKey, Uint8Array.from(hash)));
        const expected = { r: Array.from(sig.slice(0, 32)), s: Array.from(sig.slice(32, 64)) };
        expect(parseSignature(sig)).toEqual(expected);
        expect(parseSignature(Uint8Array.from([...sig, 27]))).toEqual(expected);
    });

    it("rejects any other signature length", () => {
        expect(() => parseSignature(new Uint8Array(63))).toThrow(InvalidArgumentError);
        expect(() => parseSignature(new Uint8Array(66))).toThrow(InvalidArgumentError);
        expect(() => parseSignature(undefined as never)).toThrow(InvalidArgumentError);
    });

    it("NIL_PUBKEY is the secp256k1 generator", () => {
        const g = secp256k1.ProjectivePoint.BASE.toRawBytes(false);
        expect(NIL_PUBKEY).toEqual({ x: Array.from(g.slice(1, 33)), y: Array.from(g.slice(33, 65)) });
    });
});

describe("ABI encoding", () => {
    const root = treeOf(alice.address, bob.address).signersRoot;

    it("encodeSignersInitData = abi.encode(bytes32)", () => {
        const [decoded] = decodeAbiParameters(parseAbiParameters("bytes32"), encodeSignersInitData(root));
        expect(BigInt(decoded)).toBe(root);
        expect(encodeSignersInitData(toHex(root))).toBe(encodeSignersInitData(root));
    });

    it("encodeZKSignerPublicInputs accepts bytes and hex and rejects bad hashes", () => {
        const fromBytes = encodeZKSignerPublicInputs(hash, root);
        const fromHex = encodeZKSignerPublicInputs(toHex(Uint8Array.from(hash)), root);
        expect(fromBytes).toBe(fromHex);

        const [h, r] = decodeAbiParameters(parseAbiParameters("bytes32, bytes32"), fromBytes);
        expect(h).toBe(toHex(Uint8Array.from(hash)));
        expect(BigInt(r)).toBe(root);

        expect(() => encodeZKSignerPublicInputs(hash.slice(1), root)).toThrow(InvalidArgumentError);
        expect(() => encodeZKSignerPublicInputs("0x1234", root)).toThrow(InvalidArgumentError);
    });

    it("rejects a root that is not a field element", () => {
        expect(() => encodeSignersInitData(1n << 255n)).toThrow(InvalidArgumentError);
        expect(() => encodeSignersInitData(-1n)).toThrow(InvalidArgumentError);
    });

    it("encodeZKSignerProofCalldata = abi.encode(bytes, bytes32, bytes32)", () => {
        const proofData = {
            proof: "0xdeadbeef" as Hex,
            publicInputs: [] as Hex[],
            txnHash: toHex(Uint8Array.from(hash)),
            signersRoot: toHex(root, { size: 32 }),
        };
        const [proof, h, r] = decodeAbiParameters(
            parseAbiParameters("bytes, bytes32, bytes32"),
            encodeZKSignerProofCalldata(proofData),
        );
        expect(proof).toBe("0xdeadbeef");
        expect(h).toBe(proofData.txnHash);
        expect(r).toBe(proofData.signersRoot);

        expect(() => encodeZKSignerProofCalldata({ ...proofData, signersRoot: "0x01" })).toThrow(InvalidArgumentError);
        expect(() => encodeZKSignerProofCalldata({ ...proofData, proof: "0xabc" as Hex })).toThrow(
            InvalidArgumentError,
        );
    });
});
