import { poseidon } from "@iden3/js-crypto";
import { decodeAbiParameters, parseAbiParameters, toHex, type Hex } from "viem";
import { describe, expect, it, vi } from "vitest";
import { InvalidArgumentError, InvalidCircuitError, NotFoundError, TreeCapacityError } from "../src/errors.js";
import {
    LABELS_MAX_DEPTH,
    LABEL_NAME_BYTES,
    addressToBytes,
    addressToField,
    buildLabelBindingCircuitInput,
    buildLabelBindingCircuitInputFromProof,
    buildLabelsTree,
    computeLabelCommitment,
    computeLabelLeaf,
    createZKLabels,
    encodeLabelBindingPublicInputs,
    encodeLabelProofCalldata,
    encodeLabelsInitData,
    encodeUpdateRegistryRootData,
    getLabelMerkleProof,
    labelBytesToField,
    labelNameToBytes,
    labelNameToField,
    labelsHash,
    type LabelEntry,
} from "../src/zk-label/index.js";
import { ADDRESSES } from "./helpers.js";

const [a0, a1, a2] = ADDRESSES;
const entries: LabelEntry[] = [
    { labelName: "admin", signer: a0 },
    { labelName: "operator", signer: a1 },
    { labelName: "auditor", signer: a2 },
];

const fakeCircuit = {
    bytecode: "AAAA",
    abi: {
        parameters: [
            "address_bytes",
            "label_bytes",
            "merkle_proof_length",
            "merkle_proof_indices",
            "merkle_proof_siblings",
            "registry_root",
            "label_commitment",
        ].map((name) => ({ name })),
    },
};

describe("label encoding", () => {
    it("right-pads UTF-8 to 31 bytes (spec: lib/zk_labels)", () => {
        const bytes = labelNameToBytes("admin");
        expect(bytes).toHaveLength(LABEL_NAME_BYTES);
        expect(bytes.slice(0, 5)).toEqual([97, 100, 109, 105, 110]);
        expect(bytes.slice(5).every((b) => b === 0)).toBe(true);
    });

    it("counts bytes, not characters", () => {
        expect(labelNameToBytes("é").slice(0, 2)).toEqual([0xc3, 0xa9]);
        expect(() => labelNameToBytes("é".repeat(16))).toThrow(/32 bytes/);
        expect(() => labelNameToBytes("é".repeat(15))).not.toThrow();
    });

    it("accepts exactly 31 bytes and rejects 32", () => {
        expect(() => labelNameToBytes("a".repeat(31))).not.toThrow();
        expect(() => labelNameToBytes("a".repeat(32))).toThrow(InvalidArgumentError);
    });

    it("accepts the empty label (all-zero field)", () => {
        expect(labelNameToField("")).toBe(0n);
    });

    it("rejects non-string labels", () => {
        expect(() => labelNameToBytes(5 as never)).toThrow(InvalidArgumentError);
        expect(() => labelNameToBytes(null as never)).toThrow(InvalidArgumentError);
    });

    it("converts bytes to a big-endian field element", () => {
        expect(labelBytesToField([...new Array(29).fill(0), 1, 2])).toBe(0x0102n);
        expect(labelNameToField("a")).toBe(0x61n << (30n * 8n));
        expect(() => labelBytesToField([1, 2])).toThrow(InvalidArgumentError);
    });

    it("the longest label stays below the BN254 modulus", () => {
        expect(labelNameToField("\u00ff".repeat(15) + "z")).toBeLessThan(
            21888242871839275222246405745257275088548364400416034343698204186575808495617n,
        );
    });

    it("encodes addresses as a field and 20 bytes", () => {
        expect(addressToField(a0)).toBe(BigInt(a0.toLowerCase()));
        expect(addressToBytes(a0)).toHaveLength(20);
        expect(toHex(Uint8Array.from(addressToBytes(a0)))).toBe(a0.toLowerCase());
        expect(() => addressToField("0x12" as never)).toThrow(InvalidArgumentError);
        expect(() => addressToBytes("0x12" as never)).toThrow(InvalidArgumentError);
    });
});

describe("leaf and commitment", () => {
    it("leaf = Poseidon2(Poseidon1(label), Poseidon1(address)) and equals the commitment", () => {
        const expected = poseidon.hash([
            poseidon.hash([labelNameToField("admin")]),
            poseidon.hash([addressToField(a0)]),
        ]);
        expect(computeLabelLeaf("admin", a0)).toBe(expected);
        expect(computeLabelCommitment("admin", a0)).toBe(expected);
    });

    it("binds the label to the address", () => {
        expect(computeLabelLeaf("admin", a0)).not.toBe(computeLabelLeaf("admin", a1));
        expect(computeLabelLeaf("admin", a0)).not.toBe(computeLabelLeaf("operator", a0));
    });

    it("labelsHash is Poseidon2", () => {
        expect(labelsHash(3n, 4n)).toBe(poseidon.hash([3n, 4n]));
    });
});

describe("buildLabelsTree", () => {
    it("builds a deterministic tree", () => {
        const tree = buildLabelsTree(entries);
        expect(tree.leaves).toEqual(entries.map((e) => computeLabelLeaf(e.labelName, e.signer)));
        expect(buildLabelsTree(entries).registryRoot).toBe(tree.registryRoot);
    });

    it("rejects an empty registry", () => {
        expect(() => buildLabelsTree([])).toThrow(InvalidArgumentError);
    });

    it("enforces the 2 ** LABELS_MAX_DEPTH capacity", () => {
        const make = (n: number) => ADDRESSES.slice(0, n).map((signer) => ({ labelName: "x", signer }));
        expect(() => buildLabelsTree(make(2 ** LABELS_MAX_DEPTH))).not.toThrow();
        expect(() => buildLabelsTree(make(2 ** LABELS_MAX_DEPTH + 1))).toThrow(TreeCapacityError);
    });

    it("rejects invalid entries", () => {
        expect(() => buildLabelsTree([{ labelName: "a".repeat(40), signer: a0 }])).toThrow(InvalidArgumentError);
        expect(() => buildLabelsTree([{ labelName: "a", signer: "0x1" as never }])).toThrow(InvalidArgumentError);
    });

    it("proves membership for every entry and rejects non-members", () => {
        const tree = buildLabelsTree(entries);
        for (const { labelName, signer } of entries) {
            const proof = getLabelMerkleProof(tree.tree, labelName, signer);
            let node = computeLabelLeaf(labelName, signer);
            for (let i = 0; i < proof.merkle_proof_length; i++) {
                const sibling = BigInt(proof.merkle_proof_siblings[i]);
                node = proof.merkle_proof_indices[i] ? labelsHash(sibling, node) : labelsHash(node, sibling);
            }
            expect(node).toBe(tree.registryRoot);
        }
        expect(() => getLabelMerkleProof(tree.tree, "admin", a1)).toThrow(NotFoundError);
        expect(() => getLabelMerkleProof(tree.tree, "root", a0)).toThrow(/not found/);
    });
});

describe("circuit input", () => {
    const tree = buildLabelsTree(entries);

    it("builds circuit-shaped input", () => {
        const input = buildLabelBindingCircuitInput("operator", a1, tree.tree, tree.registryRoot);
        expect(input.label_bytes).toEqual(labelNameToBytes("operator"));
        expect(input.address_bytes).toEqual(addressToBytes(a1));
        expect(input.registry_root).toBe(toHex(tree.registryRoot));
        expect(input.label_commitment).toBe(toHex(computeLabelCommitment("operator", a1)));
        expect(input.merkle_proof_indices).toHaveLength(LABELS_MAX_DEPTH);
    });

    it("validates the root and proof shape in the from-proof overload", () => {
        const proof = getLabelMerkleProof(tree.tree, "admin", a0);
        expect(() => buildLabelBindingCircuitInputFromProof("admin", a0, proof, 1n << 255n)).toThrow(
            InvalidArgumentError,
        );
        expect(() =>
            buildLabelBindingCircuitInputFromProof(
                "admin",
                a0,
                { ...proof, merkle_proof_siblings: [] },
                tree.registryRoot,
            ),
        ).toThrow(InvalidArgumentError);
    });

    it("rejects a pair that is not in the tree", () => {
        expect(() => buildLabelBindingCircuitInput("admin", a2, tree.tree, tree.registryRoot)).toThrow(NotFoundError);
    });
});

describe("ABI encoding", () => {
    const root = buildLabelsTree(entries).registryRoot;
    const commitment = computeLabelCommitment("admin", a0);

    it("encodeLabelBindingPublicInputs", () => {
        const encoded = encodeLabelBindingPublicInputs(root, toHex(commitment));
        const [r, c] = decodeAbiParameters(parseAbiParameters("bytes32, bytes32"), encoded);
        expect(BigInt(r)).toBe(root);
        expect(BigInt(c)).toBe(commitment);
        expect(() => encodeLabelBindingPublicInputs(-1n, commitment)).toThrow(InvalidArgumentError);
    });

    it("encodeLabelsInitData", () => {
        const [r] = decodeAbiParameters(parseAbiParameters("bytes32"), encodeLabelsInitData(root));
        expect(BigInt(r)).toBe(root);
    });

    it("encodeUpdateRegistryRootData", () => {
        const encoded = encodeUpdateRegistryRootData(root, commitment, "0xabcd");
        const [r, c, p] = decodeAbiParameters(parseAbiParameters("bytes32, bytes32, bytes"), encoded);
        expect([BigInt(r), BigInt(c), p]).toEqual([root, commitment, "0xabcd"]);
        expect(() => encodeUpdateRegistryRootData(root, commitment, "abcd" as Hex)).toThrow(InvalidArgumentError);
    });

    it("encodeLabelProofCalldata", () => {
        const data = {
            proof: "0xdead" as Hex,
            publicInputs: [] as Hex[],
            registryRoot: toHex(root, { size: 32 }),
            labelCommitment: toHex(commitment, { size: 32 }),
        };
        const [p, r, c] = decodeAbiParameters(
            parseAbiParameters("bytes, bytes32, bytes32"),
            encodeLabelProofCalldata(data),
        );
        expect([p, r, c]).toEqual(["0xdead", data.registryRoot, data.labelCommitment]);
        expect(() => encodeLabelProofCalldata({ ...data, registryRoot: "0x01" })).toThrow(InvalidArgumentError);
    });
});

describe("createZKLabels", () => {
    it("validates the circuit up-front", () => {
        expect(() => createZKLabels(entries, { bytecode: "x" })).toThrow(InvalidCircuitError);
        expect(() => createZKLabels(entries, undefined)).toThrow(InvalidCircuitError);
    });

    it("exposes the registry root and membership queries", () => {
        const zk = createZKLabels(entries, fakeCircuit);
        expect(BigInt(zk.registryRoot)).toBe(buildLabelsTree(entries).registryRoot);
        expect(zk.hasLabel("admin", a0)).toBe(true);
        expect(zk.hasLabel("admin", a1)).toBe(false);
        expect(zk.computeLabelCommitment("admin", a0)).toBe(computeLabelCommitment("admin", a0));
    });

    it("addLabel returns the new root and matches a fresh build", () => {
        const zk = createZKLabels(entries.slice(0, 2), fakeCircuit);
        const root = zk.addLabel(entries[2]);
        expect(BigInt(root)).toBe(buildLabelsTree(entries).registryRoot);
        expect(zk.registryRoot).toBe(root);
        expect(zk.hasLabel("auditor", a2)).toBe(true);
    });

    it("a failed addLabel leaves the registry untouched", () => {
        const zk = createZKLabels(entries, fakeCircuit);
        const before = zk.registryRoot;
        expect(() => zk.addLabel({ labelName: "x".repeat(40), signer: a0 })).toThrow(InvalidArgumentError);
        expect(() => zk.addLabel({ labelName: "x", signer: "0x1" as never })).toThrow(InvalidArgumentError);
        expect(zk.registryRoot).toBe(before);
        expect(zk.hasLabel("x", a0)).toBe(false);
    });

    it("addLabel refuses to exceed the circuit capacity, leaving state unchanged", () => {
        const full = ADDRESSES.slice(0, 16).map((signer) => ({ labelName: "m", signer }));
        const zk = createZKLabels(full, fakeCircuit);
        const before = zk.registryRoot;
        expect(() => zk.addLabel({ labelName: "m", signer: ADDRESSES[16] })).toThrow(TreeCapacityError);
        expect(zk.registryRoot).toBe(before);
    });

    it("removeLabel rebuilds the tree and matches a fresh build", () => {
        const zk = createZKLabels(entries, fakeCircuit);
        const root = zk.removeLabel(entries[1]);
        expect(BigInt(root)).toBe(buildLabelsTree([entries[0], entries[2]]).registryRoot);
        expect(zk.hasLabel("operator", a1)).toBe(false);
    });

    it("removeLabel works regardless of address casing", () => {
        const zk = createZKLabels(entries, fakeCircuit);
        zk.removeLabel({ labelName: "operator", signer: a1.toLowerCase() as Hex });
        expect(zk.hasLabel("operator", a1)).toBe(false);
        expect(BigInt(zk.registryRoot)).toBe(buildLabelsTree([entries[0], entries[2]]).registryRoot);
    });

    it("removeLabel reports unknown entries and refuses to empty the registry", () => {
        const zk = createZKLabels(entries, fakeCircuit);
        expect(() => zk.removeLabel({ labelName: "ghost", signer: a0 })).toThrow(NotFoundError);

        const single = createZKLabels([entries[0]], fakeCircuit);
        expect(() => single.removeLabel(entries[0])).toThrow(/last label/);
        expect(single.hasLabel("admin", a0)).toBe(true);
    });

    it("does not alias the caller's entry objects", () => {
        const input = entries.map((e) => ({ ...e }));
        const zk = createZKLabels(input, fakeCircuit);
        input[0].labelName = "mutated";
        zk.addLabel({ labelName: "extra", signer: ADDRESSES[5] });
        expect(zk.hasLabel("admin", a0)).toBe(true);
    });

    it("delegates proving with the validated circuit and shared options", async () => {
        const prove = vi.fn();
        vi.resetModules();
        vi.doMock("../src/zk-label/prove.js", async (original) => ({
            ...(await original<typeof import("../src/zk-label/prove.js")>()),
            generateLabelBindingProof: prove.mockResolvedValue("PROOF"),
        }));
        const { createZKLabels: create } = await import("../src/zk-label/ZKLabelsHelper.js");
        const options = { barretenberg: { destroy: async () => {} } };
        const zk = create(entries, fakeCircuit, options);

        await expect(zk.proveLabelMembership("admin", a0)).resolves.toBe("PROOF");
        expect(prove).toHaveBeenCalledWith(
            "admin",
            a0,
            expect.objectContaining({ registryRoot: expect.any(BigInt) }),
            fakeCircuit,
            options,
        );
        vi.doUnmock("../src/zk-label/prove.js");
    });
});
