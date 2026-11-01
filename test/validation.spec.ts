import { describe, expect, it } from "vitest";
import {
    InvalidArgumentError,
    InvalidCircuitError,
    MissingPeerDependencyError,
    NotFoundError,
    ProofGenerationError,
    TreeCapacityError,
    ZKSdkError,
} from "../src/errors.js";
import { assertCircuit } from "../src/internal/compiled-circuit.js";
import {
    BN254_FIELD_MODULUS,
    assertAddress,
    assertBytes,
    assertField,
    assertHex,
    assertHexBytes,
    assertInteger,
    assertNonEmptyArray,
    toFieldElement,
} from "../src/internal/validation.js";

describe("typed errors", () => {
    it.each([
        [new InvalidArgumentError("x"), "INVALID_ARGUMENT"],
        [new NotFoundError("x"), "NOT_FOUND"],
        [new TreeCapacityError("x"), "TREE_CAPACITY_EXCEEDED"],
        [new InvalidCircuitError("x"), "INVALID_CIRCUIT"],
        [new MissingPeerDependencyError("pkg"), "MISSING_PEER_DEPENDENCY"],
        [new ProofGenerationError("x"), "PROOF_GENERATION_FAILED"],
    ])("%s carries a stable code", (error, code) => {
        expect(error).toBeInstanceOf(ZKSdkError);
        expect(error).toBeInstanceOf(Error);
        expect(error.code).toBe(code);
        expect(error.name).toBe(error.constructor.name);
    });

    it("preserves the underlying cause", () => {
        const cause = new Error("root cause");
        expect(new ProofGenerationError("failed", cause).cause).toBe(cause);
        expect(new MissingPeerDependencyError("pkg", cause).cause).toBe(cause);
    });

    it("tells the user how to install a missing peer", () => {
        expect(new MissingPeerDependencyError("@aztec/bb.js").message).toContain("pnpm add @aztec/bb.js");
    });
});

describe("assertAddress", () => {
    it.each(["0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"])(
        "accepts %s",
        (address) => {
            expect(() => assertAddress(address, "a")).not.toThrow();
        },
    );

    it.each([
        ["bad checksum", "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92267"],
        ["too short", "0x1234"],
        ["not hex", "0xZZ9fd6e51aad88f6f4ce6ab8827279cfffb92266"],
        ["no prefix", "f39fd6e51aad88f6f4ce6ab8827279cfffb92266"],
        ["number", 123],
        ["null", null],
        ["undefined", undefined],
    ])("rejects %s", (_name, value) => {
        expect(() => assertAddress(value, "signer")).toThrow(InvalidArgumentError);
    });
});

describe("assertBytes", () => {
    it("normalises Uint8Array to number[]", () => {
        expect(assertBytes(Uint8Array.from([1, 2]), 2, "b")).toEqual([1, 2]);
    });

    it.each([
        ["wrong length", [1, 2, 3]],
        ["out of range", [1, 256]],
        ["negative", [1, -1]],
        ["fractional", [1, 1.5]],
        ["non-number", [1, "2"]],
        ["not an array", "ab"],
        ["null", null],
    ])("rejects %s", (_name, value) => {
        expect(() => assertBytes(value, 2, "b")).toThrow(InvalidArgumentError);
    });
});

describe("assertHexBytes / assertHex", () => {
    it("accepts exact-length hex", () => {
        expect(assertHexBytes("0x" + "ab".repeat(32), 32, "h")).toBe("0x" + "ab".repeat(32));
        expect(assertHex("0x", "p")).toBe("0x");
        expect(assertHex("0xabcd", "p")).toBe("0xabcd");
    });

    it.each(["0x" + "ab".repeat(31), "ab".repeat(32), "0xzz", 5, null])("rejects %s as 32 bytes", (value) => {
        expect(() => assertHexBytes(value, 32, "h")).toThrow(InvalidArgumentError);
    });

    it.each(["0xabc", "abcd", 5])("rejects %s as hex", (value) => {
        expect(() => assertHex(value, "p")).toThrow(InvalidArgumentError);
    });
});

describe("field element validation", () => {
    it("accepts the boundary values", () => {
        expect(assertField(0n, "f")).toBe(0n);
        expect(assertField(BN254_FIELD_MODULUS - 1n, "f")).toBe(BN254_FIELD_MODULUS - 1n);
    });

    it.each([-1n, BN254_FIELD_MODULUS, BN254_FIELD_MODULUS + 1n, 1, "1", null])("rejects %s", (value) => {
        expect(() => assertField(value, "f")).toThrow(InvalidArgumentError);
    });

    it("toFieldElement accepts bigint and hex", () => {
        expect(toFieldElement(7n, "f")).toBe(7n);
        expect(toFieldElement("0x07", "f")).toBe(7n);
    });

    it.each(["7", "0x", "0xzz", BN254_FIELD_MODULUS, "0x" + "ff".repeat(32), {}])(
        "toFieldElement rejects %s",
        (value) => {
            expect(() => toFieldElement(value, "f")).toThrow(InvalidArgumentError);
        },
    );
});

describe("assertNonEmptyArray / assertInteger", () => {
    it("validates arrays", () => {
        expect(() => assertNonEmptyArray([1], "a")).not.toThrow();
        expect(() => assertNonEmptyArray([], "a")).toThrow(InvalidArgumentError);
        expect(() => assertNonEmptyArray("x", "a")).toThrow(InvalidArgumentError);
    });

    it("validates integers in range", () => {
        expect(assertInteger(3, "i", 0, 4)).toBe(3);
        for (const bad of [-1, 5, 1.5, "1", Number.NaN]) {
            expect(() => assertInteger(bad, "i", 0, 4)).toThrow(InvalidArgumentError);
        }
    });
});

describe("assertCircuit", () => {
    const expected = ["a", "b"] as const;
    const artifact = { bytecode: "AAAA", abi: { parameters: [{ name: "a" }, { name: "b" }] } };

    it("accepts a matching artifact and returns it unchanged", () => {
        expect(assertCircuit(artifact, "c", expected)).toBe(artifact);
    });

    it.each([
        ["null", null],
        ["a string", "circuit.json"],
        ["missing bytecode", { abi: artifact.abi }],
        ["empty bytecode", { ...artifact, bytecode: "" }],
        ["missing abi", { bytecode: "AAAA" }],
        ["a different circuit", { ...artifact, abi: { parameters: [{ name: "a" }, { name: "z" }] } }],
        ["extra parameters", { ...artifact, abi: { parameters: [{ name: "a" }, { name: "b" }, { name: "c" }] } }],
        ["reordered parameters", { ...artifact, abi: { parameters: [{ name: "b" }, { name: "a" }] } }],
    ])("rejects %s", (_name, circuit) => {
        expect(() => assertCircuit(circuit, "c", expected)).toThrow(InvalidCircuitError);
    });

    it("explains which parameters were found", () => {
        expect(() => assertCircuit({ ...artifact, abi: { parameters: [{ name: "x" }] } }, "c", expected)).toThrow(
            /expected parameters \[a, b\] but found \[x\]/,
        );
    });
});
