import { describe, expect, it } from "vitest";
import { poseidon } from "../src/internal/poseidon.js";

describe("poseidon facade", () => {
    it("matches the circom/iden3 reference vector Poseidon(1, 2)", () => {
        expect(poseidon.hash([1n, 2n])).toBe(
            7853200120776062878684798364095072458815029376092732009249414926327459813530n,
        );
    });

    it("is deterministic and input-order sensitive", () => {
        expect(poseidon.hash([1n, 2n])).toBe(poseidon.hash([1n, 2n]));
        expect(poseidon.hash([2n, 1n])).not.toBe(poseidon.hash([1n, 2n]));
    });

    it("supports the 1- and 4-input arities used by the SDK", () => {
        expect(typeof poseidon.hash([1n])).toBe("bigint");
        expect(typeof poseidon.hash([1n, 2n, 3n, 4n])).toBe("bigint");
    });
});
