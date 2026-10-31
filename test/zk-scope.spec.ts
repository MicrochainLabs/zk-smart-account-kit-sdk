import { poseidon } from "@iden3/js-crypto";
import { decodeAbiParameters, parseAbiParameters, toHex, type Hex } from "viem";
import { describe, expect, it } from "vitest";
import { InvalidArgumentError, NotFoundError, TreeCapacityError } from "../src/errors.js";
import {
    MAX_PARAMS,
    PARAM_EXACT,
    PARAM_RANGE_MAX,
    PARAM_UNCONSTRAINED,
    SCOPE_MAX_DEPTH,
    buildScopeCircuitInput,
    buildScopeCircuitInputFromProof,
    buildScopeTree,
    computeCalldataHash,
    computeParamsHash,
    computeRuleLeaf,
    encodeScopeInitData,
    encodeScopeProofCalldata,
    encodeScopeProofPublicInputs,
    encodeScopePublicInputs,
    encodeUpdateScopeRootData,
    exactMatch,
    getRuleMerkleProof,
    padConstraints,
    padParamValues,
    rangeMax,
    scopeHash,
    selectorToField,
    unconstrained,
    type ScopeProofData,
    type ScopeRule,
} from "../src/zk-scope/index.js";
import { U128_MAX, addressToField } from "../src/zk-scope/rule.js";
import { ADDRESSES } from "./helpers.js";

const target = ADDRESSES[0];
const rule: ScopeRule = {
    target,
    selector: "0xd0e30db0",
    valueMax: 10n ** 18n,
    constraints: padConstraints([exactMatch(0xa0b8n), rangeMax(100_000n)]),
};
const otherRule: ScopeRule = { ...rule, target: ADDRESSES[1], constraints: padConstraints([]) };
const tree = buildScopeTree([rule, otherRule]);

describe("field conversions", () => {
    it("encodes selectors as u32 fields", () => {
        expect(selectorToField("0xd0e30db0")).toBe(0xd0e30db0n);
        expect(selectorToField("0x00000001")).toBe(1n);
        expect(selectorToField("0xD0E30DB0")).toBe(0xd0e30db0n);
    });

    it.each([
        ["too short (silently zero-padded before)", "0x1234"],
        ["full calldata (silently truncated before)", "0xd0e30db0000000000000000000000000"],
        ["no prefix", "d0e30db0"],
        ["non-hex", "0xzzzzzzzz"],
        ["number", 5],
    ])("rejects a selector that is %s", (_name, selector) => {
        expect(() => selectorToField(selector as never)).toThrow(InvalidArgumentError);
    });

    it("encodes addresses", () => {
        expect(addressToField(target)).toBe(BigInt(target.toLowerCase()));
        expect(() => addressToField("0x1" as never)).toThrow(InvalidArgumentError);
    });
});

describe("constraint helpers", () => {
    it("builds typed constraints", () => {
        expect(unconstrained()).toEqual({ constraintType: PARAM_UNCONSTRAINED, value: 0n });
        expect(exactMatch(5n)).toEqual({ constraintType: PARAM_EXACT, value: 5n });
        expect(rangeMax(9n)).toEqual({ constraintType: PARAM_RANGE_MAX, value: 9n });
    });

    it("pads to MAX_PARAMS and refuses to silently drop extras", () => {
        expect(padConstraints([exactMatch(1n)])).toHaveLength(MAX_PARAMS);
        expect(padConstraints([])[3]).toEqual(unconstrained());
        expect(() => padConstraints(new Array(MAX_PARAMS + 1).fill(unconstrained()))).toThrow(InvalidArgumentError);
    });

    it("pads parameter values and refuses extras or non-field values", () => {
        expect(padParamValues([1n])).toEqual([1n, 0n, 0n, 0n]);
        expect(() => padParamValues([1n, 2n, 3n, 4n, 5n])).toThrow(InvalidArgumentError);
        expect(() => padParamValues([-1n])).toThrow(InvalidArgumentError);
        expect(() => padParamValues(null as never)).toThrow(InvalidArgumentError);
    });
});

describe("hashing (mirrors lib/zk_scope)", () => {
    it("params hash", () => {
        const c = rule.constraints.map((k) => poseidon.hash([BigInt(k.constraintType), k.value]));
        expect(computeParamsHash(rule.constraints)).toBe(
            poseidon.hash([poseidon.hash([c[0], c[1]]), poseidon.hash([c[2], c[3]])]),
        );
        expect(() => computeParamsHash([] as never)).toThrow(InvalidArgumentError);
    });

    it("calldata hash pads with zeros", () => {
        expect(computeCalldataHash([1n, 2n])).toBe(poseidon.hash([poseidon.hash([1n, 2n]), poseidon.hash([0n, 0n])]));
    });

    it("rule leaf = Poseidon4(target, selector, valueMax, paramsHash)", () => {
        expect(computeRuleLeaf(rule)).toBe(
            poseidon.hash([addressToField(target), 0xd0e30db0n, rule.valueMax, computeParamsHash(rule.constraints)]),
        );
        expect(scopeHash(1n, 2n)).toBe(poseidon.hash([1n, 2n]));
    });

    it("every rule field changes the leaf", () => {
        const base = computeRuleLeaf(rule);
        const variants: ScopeRule[] = [
            { ...rule, target: ADDRESSES[2] },
            { ...rule, selector: "0x12345678" },
            { ...rule, valueMax: 1n },
            { ...rule, constraints: padConstraints([exactMatch(1n)]) },
            { ...rule, constraints: padConstraints([rangeMax(0xa0b8n), rangeMax(100_000n)]) },
        ];
        for (const v of variants) expect(computeRuleLeaf(v)).not.toBe(base);
    });
});

describe("rule validation", () => {
    it.each([
        ["bad target", { ...rule, target: "0x1" }],
        ["bad selector", { ...rule, selector: "0x12" }],
        ["negative valueMax", { ...rule, valueMax: -1n }],
        ["valueMax above u128", { ...rule, valueMax: U128_MAX + 1n }],
        ["too few constraints", { ...rule, constraints: [unconstrained()] }],
        ["missing constraints", { ...rule, constraints: undefined }],
        [
            "unknown constraint type",
            { ...rule, constraints: padConstraints([{ constraintType: 3 as never, value: 0n }]) },
        ],
        ["range bound above u128", { ...rule, constraints: padConstraints([rangeMax(U128_MAX + 1n)]) }],
        ["exact value above the field", { ...rule, constraints: padConstraints([exactMatch(1n << 255n)]) }],
        ["not an object", null],
    ])("rejects %s", (_name, bad) => {
        expect(() => computeRuleLeaf(bad as never)).toThrow(InvalidArgumentError);
    });

    it("accepts the u128 maximum as a wildcard value cap", () => {
        expect(() => computeRuleLeaf({ ...rule, valueMax: U128_MAX })).not.toThrow();
    });
});

describe("buildScopeTree / proofs", () => {
    it("rejects empty and over-capacity rule sets", () => {
        expect(() => buildScopeTree([])).toThrow(InvalidArgumentError);
        const many = (n: number) => Array.from({ length: n }, (_, i) => ({ ...rule, valueMax: BigInt(i) }));
        expect(() => buildScopeTree(many(2 ** SCOPE_MAX_DEPTH))).not.toThrow();
        expect(() => buildScopeTree(many(2 ** SCOPE_MAX_DEPTH + 1))).toThrow(TreeCapacityError);
    });

    it("proves membership and rejects unknown rules", () => {
        for (const r of [rule, otherRule]) {
            const proof = getRuleMerkleProof(tree.tree, r);
            let node = computeRuleLeaf(r);
            for (let i = 0; i < proof.merkle_proof_length; i++) {
                const s = BigInt(proof.merkle_proof_siblings[i]);
                node = proof.merkle_proof_indices[i] ? scopeHash(s, node) : scopeHash(node, s);
            }
            expect(node).toBe(tree.scopeRoot);
            expect(proof.merkle_proof_indices).toHaveLength(SCOPE_MAX_DEPTH);
        }
        expect(() => getRuleMerkleProof(tree.tree, { ...rule, valueMax: 5n })).toThrow(NotFoundError);
    });
});

describe("buildScopeCircuitInput", () => {
    const params = [0xa0b8n, 500n];
    const build = (overrides: Partial<{ target: Hex; selector: Hex; value: bigint; params: bigint[] }> = {}) =>
        buildScopeCircuitInput(
            (overrides.target ?? target) as Hex,
            (overrides.selector ?? rule.selector) as Hex,
            overrides.value ?? 1000n,
            overrides.params ?? params,
            rule,
            tree.tree,
            tree.scopeRoot,
        );

    it("builds circuit-shaped input", () => {
        const input = build();
        expect(input.rule_target).toBe(toHex(addressToField(target)));
        expect(input.rule_selector).toBe(toHex(0xd0e30db0n));
        expect(input.rule_value_max).toBe(toHex(rule.valueMax));
        expect(input.rule_constraints).toHaveLength(MAX_PARAMS);
        expect(input.rule_constraints[0]).toEqual({ constraint_type: PARAM_EXACT, value: toHex(0xa0b8n) });
        expect(input.param_values).toEqual([toHex(0xa0b8n), toHex(500n), "0x0", "0x0"]);
        expect(input.txn_calldata_hash).toBe(toHex(computeCalldataHash(params)));
        expect(input.scope_root).toBe(toHex(tree.scopeRoot));
        expect(input.proof_indices).toHaveLength(SCOPE_MAX_DEPTH);
    });

    it("accepts boundary transactions", () => {
        expect(() => build({ value: rule.valueMax })).not.toThrow();
        expect(() => build({ params: [0xa0b8n, 100_000n] })).not.toThrow();
    });

    it.each([
        ["target mismatch", { target: ADDRESSES[3] }, /target does not match/],
        ["selector mismatch", { selector: "0x12345678" as Hex }, /selector does not match/],
        ["value above the cap", { value: rule.valueMax + 1n }, /exceeds the rule maximum/],
        ["exact-match violation", { params: [0xbeefn, 1n] }, /must equal/],
        ["range-max violation", { params: [0xa0b8n, 100_001n] }, /at most 100000/],
        ["range slot above u128", { params: [0xa0b8n, U128_MAX + 1n] }, /u128/],
        ["more than 4 params", { params: [0xa0b8n, 1n, 0n, 0n, 0n] }, /at most 4/],
    ])("rejects %s before proving", (_name, overrides, message) => {
        expect(() => build(overrides)).toThrow(message);
    });

    it("rejects a transaction value above u128", () => {
        expect(() => build({ value: U128_MAX + 1n })).toThrow(InvalidArgumentError);
    });

    it("rejects a rule that is not in the tree", () => {
        expect(() =>
            buildScopeCircuitInput(
                target,
                rule.selector,
                1n,
                params,
                { ...rule, valueMax: 1n },
                tree.tree,
                tree.scopeRoot,
            ),
        ).toThrow(NotFoundError);
    });

    it("validates root and proof shape in the from-proof overload", () => {
        const proof = getRuleMerkleProof(tree.tree, rule);
        const call = (p: unknown, root: bigint) =>
            buildScopeCircuitInputFromProof(target, rule.selector, 1n, params, rule, p as never, root);
        expect(() => call(proof, tree.scopeRoot)).not.toThrow();
        expect(() => call(proof, 1n << 255n)).toThrow(InvalidArgumentError);
        expect(() => call({ ...proof, merkle_proof_indices: [] }, tree.scopeRoot)).toThrow(InvalidArgumentError);
    });

    it("leaves unconstrained slots free", () => {
        const free = buildScopeTree([{ ...rule, constraints: padConstraints([]) }]);
        expect(() =>
            buildScopeCircuitInput(
                target,
                rule.selector,
                0n,
                [999n, 999n, 999n, 999n],
                { ...rule, constraints: padConstraints([]) },
                free.tree,
                free.scopeRoot,
            ),
        ).not.toThrow();
    });
});

describe("ABI encoding", () => {
    const calldataHash = computeCalldataHash([1n]);
    const words = (hex: Hex) =>
        decodeAbiParameters(parseAbiParameters("bytes32, bytes32, bytes32, bytes32, bytes32"), hex);

    it("encodeScopePublicInputs orders the five public inputs", () => {
        const [t, s, v, c, r] = words(encodeScopePublicInputs(target, "0xd0e30db0", 7n, calldataHash, tree.scopeRoot));
        expect([BigInt(t), BigInt(s), BigInt(v), BigInt(c), BigInt(r)]).toEqual([
            addressToField(target),
            0xd0e30db0n,
            7n,
            calldataHash,
            tree.scopeRoot,
        ]);
    });

    it("rejects invalid public inputs", () => {
        expect(() =>
            encodeScopePublicInputs(target, "0xd0e30db0", U128_MAX + 1n, calldataHash, tree.scopeRoot),
        ).toThrow(InvalidArgumentError);
        expect(() => encodeScopePublicInputs(target, "0xd0e30db0", 1n, 1n << 255n, tree.scopeRoot)).toThrow(
            InvalidArgumentError,
        );
        expect(() => encodeScopePublicInputs(target, "0x12", 1n, 1n, 1n)).toThrow(InvalidArgumentError);
    });

    it("encodeScopeInitData / encodeUpdateScopeRootData", () => {
        const [r] = decodeAbiParameters(parseAbiParameters("bytes32"), encodeScopeInitData(tree.scopeRoot));
        expect(BigInt(r)).toBe(tree.scopeRoot);
        expect(encodeScopeInitData(toHex(tree.scopeRoot))).toBe(encodeScopeInitData(tree.scopeRoot));

        const [nr, p] = decodeAbiParameters(
            parseAbiParameters("bytes32, bytes"),
            encodeUpdateScopeRootData(tree.scopeRoot, "0xab"),
        );
        expect([BigInt(nr), p]).toEqual([tree.scopeRoot, "0xab"]);
        expect(() => encodeUpdateScopeRootData(tree.scopeRoot, "ab" as Hex)).toThrow(InvalidArgumentError);
    });

    const proofData: ScopeProofData = {
        proof: "0xdeadbeef",
        publicInputs: [1n, 2n, 3n, 4n, 5n].map((n) => toHex(n, { size: 32 })),
        txnTarget: toHex(1n, { size: 32 }),
        txnSelector: toHex(2n, { size: 32 }),
        txnValue: toHex(3n, { size: 32 }),
        txnCalldataHash: toHex(4n, { size: 32 }),
        scopeRoot: toHex(5n, { size: 32 }),
    };

    it("encodeScopeProofPublicInputs / encodeScopeProofCalldata", () => {
        expect(words(encodeScopeProofPublicInputs(proofData)).map(BigInt)).toEqual([1n, 2n, 3n, 4n, 5n]);

        const [proof, inputs] = decodeAbiParameters(
            parseAbiParameters("bytes, bytes"),
            encodeScopeProofCalldata(proofData),
        );
        expect(proof).toBe("0xdeadbeef");
        expect(inputs).toBe(encodeScopeProofPublicInputs(proofData));
    });

    it("rejects malformed proof data instead of slicing silently", () => {
        expect(() =>
            encodeScopeProofPublicInputs({ ...proofData, publicInputs: proofData.publicInputs.slice(0, 4) }),
        ).toThrow(/exactly 5/);
        expect(() =>
            encodeScopeProofPublicInputs({ ...proofData, publicInputs: [...proofData.publicInputs, "0x00"] }),
        ).toThrow(/exactly 5/);
        expect(() =>
            encodeScopeProofPublicInputs({ ...proofData, publicInputs: ["0x1", ...proofData.publicInputs.slice(1)] }),
        ).toThrow(InvalidArgumentError);
        expect(() => encodeScopeProofCalldata({ ...proofData, proof: "0xabc" as Hex })).toThrow(InvalidArgumentError);
    });
});
