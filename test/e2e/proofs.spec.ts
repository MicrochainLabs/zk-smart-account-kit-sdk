/**
 * End-to-end tests against the real compiled Noir circuits and Barretenberg.
 *
 * These prove that what the SDK computes off-chain (leaves, roots, circuit inputs)
 * is accepted by the circuits, and that the generated proofs verify. They are the
 * guard against the SDK and the circuits drifting apart.
 *
 * Circuit artifacts live in test/fixtures/circuits (refresh with `pnpm sync-circuits`).
 */

import { createBarretenberg } from "../../src/internal/prover.js";
import { Barretenberg, UltraHonkBackend } from "@aztec/bb.js";
import { Noir } from "@noir-lang/noir_js";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { InvalidArgumentError, InvalidCircuitError, ProofGenerationError } from "../../src/errors.js";
import { assertCircuit } from "../../src/internal/compiled-circuit.js";
import { proveCircuit } from "../../src/internal/prover.js";
import {
    buildLabelsTree,
    buildLabelBindingCircuitInput,
    computeLabelCommitment,
    generateLabelBindingProof,
    createZKLabels,
    encodeLabelProofCalldata,
} from "../../src/zk-label/index.js";
import { ZK_LABEL_BINDING_CIRCUIT_PARAMS } from "../../src/zk-label/prove.js";
import {
    PARAM_EXACT,
    buildScopeCircuitInput,
    buildScopeCircuitInputFromProof,
    buildScopeTree,
    computeCalldataHash,
    encodeScopeProofCalldata,
    exactMatch,
    generateScopeProof,
    getRuleMerkleProof,
    padConstraints,
    rangeMax,
    type ScopeRule,
} from "../../src/zk-scope/index.js";
import { ZK_SCOPE_VALIDATION_CIRCUIT_PARAMS } from "../../src/zk-scope/prove.js";
import {
    buildSignersTree,
    buildZKSignerCircuitInput,
    buildZKSignerCircuitInputFromProof,
    encodeZKSignerProofCalldata,
    generateZKSignerProof,
    getSignerMerkleProof,
} from "../../src/zk-signer/index.js";
import { ZK_SIGNERS_CIRCUIT_PARAMS } from "../../src/zk-signer/prove.js";
import { ADDRESSES, loadCircuit, signRaw, testHash, testKey } from "../helpers.js";

const signersCircuit = loadCircuit("zk_signers");
const labelCircuit = loadCircuit("zk_label_binding");
const scopeCircuit = loadCircuit("zk_scope_validation");

// One Barretenberg instance for the whole file, exercising the `options.barretenberg` reuse path.
let api: Barretenberg;
beforeAll(async () => {
    api = (await createBarretenberg()) as Barretenberg;
}, 120_000);
afterAll(async () => {
    await api.destroy();
});

const PROOF_TIMEOUT = 300_000;

async function execute(circuit: unknown, input: unknown) {
    return new Noir(circuit as never).execute(input as never);
}

async function verify(circuit: { bytecode: string }, proof: { proof: string; publicInputs: string[] }) {
    const backend = new UltraHonkBackend(circuit.bytecode, api);
    const bytes = Uint8Array.from(Buffer.from(proof.proof.slice(2), "hex"));
    // The default (and on-chain) flavour: keccak transcript, zero-knowledge.
    return backend.verifyProof({ proof: bytes, publicInputs: proof.publicInputs }, { verifierTarget: "evm" });
}

describe("circuit fixtures", () => {
    it.each([
        ["zk_signers", signersCircuit, ZK_SIGNERS_CIRCUIT_PARAMS],
        ["zk_label_binding", labelCircuit, ZK_LABEL_BINDING_CIRCUIT_PARAMS],
        ["zk_scope_validation", scopeCircuit, ZK_SCOPE_VALIDATION_CIRCUIT_PARAMS],
    ] as const)("%s ABI matches the parameter list the SDK expects", (name, circuit, params) => {
        expect(() => assertCircuit(circuit, name, params)).not.toThrow();
    });

    it("rejects the wrong circuit for each prover", async () => {
        const key = testKey("alice");
        const tree = buildSignersTree([{ signer: key.address }]);
        const hash = testHash("tx");
        const sig = signRaw(key.privateKey, Uint8Array.from(hash));

        await expect(generateZKSignerProof(key.pubKey, sig, key.address, tree, hash, labelCircuit)).rejects.toThrow(
            InvalidCircuitError,
        );
        await expect(
            generateLabelBindingProof(
                "a",
                key.address,
                buildLabelsTree([{ labelName: "a", signer: key.address }]),
                scopeCircuit,
            ),
        ).rejects.toThrow(InvalidCircuitError);
    });
});

describe("zk_signers", () => {
    const signers = [testKey("s0"), testKey("s1"), testKey("s2"), testKey("s3"), testKey("s4")];
    const tree = buildSignersTree(signers.map((k) => ({ signer: k.address })));
    const hash = testHash("transfer-1");

    it.each([0, 1, 2, 3, 4])("SDK inputs satisfy the circuit for signer #%i (every Merkle path shape)", async (i) => {
        const k = signers[i];
        const input = buildZKSignerCircuitInput(
            k.pubKey,
            signRaw(k.privateKey, Uint8Array.from(hash)),
            k.address,
            tree,
            hash,
        );
        await expect(execute(signersCircuit, input)).resolves.toHaveProperty("witness");
    });

    it("single-signer tree (proof length 0) satisfies the circuit", async () => {
        const k = signers[0];
        const single = buildSignersTree([{ signer: k.address }]);
        const input = buildZKSignerCircuitInput(
            k.pubKey,
            signRaw(k.privateKey, Uint8Array.from(hash)),
            k.address,
            single,
            hash,
        );
        expect(input.proof_length).toBe(0);
        await expect(execute(signersCircuit, input)).resolves.toHaveProperty("witness");
    });

    it("the circuit rejects what the SDK pre-flight rejects (signature over another hash)", async () => {
        const k = signers[0];
        const wrongSig = signRaw(k.privateKey, Uint8Array.from(testHash("other")));
        const input = buildZKSignerCircuitInputFromProof(
            k.pubKey,
            wrongSig,
            getSignerMerkleProof(tree.tree, k.address),
            tree.signersRoot,
            hash,
        );
        await expect(execute(signersCircuit, input)).rejects.toThrow();
        expect(() => buildZKSignerCircuitInput(k.pubKey, wrongSig, k.address, tree, hash)).toThrow(
            InvalidArgumentError,
        );
    });

    it("the circuit rejects a signer outside the tree", async () => {
        const outsider = testKey("outsider");
        const input = buildZKSignerCircuitInputFromProof(
            outsider.pubKey,
            signRaw(outsider.privateKey, Uint8Array.from(hash)),
            getSignerMerkleProof(tree.tree, signers[0].address),
            tree.signersRoot,
            hash,
        );
        await expect(execute(signersCircuit, input)).rejects.toThrow();
    });

    it(
        "generates a proof that verifies, with the documented public inputs",
        async () => {
            const k = signers[2];
            const sig = signRaw(k.privateKey, Uint8Array.from(hash));
            const proof = await generateZKSignerProof(k.pubKey, sig, k.address, tree, hash, signersCircuit, {
                barretenberg: api,
            });

            expect(proof.publicInputs).toHaveLength(33);
            expect(proof.publicInputs.slice(0, 32).map((p) => Number(BigInt(p)))).toEqual(hash);
            expect(BigInt(proof.signersRoot)).toBe(tree.signersRoot);
            expect(proof.txnHash).toBe(`0x${Buffer.from(hash).toString("hex")}`);
            await expect(verify(signersCircuit, proof)).resolves.toBe(true);
            expect(() =>
                encodeZKSignerProofCalldata({
                    ...proof,
                    signersRoot: `0x${tree.signersRoot.toString(16).padStart(64, "0")}`,
                }),
            ).not.toThrow();

            // A tampered public input must not verify.
            const tampered = {
                ...proof,
                publicInputs: [...proof.publicInputs.slice(0, 32), "0x" + "00".repeat(31) + "01"],
            };
            await expect(verify(signersCircuit, tampered)).resolves.toBe(false);
        },
        PROOF_TIMEOUT,
    );

    it(
        "creates and destroys its own Barretenberg instance when none is supplied",
        async () => {
            const k = signers[0];
            const single = buildSignersTree([{ signer: k.address }]);
            const proof = await generateZKSignerProof(
                k.pubKey,
                signRaw(k.privateKey, Uint8Array.from(hash)),
                k.address,
                single,
                hash,
                signersCircuit,
            );
            await expect(verify(signersCircuit, proof)).resolves.toBe(true);
        },
        PROOF_TIMEOUT,
    );

    it("proveCircuit surfaces an unsatisfied constraint as ProofGenerationError", async () => {
        const k = signers[0];
        const bad = buildZKSignerCircuitInputFromProof(
            k.pubKey,
            signRaw(k.privateKey, Uint8Array.from(testHash("other"))),
            getSignerMerkleProof(tree.tree, k.address),
            tree.signersRoot,
            hash,
        );
        const error = await proveCircuit(signersCircuit, bad as never, 33, { barretenberg: api }).catch((e) => e);
        expect(error).toBeInstanceOf(ProofGenerationError);
        expect(error.message).toMatch(/Witness generation failed/);
    });

    it(
        "proveCircuit rejects an unexpected public-input count",
        async () => {
            const k = signers[0];
            const single = buildSignersTree([{ signer: k.address }]);
            const input = buildZKSignerCircuitInput(
                k.pubKey,
                signRaw(k.privateKey, Uint8Array.from(hash)),
                k.address,
                single,
                hash,
            );
            await expect(proveCircuit(signersCircuit, input as never, 2, { barretenberg: api })).rejects.toThrow(
                /33 public inputs; expected 2/,
            );
        },
        PROOF_TIMEOUT,
    );
});

describe("zk_label_binding", () => {
    const entries = [
        { labelName: "admin", signer: ADDRESSES[0] },
        { labelName: "operator", signer: ADDRESSES[1] },
        { labelName: "auditor", signer: ADDRESSES[2] },
        { labelName: "héllo wörld ✓", signer: ADDRESSES[3] },
        { labelName: "a".repeat(31), signer: ADDRESSES[4] },
    ];
    const tree = buildLabelsTree(entries);

    it.each(entries.map((e, i) => [i, e.labelName.slice(0, 12)] as const))(
        "SDK inputs satisfy the circuit for entry #%i (%s)",
        async (i) => {
            const { labelName, signer } = entries[i];
            const input = buildLabelBindingCircuitInput(labelName, signer, tree.tree, tree.registryRoot);
            await expect(execute(labelCircuit, input)).resolves.toHaveProperty("witness");
        },
    );

    it("the circuit rejects a label that is not bound to the address", async () => {
        const input = buildLabelBindingCircuitInput("admin", ADDRESSES[0], tree.tree, tree.registryRoot);
        const forged = {
            ...input,
            label_bytes: buildLabelBindingCircuitInput("operator", ADDRESSES[1], tree.tree, tree.registryRoot)
                .label_bytes,
        };
        await expect(execute(labelCircuit, forged)).rejects.toThrow();
    });

    it(
        "generates a proof that verifies, via the function and via createZKLabels",
        async () => {
            const proof = await generateLabelBindingProof("operator", ADDRESSES[1], tree, labelCircuit, {
                barretenberg: api,
            });
            expect(proof.publicInputs).toHaveLength(2);
            expect(BigInt(proof.registryRoot)).toBe(tree.registryRoot);
            expect(BigInt(proof.labelCommitment)).toBe(computeLabelCommitment("operator", ADDRESSES[1]));
            await expect(verify(labelCircuit, proof)).resolves.toBe(true);

            const zk = createZKLabels(entries, labelCircuit, { barretenberg: api });
            const viaHelper = await zk.proveLabelMembership("admin", ADDRESSES[0]);
            await expect(verify(labelCircuit, viaHelper)).resolves.toBe(true);
            expect(encodeLabelProofCalldata(viaHelper)).toMatch(/^0x/);
        },
        PROOF_TIMEOUT,
    );

    it(
        "a registry updated through the helper still proves",
        async () => {
            const zk = createZKLabels(entries.slice(0, 2), labelCircuit, { barretenberg: api });
            zk.addLabel(entries[2]);
            const proof = await zk.proveLabelMembership("auditor", ADDRESSES[2]);
            expect(BigInt(proof.registryRoot)).toBe(BigInt(zk.registryRoot));
            await expect(verify(labelCircuit, proof)).resolves.toBe(true);
        },
        PROOF_TIMEOUT,
    );
});

describe("zk_scope_validation", () => {
    const rules: ScopeRule[] = [
        {
            target: ADDRESSES[0],
            selector: "0xd0e30db0",
            valueMax: 10n ** 18n,
            constraints: padConstraints([exactMatch(0xa0b8n), rangeMax(100_000n)]),
        },
        { target: ADDRESSES[1], selector: "0xa9059cbb", valueMax: 0n, constraints: padConstraints([]) },
        {
            target: ADDRESSES[2],
            selector: "0x095ea7b3",
            valueMax: (1n << 128n) - 1n,
            constraints: padConstraints([rangeMax((1n << 128n) - 1n)]),
        },
        {
            target: ADDRESSES[3],
            selector: "0x12345678",
            valueMax: 5n,
            constraints: padConstraints([exactMatch(1n), exactMatch(2n), exactMatch(3n), exactMatch(4n)]),
        },
    ];
    const tree = buildScopeTree(rules);

    const cases: Array<[string, number, bigint, bigint[]]> = [
        ["exact + range, mid values", 0, 1000n, [0xa0b8n, 500n]],
        ["exact + range, boundary values", 0, 10n ** 18n, [0xa0b8n, 100_000n]],
        ["fully unconstrained transfer", 1, 0n, [7n, 8n, 9n, 10n]],
        ["u128 max range bound", 2, (1n << 128n) - 1n, [0n, (1n << 128n) - 1n]],
        ["four exact constraints", 3, 5n, [1n, 2n, 3n, 4n]],
    ];

    it.each(cases)("SDK inputs satisfy the circuit: %s", async (_name, ruleIndex, value, params) => {
        const rule = rules[ruleIndex];
        const input = buildScopeCircuitInput(
            rule.target,
            rule.selector,
            value,
            params,
            rule,
            tree.tree,
            tree.scopeRoot,
        );
        await expect(execute(scopeCircuit, input)).resolves.toHaveProperty("witness");
        expect(input.txn_calldata_hash).toBeDefined();
    });

    it("the SDK pre-flight agrees with the circuit on every violation", async () => {
        const rule = rules[0];
        const proof = getRuleMerkleProof(tree.tree, rule);
        const violations: Array<[string, Parameters<typeof buildScopeCircuitInputFromProof>]> = [
            [
                "value above cap",
                [rule.target, rule.selector, rule.valueMax + 1n, [0xa0b8n, 1n], rule, proof, tree.scopeRoot],
            ],
            ["exact mismatch", [rule.target, rule.selector, 1n, [0xbeefn, 1n], rule, proof, tree.scopeRoot]],
            ["range exceeded", [rule.target, rule.selector, 1n, [0xa0b8n, 100_001n], rule, proof, tree.scopeRoot]],
            ["selector mismatch", [rule.target, "0x12345678", 1n, [0xa0b8n, 1n], rule, proof, tree.scopeRoot]],
            ["target mismatch", [ADDRESSES[9], rule.selector, 1n, [0xa0b8n, 1n], rule, proof, tree.scopeRoot]],
        ];

        for (const [name, args] of violations) {
            // The SDK refuses early…
            expect(() => buildScopeCircuitInputFromProof(...args), name).toThrow(InvalidArgumentError);

            // …and so does the circuit (bypass the pre-flight by hand-building the inputs).
            const [target, selector, value, params, , , root] = args;
            const honest = buildScopeCircuitInputFromProof(
                rule.target,
                rule.selector,
                1n,
                [0xa0b8n, 1n],
                rule,
                proof,
                root,
            );
            const input = {
                ...honest,
                txn_target: `0x${BigInt(target.toLowerCase()).toString(16)}`,
                txn_selector: `0x${BigInt(selector).toString(16)}`,
                txn_value: `0x${value.toString(16)}`,
                param_values: [...params, 0n, 0n, 0n, 0n].slice(0, 4).map((v) => `0x${v.toString(16)}`),
                txn_calldata_hash: `0x${computeCalldataHash(params).toString(16)}`,
            };
            await expect(execute(scopeCircuit, input), name).rejects.toThrow();
        }
        expect(PARAM_EXACT).toBe(1);
    });

    it(
        "generates a proof that verifies, with the documented public inputs",
        async () => {
            const rule = rules[0];
            const params = [0xa0b8n, 500n];
            const proof = await generateScopeProof(
                rule.target,
                rule.selector,
                1000n,
                params,
                rule,
                tree,
                scopeCircuit,
                { barretenberg: api },
            );

            expect(proof.publicInputs).toHaveLength(5);
            expect(BigInt(proof.txnValue)).toBe(1000n);
            expect(BigInt(proof.txnSelector)).toBe(0xd0e30db0n);
            expect(BigInt(proof.txnCalldataHash)).toBe(computeCalldataHash(params));
            expect(BigInt(proof.scopeRoot)).toBe(tree.scopeRoot);
            await expect(verify(scopeCircuit, proof)).resolves.toBe(true);
            expect(encodeScopeProofCalldata(proof)).toMatch(/^0x/);
        },
        PROOF_TIMEOUT,
    );
});
