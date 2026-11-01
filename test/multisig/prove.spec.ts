import { keccak256, toBytes, toHex, type Hex } from "viem";
import { afterEach, describe, expect, it, vi } from "vitest";
import { InvalidCircuitError } from "../../src/errors.js";
import {
    ZK_MULTISIG_CIRCUIT_PARAMS,
    ZK_MULTISIG_STATE_VALIDATION_CIRCUIT_PARAMS,
    createMultiSigState,
    generateMultiSigProof,
    generateStateValidationProof,
    type MultiSigConfig,
} from "../../src/zk-multisig/index.js";
import { testAccounts } from "../helpers.js";

const SALT = 0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefn;
const accounts = testAccounts(3, "prove");
const config: MultiSigConfig = { signers: accounts.map((a) => a.address), threshold: 2, salt: SALT };
const state = createMultiSigState(config);
const hash = keccak256(toBytes("prove"));

const named = (names: readonly string[]) => ({
    bytecode: "AAAA",
    abi: { parameters: names.map((name) => ({ name })) },
});
const txCircuit = named(ZK_MULTISIG_CIRCUIT_PARAMS);
const stateCircuit = named(ZK_MULTISIG_STATE_VALIDATION_CIRCUIT_PARAMS);

afterEach(() => {
    vi.doUnmock("../../src/internal/prover.js");
});

async function withProver(publicInputs: Hex[]) {
    vi.resetModules();
    const proveCircuit = vi.fn().mockResolvedValue({ proof: "0xdeadbeef", publicInputs });
    vi.doMock("../../src/internal/prover.js", () => ({ proveCircuit }));
    const prove = await import("../../src/zk-multisig/prove.js");
    return { prove, proveCircuit };
}

describe("generateMultiSigProof", () => {
    it("builds the circuit input, expects 33 public inputs and derives hash and root from the proof", async () => {
        const publicInputs = [
            ...Array.from({ length: 32 }, (_, i) => toHex(i, { size: 32 })),
            toHex(state.stateRoot, { size: 32 }),
        ];
        const { prove, proveCircuit } = await withProver(publicInputs as Hex[]);
        const signatures = await Promise.all([0, 1].map((i) => accounts[i].sign({ hash })));
        const options = { verifierTarget: "evm" as const };

        const result = await prove.generateMultiSigProof(config, hash, signatures, state.stateRoot, txCircuit, options);

        expect(result).toEqual({ proof: "0xdeadbeef", publicInputs, txnHash: hash, stateRoot: publicInputs[32] });
        const [circuit, input, count, passed] = proveCircuit.mock.calls[0] as [
            unknown,
            Record<string, unknown>,
            number,
            unknown,
        ];
        expect(circuit).toBe(txCircuit);
        expect(count).toBe(33);
        expect(passed).toBe(options);
        expect(input).toMatchObject({ threshold: 2, on_chain_state_root: toHex(state.stateRoot) });
    });

    it("rejects the wrong circuit before doing any work", async () => {
        const signatures = await Promise.all([0, 1].map((i) => accounts[i].sign({ hash })));
        await expect(generateMultiSigProof(config, hash, signatures, state.stateRoot, stateCircuit)).rejects.toThrow(
            InvalidCircuitError,
        );
        await expect(generateMultiSigProof(config, hash, signatures, state.stateRoot, undefined)).rejects.toThrow(
            InvalidCircuitError,
        );
    });
});

describe("generateStateValidationProof", () => {
    it("proves the configuration and reports the single public input as the state root", async () => {
        const publicInputs = [toHex(state.stateRoot, { size: 32 })] as Hex[];
        const { prove, proveCircuit } = await withProver(publicInputs);

        const result = await prove.generateStateValidationProof(config, stateCircuit);

        expect(result).toEqual({ proof: "0xdeadbeef", publicInputs, stateRoot: publicInputs[0] });
        const [, input, count] = proveCircuit.mock.calls[0] as [unknown, Record<string, unknown>, number];
        expect(count).toBe(1);
        expect(input).toMatchObject({ signers_root: toHex(state.signersRoot), salt: toHex(SALT) });
    });

    it("rejects the wrong circuit", async () => {
        await expect(generateStateValidationProof(config, txCircuit)).rejects.toThrow(InvalidCircuitError);
    });
});
