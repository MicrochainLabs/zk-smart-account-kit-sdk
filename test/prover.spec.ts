import { afterEach, describe, expect, it, vi } from "vitest";

const circuit = { bytecode: "AAAA", abi: { parameters: [] } };

interface Mocks {
    destroy: ReturnType<typeof vi.fn>;
    execute: ReturnType<typeof vi.fn>;
    generateProof: ReturnType<typeof vi.fn>;
    verifyProof: ReturnType<typeof vi.fn>;
    newBarretenberg: ReturnType<typeof vi.fn>;
}

async function loadProver(overrides: Partial<Mocks> = {}) {
    vi.resetModules();
    const destroy = vi.fn().mockResolvedValue(undefined);
    const mocks: Mocks = {
        destroy,
        newBarretenberg: vi.fn().mockResolvedValue({ destroy, grumpkinGetRandomFr: vi.fn().mockResolvedValue({}) }),
        execute: vi.fn().mockResolvedValue({ witness: new Uint8Array([1]) }),
        generateProof: vi.fn().mockResolvedValue({ proof: new Uint8Array([0xde, 0xad]), publicInputs: ["0x1", "0x2"] }),
        verifyProof: vi.fn().mockResolvedValue(true),
        ...overrides,
    };

    vi.doMock("@aztec/bb.js", () => ({
        Barretenberg: { new: mocks.newBarretenberg },
        UltraHonkBackend: class {
            generateProof = mocks.generateProof;
            verifyProof = mocks.verifyProof;
        },
    }));
    vi.doMock("@noir-lang/noir_js", () => ({
        Noir: class {
            execute = mocks.execute;
        },
    }));

    // Imported after the module reset so `instanceof` checks see the same error classes the prover threw.
    const { proveCircuit, createBarretenberg } = await import("../src/internal/prover.js");
    const errors = await import("../src/errors.js");
    return { proveCircuit, createBarretenberg, mocks, errors };
}

afterEach(() => {
    vi.doUnmock("@aztec/bb.js");
    vi.doUnmock("@noir-lang/noir_js");
});

describe("proveCircuit", () => {
    it("returns hex proof and public inputs, then destroys its own Barretenberg instance", async () => {
        const { proveCircuit, mocks } = await loadProver();
        await expect(proveCircuit(circuit as never, { a: 1 }, 2)).resolves.toEqual({
            proof: "0xdead",
            publicInputs: ["0x1", "0x2"],
        });
        expect(mocks.execute).toHaveBeenCalledWith({ a: 1 });
        expect(mocks.destroy).toHaveBeenCalledTimes(1);
    });

    it("generates and verifies EVM-target proofs by default", async () => {
        const { proveCircuit, mocks } = await loadProver();
        await proveCircuit(circuit as never, {}, 2);
        expect(mocks.generateProof).toHaveBeenCalledWith(expect.anything(), { verifierTarget: "evm" });
        expect(mocks.verifyProof).toHaveBeenCalledWith(expect.anything(), { verifierTarget: "evm" });
    });

    it("honours a custom verifierTarget and can skip local verification", async () => {
        const { proveCircuit, mocks } = await loadProver();
        await proveCircuit(circuit as never, {}, 2, { verifierTarget: "evm-no-zk", verify: false });
        expect(mocks.generateProof).toHaveBeenCalledWith(expect.anything(), { verifierTarget: "evm-no-zk" });
        expect(mocks.verifyProof).not.toHaveBeenCalled();
    });

    it("rejects a proof that fails local verification", async () => {
        const { proveCircuit, errors } = await loadProver({ verifyProof: vi.fn().mockResolvedValue(false) });
        const error = await proveCircuit(circuit as never, {}, 2).catch((e) => e);
        expect(error).toBeInstanceOf(errors.ProofGenerationError);
        expect(error.message).toContain("does not verify");
    });

    it("generates the witness before it creates Barretenberg (which would otherwise lose its connection)", async () => {
        const order: string[] = [];
        const { proveCircuit } = await loadProver({
            execute: vi.fn().mockImplementation(() => {
                order.push("witness");
                return Promise.resolve({ witness: new Uint8Array([1]) });
            }),
            newBarretenberg: vi.fn().mockImplementation(() => {
                order.push("barretenberg");
                return Promise.resolve({ destroy: vi.fn(), grumpkinGetRandomFr: vi.fn().mockResolvedValue({}) });
            }),
        });
        await proveCircuit(circuit as never, {}, 2);
        expect(order).toEqual(["witness", "barretenberg"]);
    });

    it("does not create Barretenberg at all when the witness cannot be generated", async () => {
        const { proveCircuit, mocks } = await loadProver({
            execute: vi.fn().mockRejectedValue(new Error("unsatisfied")),
        });
        await expect(proveCircuit(circuit as never, {}, 2)).rejects.toThrow(/Witness generation failed/);
        expect(mocks.newBarretenberg).not.toHaveBeenCalled();
    });

    it("never destroys a caller-supplied Barretenberg instance", async () => {
        const { proveCircuit, mocks } = await loadProver();
        const shared = { destroy: vi.fn() };
        await proveCircuit(circuit as never, {}, 2, { barretenberg: shared });
        expect(shared.destroy).not.toHaveBeenCalled();
        expect(mocks.newBarretenberg).not.toHaveBeenCalled();
    });

    it("wraps witness failures without ever starting the prover", async () => {
        const cause = new Error("Cannot satisfy constraint");
        const { proveCircuit, mocks, errors } = await loadProver({ execute: vi.fn().mockRejectedValue(cause) });
        const error = await proveCircuit(circuit as never, {}, 2).catch((e) => e);
        expect(error).toBeInstanceOf(errors.ProofGenerationError);
        expect(error.message).toContain("Witness generation failed");
        expect(error.message).toContain("Cannot satisfy constraint");
        expect(error.cause).toBe(cause);
        expect(mocks.generateProof).not.toHaveBeenCalled();
        expect(mocks.newBarretenberg).not.toHaveBeenCalled();
    });

    it("wraps proving failures (including non-Error throwables) and still releases resources", async () => {
        const { proveCircuit, mocks, errors } = await loadProver({ generateProof: vi.fn().mockRejectedValue("boom") });
        const error = await proveCircuit(circuit as never, {}, 2).catch((e) => e);
        expect(error).toBeInstanceOf(errors.ProofGenerationError);
        expect(error.message).toContain("Proof generation failed: boom");
        expect(mocks.destroy).toHaveBeenCalledTimes(1);
    });

    it("rejects an unexpected number of public inputs", async () => {
        const { proveCircuit } = await loadProver();
        await expect(proveCircuit(circuit as never, {}, 33)).rejects.toThrow(/2 public inputs; expected 33/);
    });
});

describe("createBarretenberg", () => {
    it("creates an instance and completes its lazy connection with a round-trip", async () => {
        const grumpkinGetRandomFr = vi.fn().mockResolvedValue({});
        const instance = { destroy: vi.fn(), grumpkinGetRandomFr };
        const { createBarretenberg, mocks } = await loadProver({
            newBarretenberg: vi.fn().mockResolvedValue(instance),
        });
        await expect(createBarretenberg({ threads: 2 })).resolves.toBe(instance);
        expect(mocks.newBarretenberg).toHaveBeenCalledWith({ threads: 2 });
        expect(grumpkinGetRandomFr).toHaveBeenCalledTimes(1);
        expect(instance.destroy).not.toHaveBeenCalled();
    });

    it("loads noir_js before the first Barretenberg round-trip (a Node.js module-resolution quirk otherwise loads the wrong WASM)", async () => {
        const order: string[] = [];
        vi.resetModules();
        const destroy = vi.fn();
        vi.doMock("@noir-lang/noir_js", () => {
            order.push("noir_js");
            return { Noir: class {} };
        });
        vi.doMock("@aztec/bb.js", () => {
            order.push("bb.js");
            return {
                Barretenberg: {
                    new: () => {
                        order.push("Barretenberg.new");
                        return Promise.resolve({
                            destroy,
                            grumpkinGetRandomFr: () => {
                                order.push("round-trip");
                                return Promise.resolve({});
                            },
                        });
                    },
                },
            };
        });
        const { createBarretenberg } = await import("../src/internal/prover.js");
        await createBarretenberg();
        expect(order).toEqual(["noir_js", "bb.js", "Barretenberg.new", "round-trip"]);
    });

    it("destroys the instance and rethrows when the connection never completes", async () => {
        const failure = new Error("Timeout connecting to bb socket");
        const instance = {
            destroy: vi.fn().mockResolvedValue(undefined),
            grumpkinGetRandomFr: vi.fn().mockRejectedValue(failure),
        };
        const { createBarretenberg } = await loadProver({ newBarretenberg: vi.fn().mockResolvedValue(instance) });
        await expect(createBarretenberg()).rejects.toBe(failure);
        expect(instance.destroy).toHaveBeenCalledTimes(1);

        const stubborn = {
            destroy: vi.fn().mockRejectedValue(new Error("destroy failed")),
            grumpkinGetRandomFr: vi.fn().mockRejectedValue(failure),
        };
        const again = await loadProver({ newBarretenberg: vi.fn().mockResolvedValue(stubborn) });
        await expect(again.createBarretenberg()).rejects.toBe(failure);
    });
});

describe("loadPeer", () => {
    const notFound = (code: string) => Object.assign(new Error("not found"), { code });

    it("passes through a successfully loaded module", async () => {
        const { loadPeer } = await import("../src/internal/prover.js");
        await expect(loadPeer("pkg", async () => 42)).resolves.toBe(42);
    });

    it.each(["ERR_MODULE_NOT_FOUND", "MODULE_NOT_FOUND"])("maps %s to MissingPeerDependencyError", async (code) => {
        const { loadPeer } = await import("../src/internal/prover.js");
        const error = await loadPeer("@aztec/bb.js", async () => Promise.reject(notFound(code))).catch((e) => e);
        expect(error.code).toBe("MISSING_PEER_DEPENDENCY");
        expect(error.message).toContain("pnpm add @aztec/bb.js");
        expect(error.cause.code).toBe(code);
    });

    it("rethrows unrelated failures untouched", async () => {
        const { loadPeer } = await import("../src/internal/prover.js");
        const failure = new TypeError("syntax problem inside the package");
        await expect(loadPeer("pkg", async () => Promise.reject(failure))).rejects.toBe(failure);
        await expect(loadPeer("pkg", async () => Promise.reject(null))).rejects.toBeNull();
    });
});
