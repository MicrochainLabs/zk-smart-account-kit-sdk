import { afterEach, describe, expect, it, vi } from "vitest";

const circuit = { bytecode: "AAAA", abi: { parameters: [] } };

interface Mocks {
    destroy: ReturnType<typeof vi.fn>;
    execute: ReturnType<typeof vi.fn>;
    generateProof: ReturnType<typeof vi.fn>;
    newBarretenberg: ReturnType<typeof vi.fn>;
}

async function loadProver(overrides: Partial<Mocks> = {}) {
    vi.resetModules();
    const destroy = vi.fn().mockResolvedValue(undefined);
    const mocks: Mocks = {
        destroy,
        newBarretenberg: vi.fn().mockResolvedValue({ destroy }),
        execute: vi.fn().mockResolvedValue({ witness: new Uint8Array([1]) }),
        generateProof: vi.fn().mockResolvedValue({ proof: new Uint8Array([0xde, 0xad]), publicInputs: ["0x1", "0x2"] }),
        ...overrides,
    };

    vi.doMock("@aztec/bb.js", () => ({
        Barretenberg: { new: mocks.newBarretenberg },
        UltraHonkBackend: class {
            generateProof = mocks.generateProof;
        },
    }));
    vi.doMock("@noir-lang/noir_js", () => ({
        Noir: class {
            execute = mocks.execute;
        },
    }));

    // Imported after the module reset so `instanceof` checks see the same error classes the prover threw.
    const { proveCircuit } = await import("../src/internal/prover.js");
    const errors = await import("../src/errors.js");
    return { proveCircuit, mocks, errors };
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

    it("never destroys a caller-supplied Barretenberg instance", async () => {
        const { proveCircuit, mocks } = await loadProver();
        const shared = { destroy: vi.fn() };
        await proveCircuit(circuit as never, {}, 2, { barretenberg: shared });
        expect(shared.destroy).not.toHaveBeenCalled();
        expect(mocks.newBarretenberg).not.toHaveBeenCalled();
    });

    it("wraps witness failures and still releases resources", async () => {
        const cause = new Error("Cannot satisfy constraint");
        const { proveCircuit, mocks, errors } = await loadProver({ execute: vi.fn().mockRejectedValue(cause) });
        const error = await proveCircuit(circuit as never, {}, 2).catch((e) => e);
        expect(error).toBeInstanceOf(errors.ProofGenerationError);
        expect(error.message).toContain("Witness generation failed");
        expect(error.message).toContain("Cannot satisfy constraint");
        expect(error.cause).toBe(cause);
        expect(mocks.generateProof).not.toHaveBeenCalled();
        expect(mocks.destroy).toHaveBeenCalledTimes(1);
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
