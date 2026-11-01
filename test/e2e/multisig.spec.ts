/**
 * End-to-end tests of the ZK MultiSig primitive against the real compiled circuits
 * (microchain-zk-signers): SDK-built inputs are executed, proved with the EVM flavour and verified.
 */

import { createBarretenberg } from "../../src/internal/prover.js";
import { Barretenberg, UltraHonkBackend } from "@aztec/bb.js";
import { Noir } from "@noir-lang/noir_js";
import { hexToBytes, keccak256, toBytes, toHex, type Hex } from "viem";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ChainStateError, InvalidArgumentError, InvalidCircuitError, NotFoundError } from "../../src/errors.js";
import {
    MULTISIG_PUBLIC_INPUTS,
    buildMultiSigCircuitInput,
    buildMultiSigPublicInputs,
    buildStateValidationCircuitInput,
    computeStateRoot,
    createMultiSigState,
    generateMultiSigProof,
    generateStateValidationProof,
    type MultiSigConfig,
} from "../../src/zk-multisig/index.js";
import { loadCircuit, testAccounts } from "../helpers.js";

const txCircuit = loadCircuit("zk_multi_sig_ecdsa");
const stateCircuit = loadCircuit("zk_multi_sig_ecdsa_private_state_validation");
const PROOF_TIMEOUT = 300_000;

let api: Barretenberg;
beforeAll(async () => {
    api = (await createBarretenberg()) as Barretenberg;
}, 120_000);
afterAll(async () => {
    await api.destroy();
});

const hashOf = (label: string) => keccak256(toBytes(label));
const SALT = 0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefn;

async function execute(circuit: unknown, input: unknown) {
    return new Noir(circuit as never).execute(input as never);
}

async function verify(circuit: { bytecode: string }, proof: { proof: Hex; publicInputs: Hex[] }) {
    const backend = new UltraHonkBackend(circuit.bytecode, api);
    return backend.verifyProof(
        { proof: hexToBytes(proof.proof), publicInputs: proof.publicInputs },
        { verifierTarget: "evm" },
    );
}

describe("circuit fixtures", () => {
    it("have the ABI the SDK expects", () => {
        expect(txCircuit.abi.parameters.map((p: { name: string }) => p.name)).toEqual([
            "signers",
            "threshold",
            "signers_root",
            "salt",
            "merkle_proof_length",
            "indices",
            "siblings",
            "signatures",
            "txn_hash",
            "on_chain_state_root",
        ]);
    });

    it("the SDK state root matches the Noir compute_state_root test vector", () => {
        // From noir/zk_multi_sig_ecdsa/src/main.nr (TEST_*).
        const signersRoot = 16223743289759414337474221898890222788896083712324022742978151074941795950178n;
        expect(computeStateRoot(signersRoot, 2, SALT)).toBe(
            20321389246711366214573318284446720008267991448836355782945972567979658685784n,
        );
    });
});

describe("zk_multi_sig_ecdsa: SDK inputs satisfy the circuit", () => {
    const accounts = testAccounts(5);

    // [name, number of signers, threshold, indices of the signers that sign]
    const cases: Array<[string, number, number, number[]]> = [
        ["1-of-1", 1, 1, [0]],
        ["1-of-2, the second signer signs", 2, 1, [1]],
        ["2-of-2", 2, 2, [0, 1]],
        ["2-of-3, the middle and last signer", 3, 2, [1, 2]],
        ["3-of-3", 3, 3, [0, 1, 2]],
        ["3-of-4, a gap in the middle", 4, 3, [0, 2, 3]],
        ["2-of-5, the last two (largest tree)", 5, 2, [3, 4]],
        ["5-of-5, every slot used", 5, 5, [0, 1, 2, 3, 4]],
        ["2-of-5 with extra, unneeded signatures", 5, 2, [0, 1, 2, 3, 4]],
    ];

    it.each(cases)("%s", async (name, count, threshold, who) => {
        const config: MultiSigConfig = {
            signers: accounts.slice(0, count).map((a) => a.address),
            threshold,
            salt: SALT,
        };
        const hash = hashOf(`tx:${name}`);
        const signatures = await Promise.all(who.map((i) => accounts[i].sign({ hash })));
        const state = createMultiSigState(config);

        const input = buildMultiSigCircuitInput(config, hash, signatures, state.stateRoot);
        await expect(execute(txCircuit, input)).resolves.toHaveProperty("witness");
    });

    it("is insensitive to the order of the supplied signatures and of the signer list", async () => {
        const signers = accounts.slice(0, 4).map((a) => a.address);
        const hash = hashOf("order");
        const sigs = await Promise.all([3, 0, 2].map((i) => accounts[i].sign({ hash })));
        const a = buildMultiSigCircuitInput({ signers, threshold: 3, salt: SALT }, hash, sigs);
        const b = buildMultiSigCircuitInput(
            { signers: [...signers].reverse().map((s) => s.toLowerCase()), threshold: 3, salt: SALT },
            hash,
            [...sigs].reverse(),
        );
        expect(a).toEqual(b);
        await expect(execute(txCircuit, a)).resolves.toHaveProperty("witness");
    });

    it("the circuit rejects what the SDK pre-flight rejects", async () => {
        const signers = accounts.slice(0, 3).map((a) => a.address);
        const config: MultiSigConfig = { signers, threshold: 2, salt: SALT };
        const hash = hashOf("negatives");
        const [s0, s1] = await Promise.all([accounts[0].sign({ hash }), accounts[1].sign({ hash })]);
        const good = buildMultiSigCircuitInput(config, hash, [s0, s1]);

        // Below threshold: drop the second slot to NIL.
        const belowThreshold = {
            ...good,
            signers: [good.signers[0], ...good.signers.slice(2), good.signers[2]],
            signatures: [good.signatures[0], ...good.signatures.slice(2), good.signatures[2]],
        };
        await expect(execute(txCircuit, belowThreshold)).rejects.toThrow();

        // Wrong salt.
        await expect(execute(txCircuit, { ...good, salt: toHex(SALT + 1n) })).rejects.toThrow();

        // Wrong on-chain state root.
        await expect(execute(txCircuit, { ...good, on_chain_state_root: toHex(1n) })).rejects.toThrow();

        // Signature over a different hash.
        await expect(execute(txCircuit, { ...good, txn_hash: Array.from(toBytes(hashOf("other"))) })).rejects.toThrow();

        // The same signature twice (addresses must be strictly increasing).
        const twice = {
            ...good,
            signers: [good.signers[0], good.signers[0], ...good.signers.slice(2)],
            signatures: [good.signatures[0], good.signatures[0], ...good.signatures.slice(2)],
            indices: [good.indices[0], good.indices[0], ...good.indices.slice(2)],
            siblings: [good.siblings[0], good.siblings[0], ...good.siblings.slice(2)],
            merkle_proof_length: [good.merkle_proof_length[0], good.merkle_proof_length[0], 0, 0, 0],
        };
        await expect(execute(txCircuit, twice)).rejects.toThrow();

        // A signer outside the set.
        const [outsider] = testAccounts(1, "outsider");
        const sigOutside = await outsider.sign({ hash });
        expect(() => buildMultiSigCircuitInput(config, hash, [s0, sigOutside])).toThrow(NotFoundError);
        expect(() => buildMultiSigCircuitInput(config, hash, [s0])).toThrow(InvalidArgumentError);
        expect(() => buildMultiSigCircuitInput(config, hash, [s0, s0])).toThrow(/more than once/);
        expect(() => buildMultiSigCircuitInput(config, hash, [s0, s1], toHex(1n))).toThrow(ChainStateError);
    });

    it("high-S signatures are refused by the SDK; the circuit's own behaviour is pinned", async () => {
        const signers = accounts.slice(0, 2).map((a) => a.address);
        const config: MultiSigConfig = { signers, threshold: 1, salt: SALT };
        const hash = hashOf("high-s");
        const sig = await accounts[0].sign({ hash });
        const bytes = hexToBytes(sig);
        const n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
        const s = BigInt(toHex(bytes.slice(32, 64)));
        const highS =
            `0x${sig.slice(2, 66)}${(n - s).toString(16).padStart(64, "0")}${bytes[64] === 27 ? "1c" : "1b"}` as Hex;

        expect(() => buildMultiSigCircuitInput(config, hash, [highS])).toThrow(/low-S/);

        // Bypass the pre-flight to see what the circuit itself does with the malleated twin.
        const good = buildMultiSigCircuitInput(config, hash, [sig]);
        const malleated = {
            ...good,
            signatures: [Array.from(hexToBytes(highS).slice(0, 64)), ...good.signatures.slice(1)],
        };
        await expect(execute(txCircuit, malleated)).rejects.toThrow();
    });
});

describe("proofs", () => {
    const accounts = testAccounts(3, "proofs");
    const signers = accounts.map((a) => a.address);
    const config: MultiSigConfig = { signers, threshold: 2, salt: SALT };
    const state = createMultiSigState(config);

    it(
        "state validation: generates a proof that verifies and binds to the state root",
        async () => {
            const proof = await generateStateValidationProof(config, stateCircuit, { barretenberg: api });
            expect(proof.publicInputs).toHaveLength(1);
            expect(BigInt(proof.stateRoot)).toBe(state.stateRoot);
            await expect(verify(stateCircuit, proof)).resolves.toBe(true);

            // A different public input must not verify.
            const tampered = { ...proof, publicInputs: [toHex(state.stateRoot + 1n, { size: 32 })] };
            await expect(verify(stateCircuit, tampered).catch(() => false)).resolves.toBe(false);
        },
        PROOF_TIMEOUT,
    );

    it("state validation input satisfies the circuit and equals the Noir test configuration's root", async () => {
        const input = buildStateValidationCircuitInput(config);
        expect(BigInt(input.on_chain_state_root)).toBe(state.stateRoot);
        await expect(execute(stateCircuit, input)).resolves.toHaveProperty("witness");
    });

    it(
        "transaction: generates a proof that verifies, with the documented public inputs",
        async () => {
            const hash = hashOf("transfer");
            const signatures = await Promise.all([0, 2].map((i) => accounts[i].sign({ hash })));
            const proof = await generateMultiSigProof(config, hash, signatures, state.stateRoot, txCircuit, {
                barretenberg: api,
            });

            expect(proof.publicInputs).toHaveLength(MULTISIG_PUBLIC_INPUTS);
            expect(proof.publicInputs).toEqual(buildMultiSigPublicInputs(hash, state.stateRoot));
            expect(proof.txnHash).toBe(hash);
            expect(BigInt(proof.stateRoot)).toBe(state.stateRoot);
            await expect(verify(txCircuit, proof)).resolves.toBe(true);

            // Binding: the same proof does not verify for another transaction hash or another state root.
            const otherHash = { ...proof, publicInputs: buildMultiSigPublicInputs(hashOf("other"), state.stateRoot) };
            await expect(verify(txCircuit, otherHash).catch(() => false)).resolves.toBe(false);
            const otherRoot = { ...proof, publicInputs: buildMultiSigPublicInputs(hash, state.stateRoot + 1n) };
            await expect(verify(txCircuit, otherRoot).catch(() => false)).resolves.toBe(false);
        },
        PROOF_TIMEOUT,
    );

    it(
        "creates and destroys its own Barretenberg instance when none is supplied",
        async () => {
            const hash = hashOf("own-instance");
            const single = { signers: [signers[0]], threshold: 1, salt: SALT };
            const root = createMultiSigState(single).stateRoot;
            const proof = await generateMultiSigProof(
                single,
                hash,
                [await accounts[0].sign({ hash })],
                root,
                txCircuit,
            );
            await expect(verify(txCircuit, proof)).resolves.toBe(true);
        },
        PROOF_TIMEOUT,
    );

    it("refuses early when the configuration does not match the chain (wrong salt) and for the wrong circuit", async () => {
        const hash = hashOf("wrong-salt");
        const signatures = await Promise.all([0, 1].map((i) => accounts[i].sign({ hash })));
        await expect(
            generateMultiSigProof({ ...config, salt: SALT + 1n }, hash, signatures, state.stateRoot, txCircuit),
        ).rejects.toThrow(ChainStateError);
        await expect(generateMultiSigProof(config, hash, signatures, state.stateRoot, stateCircuit)).rejects.toThrow(
            InvalidCircuitError,
        );
        await expect(generateStateValidationProof(config, txCircuit)).rejects.toThrow(InvalidCircuitError);
    });
});
