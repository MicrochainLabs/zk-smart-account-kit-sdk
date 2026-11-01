// Exports ABI + creation bytecode of the Microchain contracts used by the on-chain tests into
// test/fixtures/contracts, from a Foundry build of microchain-zk-signers:
//
//   OUT="$(mktemp -d)"   # private directory, not a predictable shared path
//   (cd ../microchain-zk-signers && forge build --out "$OUT/out" --cache-path "$OUT/cache")
//   pnpm sync-contracts "$OUT/out"
//
// Only Microchain's own contracts and the verifiers generated from the circuits are exported (no
// third-party bytecode). A manifest records the compiler version and a SHA-256 of every fixture so
// contract drift is visible in code review.

import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL(".", import.meta.url)), "..");
const out = resolve(process.argv[2] ?? join(root, "..", "microchain-zk-signers", "out"));

// [fixture name, forge source dir, contract name, include bytecode]
const CONTRACTS = [
    ["ZKMultiSigEcdsaFactory", "ZKMultiSigEcdsaFactory.sol", "ZKMultiSigEcdsaFactory", true],
    ["ZKMultiSigEcdsaSingleton", "ZKMultiSigEcdsaSingleton.sol", "ZKMultiSigEcdsaSingleton", true],
    ["ZKMultiSigEcdsaProxy", "ZKMultiSigEcdsaProxy.sol", "ZKMultiSigEcdsaProxy", true],
    ["ZKMultiSigValidator", "ZKMultiSigValidator.sol", "ZKMultiSigValidator", true],
    // The Nexus factory needs the Nexus account implementation to deploy; its ABI is enough for conformance tests.
    ["ZKMultiSigValidatorFactory", "ZKMultiSigValidatorFactory.sol", "ZKMultiSigValidatorFactory", false],
    ["ZKMultiSigEcdsaProofVerifier", "ZKMultiSigEcdsaProofVerifier.sol", "ZKMultiSigEcdsaProofVerifier", true],
    [
        "PrivateStateValidationProofVerifier",
        "PrivateStateValidationProofVerifier.sol",
        "PrivateStateValidationProofVerifier",
        true,
    ],
    ["TxHonkVerifier", "zk_multi_sig_ecdsa.sol", "HonkVerifier", true],
    ["TxRelationsLib", "zk_multi_sig_ecdsa.sol", "RelationsLib", true],
    ["TxZKTranscriptLib", "zk_multi_sig_ecdsa.sol", "ZKTranscriptLib", true],
    ["StateHonkVerifier", "zk_multi_sig_ecdsa_private_state_validation.sol", "HonkVerifier", true],
    ["StateRelationsLib", "zk_multi_sig_ecdsa_private_state_validation.sol", "RelationsLib", true],
    ["StateZKTranscriptLib", "zk_multi_sig_ecdsa_private_state_validation.sol", "ZKTranscriptLib", true],
];

const target = join(root, "test", "fixtures", "contracts");
mkdirSync(target, { recursive: true });

const manifest = {};
for (const [name, dir, contract, withBytecode] of CONTRACTS) {
    const artifact = JSON.parse(readFileSync(join(out, dir, `${contract}.json`), "utf8"));
    const fixture = { abi: artifact.abi };
    if (withBytecode) {
        fixture.bytecode = artifact.bytecode.object;
        fixture.linkReferences = artifact.bytecode.linkReferences;
    }
    const json = JSON.stringify(fixture);
    writeFileSync(join(target, `${name}.json`), json + "\n");
    manifest[name] = {
        solc: artifact.metadata.compiler.version,
        sha256: createHash("sha256").update(json).digest("hex"),
    };
    console.log(`${name}: ${withBytecode ? `${(fixture.bytecode.length - 2) / 2} bytes` : "abi only"}`);
}
writeFileSync(join(target, "manifest.json"), JSON.stringify(manifest, null, 2) + "\n");
