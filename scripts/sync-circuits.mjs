// Copies the compiled circuits used by the end-to-end tests into test/fixtures/circuits, stripping
// debug info (debug_symbols, file_map) to keep them small. Run after recompiling circuits:
//
//   pnpm sync-circuits [kit-noir-target] [signers-noir-target]
//
//   kit-noir-target      zk-smart-account-kit/noir/target          (zk_signers, zk_label_binding, zk_scope_validation)
//   signers-noir-target  microchain-zk-signers/noir/target         (zk_multi_sig_ecdsa, zk_multi_sig_ecdsa_private_state_validation)
//
// A manifest records the Noir version and a SHA-256 of each stripped artifact so circuit drift is
// visible in code review.

import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL(".", import.meta.url)), "..");
const kitTarget = resolve(process.argv[2] ?? join(root, "..", "zk-smart-account-kit", "noir", "target"));
const signersTarget = resolve(process.argv[3] ?? join(root, "..", "microchain-zk-signers", "noir", "target"));

const SOURCES = [
    [kitTarget, ["zk_signers", "zk_label_binding", "zk_scope_validation"]],
    [signersTarget, ["zk_multi_sig_ecdsa", "zk_multi_sig_ecdsa_private_state_validation"]],
];

const target = join(root, "test", "fixtures", "circuits");
mkdirSync(target, { recursive: true });

const manifest = {};
for (const [source, names] of SOURCES) {
    for (const name of names) {
        const artifact = JSON.parse(readFileSync(join(source, `${name}.json`), "utf8"));
        const { debug_symbols: _debug, file_map: _files, ...stripped } = artifact;
        const json = JSON.stringify(stripped);
        writeFileSync(join(target, `${name}.json`), json + "\n");
        manifest[name] = {
            noir_version: stripped.noir_version,
            sha256: createHash("sha256").update(json).digest("hex"),
        };
        console.log(`${name}: ${stripped.noir_version} (${(json.length / 1024).toFixed(0)} KiB)`);
    }
}
writeFileSync(join(target, "manifest.json"), JSON.stringify(manifest, null, 2) + "\n");
