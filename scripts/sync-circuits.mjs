// Copies the compiled circuits used by the end-to-end tests from a checkout of
// zk-smart-account-kit into test/fixtures/circuits, stripping debug info
// (debug_symbols, file_map) to keep them small. Run after recompiling circuits:
//
//   pnpm sync-circuits [path/to/zk-smart-account-kit/noir/target]
//
// A manifest records the Noir version and a SHA-256 of each stripped artifact so
// circuit drift is visible in code review.

import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";

const CIRCUITS = ["zk_signers", "zk_label_binding", "zk_scope_validation"];

const root = resolve(import.meta.dirname, "..");
const source = resolve(process.argv[2] ?? join(root, "..", "zk-smart-account-kit", "noir", "target"));
const target = join(root, "test", "fixtures", "circuits");
mkdirSync(target, { recursive: true });

const manifest = {};
for (const name of CIRCUITS) {
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
writeFileSync(join(target, "manifest.json"), JSON.stringify(manifest, null, 2) + "\n");
