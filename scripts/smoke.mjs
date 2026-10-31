// Installs the packed tarball into a clean temp project (no dev dependencies, no
// optional peers) and exercises it from both ESM and CJS, exactly as a consumer would.
//
//   pnpm build && node scripts/smoke.mjs

import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

// import.meta.dirname is unavailable on Node 18, which this script must run on.
const root = resolve(fileURLToPath(new URL(".", import.meta.url)), "..");
const work = mkdtempSync(join(tmpdir(), "zk-sdk-smoke-"));
const run = (cmd, args, cwd) =>
    execFileSync(cmd, args, { cwd, stdio: ["ignore", "pipe", "inherit"], encoding: "utf8" });

try {
    const packed = JSON.parse(run("npm", ["pack", "--json", "--pack-destination", work], root));
    const tarball = join(work, packed[0].filename);

    writeFileSync(join(work, "package.json"), JSON.stringify({ name: "smoke", private: true }));
    run("npm", ["install", "--no-audit", "--no-fund", tarball], work);

    const body = `
        const subpaths = ["", "/zk-signer", "/zk-label", "/zk-scope", "/errors"];
        const assert = (cond, msg) => { if (!cond) { console.error("FAIL: " + msg); process.exit(1); } };
        const load = SPECIFIER;

        (async () => {
            for (const sub of subpaths) assert(await load("zk-smart-account-kit-sdk" + sub), "load " + sub);

            const root = await load("zk-smart-account-kit-sdk");
            const signer = await load("zk-smart-account-kit-sdk/zk-signer");
            const errors = await load("zk-smart-account-kit-sdk/errors");

            const tree = signer.buildSignersTree([{ signer: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266" }]);
            assert(tree.signersRoot === 7883074409468045280407067478175608582487155714151013737870117867970375847717n, "golden root");

            // Error classes must be shared across entry points.
            try { signer.buildSignersTree([]); assert(false, "empty tree must throw"); }
            catch (e) { assert(e instanceof errors.ZKSdkError && e instanceof root.ZKSdkError, "instanceof across subpaths"); }

            // Optional peers are not installed here: proving must fail with an actionable error.
            const circuit = { bytecode: "AAAA", abi: { parameters: ["pubkey","signature","proof_length","proof_index","proof_siblings","txn_hash","signers_root"].map((name) => ({ name })) } };
            const key = "0x" + "11".repeat(32);
            const { secp256k1 } = await load("@noble/curves/secp256k1");
            const { privateKeyToAccount } = await load("viem/accounts");
            const priv = Uint8Array.from(Buffer.from(key.slice(2), "hex"));
            const pub = secp256k1.getPublicKey(priv, false);
            const address = privateKeyToAccount(key).address;
            const hash = Array.from({ length: 32 }, (_, i) => i);
            const sig = Array.from(secp256k1.sign(Uint8Array.from(hash), priv).toCompactRawBytes());
            const t = signer.buildSignersTree([{ signer: address }]);
            try {
                await signer.generateZKSignerProof(signer.parsePubKey(pub), sig, address, t, hash, circuit);
                assert(false, "proving without peers must throw");
            } catch (e) {
                assert(e.code === "MISSING_PEER_DEPENDENCY", "missing peer error, got " + e.code + ": " + e.message);
            }
            console.log("ok");
        })();
    `;

    writeFileSync(join(work, "esm.mjs"), body.replace("SPECIFIER", "(s) => import(s)"));
    writeFileSync(join(work, "cjs.cjs"), body.replace("SPECIFIER", "(s) => Promise.resolve(require(s))"));

    for (const file of ["esm.mjs", "cjs.cjs"]) {
        const out = run(process.execPath, [file], work).trim();
        if (out !== "ok") throw new Error(`${file}: unexpected output ${out}`);
        console.log(`${file}: ok`);
    }
} finally {
    rmSync(work, { recursive: true, force: true });
}
