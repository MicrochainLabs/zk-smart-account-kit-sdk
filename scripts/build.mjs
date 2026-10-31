// Dual ESM + CJS build.
//
//   dist/esm  — tsc output (ESM JS + .d.ts), package "type": "module"
//   dist/cjs  — esbuild per-file CJS transpile + .d.ts, package "type": "commonjs"
//
// Both trees keep the source module structure (no bundling) so every subpath
// shares one copy of each module — in particular the error classes, which keeps
// `instanceof` working when a consumer mixes root and subpath imports.

import { execFileSync } from "node:child_process";
import { readdirSync, rmSync, writeFileSync, mkdirSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { build } from "esbuild";

const root = resolve(import.meta.dirname, "..");
const dist = join(root, "dist");
const tsc = join(root, "node_modules", "typescript", "bin", "tsc");

function walk(dir) {
    return readdirSync(dir).flatMap((name) => {
        const path = join(dir, name);
        return statSync(path).isDirectory() ? walk(path) : [path];
    });
}

rmSync(dist, { recursive: true, force: true });

// ESM: JS + declarations.
execFileSync(process.execPath, [tsc, "-p", "tsconfig.build.json"], { cwd: root, stdio: "inherit" });

// CJS: JS.
const entryPoints = walk(join(root, "src")).filter((f) => f.endsWith(".ts") && !f.endsWith(".d.ts"));
await build({
    entryPoints,
    outdir: join(dist, "cjs"),
    outbase: join(root, "src"),
    bundle: false,
    format: "cjs",
    platform: "node",
    target: "node18",
    sourcemap: true,
    sourcesContent: true,
    logLevel: "warning",
});

// CJS: declarations.
execFileSync(
    process.execPath,
    [
        tsc,
        "-p",
        "tsconfig.build.json",
        "--emitDeclarationOnly",
        "--outDir",
        "dist/cjs",
        "--sourceMap",
        "false",
        "--inlineSources",
        "false",
    ],
    { cwd: root, stdio: "inherit" },
);

mkdirSync(join(dist, "cjs"), { recursive: true });
writeFileSync(join(dist, "cjs", "package.json"), JSON.stringify({ type: "commonjs" }) + "\n");
writeFileSync(join(dist, "esm", "package.json"), JSON.stringify({ type: "module" }) + "\n");

console.log("Built dist/esm and dist/cjs");
