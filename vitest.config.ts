import { resolve } from "node:path";
import { defineConfig } from "vitest/config";

const src = resolve(import.meta.dirname, "src");

export default defineConfig({
    resolve: {
        // Examples import the package by name, as a consumer would; point that at the sources.
        alias: [
            { find: /^zk-smart-account-kit-sdk$/, replacement: `${src}/index.ts` },
            { find: /^zk-smart-account-kit-sdk\/(.*)$/, replacement: `${src}/$1/index.ts` },
        ],
    },
    test: {
        include: ["test/**/*.spec.ts"],
        testTimeout: 30_000,
        hookTimeout: 60_000,
        coverage: {
            provider: "v8",
            include: ["src/**/*.ts"],
            exclude: ["src/**/index.ts"],
            reporter: ["text-summary", "text", "lcov", "json-summary"],
            thresholds: { lines: 97, statements: 97, functions: 100, branches: 95 },
        },
    },
});
