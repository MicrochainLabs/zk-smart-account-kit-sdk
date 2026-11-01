// Builds the third-party and Microchain contracts that the integration tests need (Safe, Nexus,
// ERC-4337 EntryPoint v0.7, ZK validator and factories) from source into a Foundry output directory,
// without modifying the microchain-zk-signers checkout:
//
//   node scripts/build-integration-contracts.mjs <path-to-microchain-zk-signers> <out-dir>
//   ZK_SIGNERS_OUT=<out-dir> pnpm test:integration
//
// Requires Foundry (`forge`), git and network access (first run only) to fetch two Nexus dependencies
// that microchain-zk-signers does not install. Their revisions are pinned below. Nothing from here is
// committed or published: third-party bytecode is never vendored in this repository.

import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const [signersArg, outArg] = process.argv.slice(2);
if (!signersArg || !outArg) {
    console.error("usage: node scripts/build-integration-contracts.mjs <microchain-zk-signers> <out-dir>");
    process.exit(2);
}
const signers = resolve(signersArg);
const out = resolve(outArg);

// Pinned dependency revisions (Nexus imports both; microchain-zk-signers does not install them).
const DEPENDENCIES = [
    { name: "composability", url: "https://github.com/bcnmy/composability.git", ref: "v1.1.0" },
    {
        name: "erc7579",
        url: "https://github.com/erc7579/erc7579-implementation.git",
        ref: "99cbd34479b9d125651316ff2d92f38611ddf665",
    },
];

// A fresh, private (mode 0700) directory: a predictable path in the shared temp dir would let another
// local user pre-create it and plant a foundry.toml or remappings that this script then builds with.
const work = mkdtempSync(join(tmpdir(), "zk-sdk-integration-contracts-"));
mkdirSync(join(work, "src"));
mkdirSync(join(work, "deps"));

const run = (cmd, args, cwd) => execFileSync(cmd, args, { cwd, stdio: "inherit" });

try {
    for (const dep of DEPENDENCIES) {
        const dir = join(work, "deps", dep.name);
        // Fetch exactly the pinned tag or commit.
        mkdirSync(dir);
        run("git", ["init", "--quiet"], dir);
        run("git", ["fetch", "--quiet", "--depth", "1", dep.url, dep.ref], dir);
        run("git", ["checkout", "--quiet", "FETCH_HEAD"], dir);
    }

    const remappings = [
        `@openzeppelin/=${signers}/node_modules/@openzeppelin/`,
        `account-abstraction/=${signers}/node_modules/account-abstraction/contracts/`,
        `@account-abstraction/=${signers}/node_modules/@account-abstraction/`,
        `solady/=${signers}/node_modules/solady/src/`,
        `@safe-global/=${signers}/node_modules/@safe-global/`,
        `@biconomy/nexus/=${signers}/lib/nexus/contracts/`,
        `sentinellist/=${signers}/lib/sentinellist/src/`,
        `solarray/=${signers}/lib/solarray/src/`,
        `erc7739Validator/=${signers}/lib/erc7739Validator/src/`,
        `excessively-safe-call/=${signers}/lib/ExcessivelySafeCall/src/`,
        `composability/=${join(work, "deps", "composability", "contracts")}/`,
        `erc7579/=${join(work, "deps", "erc7579", "src")}/`,
        `zk-signers/=${signers}/contracts/`,
    ];
    writeFileSync(join(work, "remappings.txt"), remappings.join("\n") + "\n", { mode: 0o600 });

    writeFileSync(
        join(work, "foundry.toml"),
        `[profile.default]
    src = 'src'
    out = '${out}'
    libs = []
    cache_path = 'cache'
    solc_version = '0.8.29'
    evm_version = 'cancun'
    optimizer = true
    optimizer_runs = 200
    `,
    );

    // One file per group: wildcard imports of unrelated trees clash on shared interface names (IERC165, …).
    const SOURCES = {
        "Nexus.sol": ["@biconomy/nexus/Nexus.sol", "@biconomy/nexus/utils/NexusBootstrap.sol"],
        "EntryPointDep.sol": ["account-abstraction/core/EntryPoint.sol"],
        "ZkSigners.sol": [
            "zk-signers/nexus/factory/ZKMultiSigValidatorFactory.sol",
            "zk-signers/nexus/modules/validators/ZKMultiSigValidator.sol",
        ],
        "SafeDeps.sol": [
            "@safe-global/safe-contracts/contracts/Safe.sol",
            "@safe-global/safe-contracts/contracts/proxies/SafeProxyFactory.sol",
            "@safe-global/safe-contracts/contracts/handler/CompatibilityFallbackHandler.sol",
        ],
    };
    for (const [file, imports] of Object.entries(SOURCES)) {
        writeFileSync(
            join(work, "src", file),
            `// SPDX-License-Identifier: MIT\npragma solidity >=0.7.0;\n\n${imports.map((i) => `import "${i}";`).join("\n")}\n`,
        );
    }

    run("forge", ["build", "--root", work], work);
} finally {
    rmSync(work, { recursive: true, force: true });
}

console.log(`Contracts built into ${out}`);
