/**
 * ZK Scope — prove that a transaction is allowed by a private policy, without
 * revealing the policy. Only the root of the rule set is public.
 *
 * Requires the optional peers: pnpm add @aztec/bb.js @noir-lang/noir_js
 * and the compiled zk_scope_validation circuit (see README → Circuits).
 */

import {
    buildScopeTree,
    encodeScopeInitData,
    encodeScopeProofCalldata,
    exactMatch,
    generateScopeProof,
    padConstraints,
    rangeMax,
    type ScopeRule,
} from "zk-smart-account-kit-sdk/zk-scope";
import circuit from "../test/fixtures/circuits/zk_scope_validation.json" with { type: "json" };

const ROUTER = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
const USDC_ID = 0xa0b8n; // calldata values must fit in a BN254 field element

export async function main() {
    // Rule: call `deposit()` on the router, at most 1 ETH, token must be USDC, amount <= 1_000_000.
    const rule: ScopeRule = {
        target: ROUTER,
        selector: "0xd0e30db0", // exactly 4 bytes
        valueMax: 10n ** 18n,
        constraints: padConstraints([exactMatch(USDC_ID), rangeMax(1_000_000n)]),
    };

    const tree = buildScopeTree([rule]);
    const initData = encodeScopeInitData(tree.scopeRoot); // for module installation

    // The SDK checks the transaction against the rule before proving, so a violation fails fast with
    // an InvalidArgumentError instead of after seconds of proving work.
    const params = [USDC_ID, 500_000n];
    const proof = await generateScopeProof(ROUTER, rule.selector, 10n ** 17n, params, rule, tree, circuit);
    const calldata = encodeScopeProofCalldata(proof);

    return { initData, proof, calldata };
}
