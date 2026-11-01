/**
 * ZK Label — prove that an address holds a private label (role, group, tag…)
 * from a committed registry, without revealing the label or the address on-chain.
 *
 * Requires the optional peers: pnpm add @aztec/bb.js @noir-lang/noir_js
 * and the compiled zk_label_binding circuit (see README → Circuits).
 */

import { createZKLabels, encodeLabelProofCalldata, encodeLabelsInitData } from "zk-smart-account-kit-sdk/zk-label";
import circuit from "../test/fixtures/circuits/zk_label_binding.json" with { type: "json" };

const ADMIN = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
const MEMBER = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
const VIEWER = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC";

export async function main() {
    // The registry holds up to 16 labels; the tree is built immediately.
    const labels = createZKLabels(
        [
            { labelName: "admin", signer: ADMIN },
            { labelName: "member", signer: MEMBER },
        ],
        circuit,
    );

    const initData = encodeLabelsInitData(labels.registryRoot); // for module installation

    // Registries can be updated; each change returns the new root to publish on-chain.
    const newRoot = labels.addLabel({ labelName: "viewer", signer: VIEWER });

    const proof = await labels.proveLabelMembership("admin", ADMIN);
    const calldata = encodeLabelProofCalldata(proof);

    return { initData, newRoot, proof, calldata };
}
