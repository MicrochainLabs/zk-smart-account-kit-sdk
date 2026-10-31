/**
 * ZK Signer — prove that an authorised signer approved a transaction hash,
 * without revealing which signer it was.
 *
 *   1. Commit the set of authorised signers as a Merkle root (stored on-chain).
 *   2. A signer signs the transaction hash (raw hash, no Ethereum message prefix).
 *   3. Generate a proof; submit `encodeZKSignerProofCalldata(proof)` on-chain.
 *
 * Requires the optional peers: pnpm add @aztec/bb.js @noir-lang/noir_js
 * and the compiled zk_signers circuit (see README → Circuits).
 */

import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak256, toBytes } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import {
    buildSignersTree,
    encodeSignersInitData,
    encodeZKSignerProofCalldata,
    generateZKSignerProof,
    parsePubKey,
} from "zk-smart-account-kit-sdk/zk-signer";
import circuit from "../test/fixtures/circuits/zk_signers.json" with { type: "json" };

export async function main() {
    // Demo keys. In production the private key stays in the signer's wallet/HSM.
    const privateKey = toBytes(keccak256(toBytes("example-signer")));
    const address = privateKeyToAccount(`0x${Buffer.from(privateKey).toString("hex")}`).address;
    const pubKey = parsePubKey(secp256k1.getPublicKey(privateKey, false));

    // 1. Authorised signers (a canonical order, e.g. sorted by address, keeps the root reproducible).
    const tree = buildSignersTree([{ signer: address }]);
    const initData = encodeSignersInitData(tree.signersRoot); // for module installation

    // 2. The signer signs the 32-byte transaction hash. The signature must be low-S (noble's default).
    const txnHash = Array.from(toBytes(keccak256(toBytes("transfer 1 ETH to alice"))));
    const signature = Array.from(secp256k1.sign(Uint8Array.from(txnHash), privateKey).toCompactRawBytes());

    // 3. Prove (Node.js only) and encode for on-chain submission.
    const proof = await generateZKSignerProof(pubKey, signature, address, tree, txnHash, circuit);
    const calldata = encodeZKSignerProofCalldata(proof);

    return { initData, proof, calldata };
}
