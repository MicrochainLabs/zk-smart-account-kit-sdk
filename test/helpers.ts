import { readFileSync } from "node:fs";
import { join } from "node:path";
import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak256, toBytes, type Address } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import type { PubKey } from "../src/zk-signer/types.js";

/** Deterministic throw-away keys derived from a label; never used outside tests. */
export function testKey(label: string): { privateKey: Uint8Array; address: Address; pubKey: PubKey } {
    const privateKey = toBytes(keccak256(toBytes(`zk-smart-account-kit-sdk/test/${label}`)));
    const uncompressed = secp256k1.getPublicKey(privateKey, false);
    const account = privateKeyToAccount(`0x${Buffer.from(privateKey).toString("hex")}`);
    return {
        privateKey,
        address: account.address,
        pubKey: { x: Array.from(uncompressed.slice(1, 33)), y: Array.from(uncompressed.slice(33, 65)) },
    };
}

/** Raw (unprefixed) low-S ECDSA signature, r || s, as the circuit expects. */
export function signRaw(privateKey: Uint8Array, hash: Uint8Array): number[] {
    return Array.from(secp256k1.sign(hash, privateKey).toCompactRawBytes());
}

export function testHash(label: string): number[] {
    return Array.from(toBytes(keccak256(toBytes(label))));
}

const circuitsDir = join(import.meta.dirname, "fixtures", "circuits");

export function loadCircuit(name: "zk_signers" | "zk_label_binding" | "zk_scope_validation"): any {
    return JSON.parse(readFileSync(join(circuitsDir, `${name}.json`), "utf8"));
}

/** Ten distinct, valid, checksummed-or-lowercase addresses. */
export const ADDRESSES: Address[] = Array.from(
    { length: 20 },
    (_, i) => privateKeyToAccount(keccak256(toBytes(`addr-${i}`))).address,
);

export const HARDHAT_0: Address = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
