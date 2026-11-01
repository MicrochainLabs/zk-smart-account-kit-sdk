/**
 * zk-smart-account-kit-sdk
 *
 * Unified TypeScript SDK for Microchain ZK primitives.
 *
 * Subpath imports give tree-shakeable, granular access:
 *
 *   import { buildLabelsTree, createZKLabels } from "zk-smart-account-kit-sdk/zk-label";
 *   import { parsePubKey, type PubKey }        from "zk-smart-account-kit-sdk/zk-signer";
 *   import { createMultiSigState }              from "zk-smart-account-kit-sdk/zk-multisig";
 *
 * The root import re-exports every primitive for convenience:
 *
 *   import { buildLabelsTree, parsePubKey } from "zk-smart-account-kit-sdk";
 */

export * from "./errors.js";
export type { CompiledCircuit } from "./internal/compiled-circuit.js";
export { LeanIMT, type MerkleTreeLike, type HashFunction } from "./internal/merkle.js";
export * from "./zk-label/index.js";
export * from "./zk-signer/index.js";
export * from "./zk-scope/index.js";
export * from "./zk-multisig/index.js";
