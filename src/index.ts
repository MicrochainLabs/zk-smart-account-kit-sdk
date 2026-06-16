/**
 * @microchain/zk-sdk
 *
 * Unified TypeScript SDK for Microchain ZK primitives.
 *
 * Subpath imports give tree-shakeable, granular access:
 *
 *   import { buildLabelsTree, ZKLabelsHelper } from "@microchain/zk-sdk/zk-label";
 *   import { parsePubKey, type PubKey }        from "@microchain/zk-sdk/zk-signer";
 *
 * The root import re-exports every primitive for convenience:
 *
 *   import { buildLabelsTree, parsePubKey } from "@microchain/zk-sdk";
 */

export * from "./zk-label/index.js";
export * from "./zk-signer/index.js";
export * from "./zk-scope/index.js";
export * from "./zk-multisig/index.js";
