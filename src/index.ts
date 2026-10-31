/**
 * zk-smart-account-kit-sdk
 *
 * Unified TypeScript SDK for Microchain ZK primitives.
 *
 * Subpath imports give tree-shakeable, granular access:
 *
 *   import { buildLabelsTree, ZKLabelsHelper } from "zk-smart-account-kit-sdk/zk-label";
 *   import { parsePubKey, type PubKey }        from "zk-smart-account-kit-sdk/zk-signer";
 *
 * The root import re-exports every primitive for convenience:
 *
 *   import { buildLabelsTree, parsePubKey } from "zk-smart-account-kit-sdk";
 */

export * from "./zk-label/index.js";
export * from "./zk-signer/index.js";
export * from "./zk-scope/index.js";
