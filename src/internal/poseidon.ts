/**
 * Typed facade over `@iden3/js-crypto`'s Poseidon.
 *
 * The package's `exports` map lists the `node` condition before `types`, so TypeScript
 * resolves it to an untyped JS file and the import silently becomes `any`. Funnelling
 * every call through this facade keeps the rest of the SDK fully typed.
 */

import { poseidon as untyped } from "@iden3/js-crypto";

interface Poseidon {
    /** Poseidon over BN254 (circom-compatible) for 1..16 field-element inputs. */
    hash(inputs: bigint[]): bigint;
}

// eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
export const poseidon: Poseidon = untyped;
