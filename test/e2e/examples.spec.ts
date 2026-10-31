import { describe, expect, it } from "vitest";
import { main as label } from "../../examples/zk-label.js";
import { main as scope } from "../../examples/zk-scope.js";
import { main as signer } from "../../examples/zk-signer.js";

// The examples are documentation that must keep working: run them end to end.
describe("examples", () => {
    it("zk-signer", async () => {
        const result = await signer();
        expect(result.proof.publicInputs).toHaveLength(33);
        expect(result.calldata).toMatch(/^0x/);
    }, 120_000);

    it("zk-label", async () => {
        const result = await label();
        expect(result.proof.publicInputs).toHaveLength(2);
        expect(result.calldata).toMatch(/^0x/);
    }, 120_000);

    it("zk-scope", async () => {
        const result = await scope();
        expect(result.proof.publicInputs).toHaveLength(5);
        expect(result.calldata).toMatch(/^0x/);
    }, 120_000);
});
