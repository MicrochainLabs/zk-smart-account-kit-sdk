/**
 * @microchain/zk-sdk — zk-scope subpath
 *
 * Rule encoding, tree construction, circuit input building, and ABI helpers
 * are browser-safe. Import `./prove.js` for proof generation (Node.js only).
 */

// Constants & types
export {
    SCOPE_MAX_DEPTH,
    MAX_PARAMS,
    PARAM_UNCONSTRAINED,
    PARAM_EXACT,
    PARAM_RANGE_MAX,
    type ParamConstraintType,
    type ParamConstraint,
    type ScopeRule,
    type ScopeTree,
    type ScopeMerkleProof,
    type ScopeCircuitInput,
    type ScopeProofData,
    unconstrained,
    exactMatch,
    rangeMax,
    padConstraints,
} from "./types.js";

// Rule encoding & hashing
export {
    selectorToField,
    computeParamsHash,
    computeCalldataHash,
    computeRuleLeaf,
    scopeHash,
    padParamValues,
} from "./rule.js";

// Merkle tree
export { buildScopeTree, getRuleMerkleProof } from "./tree.js";

// Circuit input builder (browser-safe)
export {
    buildScopeCircuitInput,
    buildScopeCircuitInputFromProof,
} from "./circuit.js";

// ABI encoding (browser-safe)
export {
    encodeScopePublicInputs,
    encodeScopeProofPublicInputs,
    encodeScopeInitData,
    encodeUpdateScopeRootData,
    encodeScopeProofCalldata,
} from "./abi.js";

// Proof generation (Node.js, requires peer deps)
export { generateScopeProof } from "./prove.js";
