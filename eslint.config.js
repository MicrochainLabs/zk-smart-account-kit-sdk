import js from "@eslint/js";
import prettier from "eslint-config-prettier";
import tseslint from "typescript-eslint";

export default tseslint.config(
    { ignores: ["dist/", "coverage/", "docs/api/", "node_modules/", "test/fixtures/"] },

    js.configs.recommended,

    {
        files: ["src/**/*.ts"],
        extends: [...tseslint.configs.strictTypeChecked],
        languageOptions: {
            parserOptions: { projectService: true, tsconfigRootDir: import.meta.dirname },
        },
        rules: {
            "@typescript-eslint/no-floating-promises": "error",
            "@typescript-eslint/consistent-type-imports": ["error", { fixStyle: "inline-type-imports" }],
            "@typescript-eslint/restrict-template-expressions": ["error", { allowNumber: true, allowBoolean: true }],
            // Public signatures validate `unknown`-typed runtime input on purpose.
            "@typescript-eslint/no-unnecessary-condition": "off",
            "@typescript-eslint/no-non-null-assertion": "error",
            "@typescript-eslint/no-explicit-any": "error",
        },
    },

    {
        files: ["test/**/*.ts", "examples/**/*.ts", "*.config.ts"],
        extends: [...tseslint.configs.recommended],
        rules: {
            "@typescript-eslint/no-explicit-any": "off",
            "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_", varsIgnorePattern: "^_" }],
        },
    },

    {
        files: ["scripts/**/*.mjs"],
        languageOptions: {
            globals: { process: "readonly", console: "readonly", Buffer: "readonly", URL: "readonly" },
        },
        rules: { "no-unused-vars": ["error", { varsIgnorePattern: "^_" }] },
    },

    prettier,
);
