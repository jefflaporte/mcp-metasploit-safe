import perfectionist from "eslint-plugin-perfectionist";
import eslint from "@eslint/js";
import tseslint from "typescript-eslint";

// Define configuration for TypeScript files
const typescriptConfig = {
    files: ["**/*.ts", "**/*.tsx"],
    ...tseslint.configs.recommended,
    rules: {
        // Add custom rules for TypeScript files here
        "no-unused-vars": "off", // Use TypeScript's version instead
        "@typescript-eslint/no-unused-vars": "warn",
        "@typescript-eslint/no-explicit-any": "warn",
        "@typescript-eslint/explicit-function-return-type": "off",
        "@typescript-eslint/no-non-null-assertion": "warn"
    }
};

// Define configuration for JavaScript files
const javascriptConfig = {
    files: ["**/*.js", "**/*.jsx"],
    ...eslint.configs.recommended,
    rules: {
        // Add custom rules for JavaScript files here
        "no-unused-vars": "warn",
        "no-console": "warn"
    }
};

export default [perfectionist.configs["recommended-alphabetical"]];
