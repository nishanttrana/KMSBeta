import js from "@eslint/js";
import reactHooks from "eslint-plugin-react-hooks";
import globals from "globals";
import tseslint from "typescript-eslint";

export default tseslint.config(
  {
    ignores: [
      "dist/**",
      "node_modules/**",
      "src/generated/**",
      "scripts/**"
    ]
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ["**/*.{ts,tsx}"],
    languageOptions: {
      globals: {
        ...globals.browser,
        ...globals.node
      }
    },
    plugins: {
      "react-hooks": reactHooks
    },
    rules: {
      "@typescript-eslint/no-unused-vars": [
        "error",
        {
          varsIgnorePattern: "^_",
          argsIgnorePattern: "^_",
          ignoreRestSiblings: true
        }
      ],
      "@typescript-eslint/no-explicit-any": "off",
      "react-hooks/rules-of-hooks": "error",
      "react-hooks/exhaustive-deps": "error"
    }
  },
  {
    files: ["**/*.{js,mjs,cjs}"],
    rules: {
      "no-undef": "error"
    }
  },
  {
    files: ["src/**/*.{ts,tsx}"],
    ignores: ["src/generated/**", "src/lib/**"],
    rules: {
      // Enforce API access through generated/service client modules only.
      "no-restricted-globals": ["error", "fetch"],
      "no-restricted-imports": [
        "error",
        {
          patterns: [
            {
              group: ["**/lib/serviceApi"],
              message: "Use typed client modules in src/lib/* instead of importing serviceRequest directly in UI modules."
            }
          ]
        }
      ]
    }
  },
  {
    files: ["src/lib/serviceApi.ts", "src/lib/auth.ts", "src/lib/deployment.ts"],
    rules: {
      // Allow raw fetch only in centralized service client.
      "no-restricted-globals": "off"
    }
  }
);
