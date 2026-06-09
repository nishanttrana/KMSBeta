import js from "@eslint/js";
import reactHooks from "eslint-plugin-react-hooks";
import unusedImports from "eslint-plugin-unused-imports";
import globals from "globals";
import tseslint from "typescript-eslint";

export default tseslint.config(
  {
    ignores: [
      "dist/**",
      "node_modules/**",
      "public/openapi/swagger-ui/**",
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
      "react-hooks": reactHooks,
      "unused-imports": unusedImports
    },
    rules: {
      // Unused IMPORTS are always caught (and auto-removed by --fix) — they are
      // pure dead code. Unused local vars/args are left as a non-failing concern
      // on these long-lived dashboard files to avoid a noisy churn refactor,
      // consistent with the ESLint-10 rule policy below.
      "@typescript-eslint/no-unused-vars": "off",
      "unused-imports/no-unused-imports": "error",
      "unused-imports/no-unused-vars": "off",
      "@typescript-eslint/no-explicit-any": "off",
      // Warn on @ts-nocheck — it silences ALL type errors including missing imports.
      // Use @ts-expect-error with a description on specific lines instead.
      "@typescript-eslint/ban-ts-comment": [
        "warn",
        { "ts-nocheck": "allow-with-description", minimumDescriptionLength: 10 }
      ],
      "react-hooks/rules-of-hooks": "error",
      "react-hooks/exhaustive-deps": "error"
    }
  },
  {
    rules: {
      // ESLint 10 tightened broad style rules across long-lived dashboard files.
      // Keep dependency/security upgrades focused instead of forcing a noisy UI refactor.
      "no-extra-boolean-cast": "off",
      "no-useless-assignment": "off",
      "preserve-caught-error": "off"
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
