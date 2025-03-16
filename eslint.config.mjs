import globals from "globals";
import js from "@eslint/js";
import jsdoc from "eslint-plugin-jsdoc";
import json from "@eslint/json";
import mocha from "eslint-plugin-mocha";
import mozilla from "eslint-plugin-mozilla";
import stylistic from "@stylistic/eslint-plugin";


export default [
	{
		ignores: ["thirdparty/**/*"],
	}, {
		files: ["**/*.js", "**/*.mjs"],
		...js.configs.recommended,
	}, {
		files: ["**/*.js", "**/*.mjs"],
		...jsdoc.configs["flat/recommended-typescript-flavor"],
	}, {
		files: ["**/*.js", "**/*.mjs"],
		...stylistic.configs.customize({
			braceStyle: "1tbs",
			indent: "tab",
			semi: true,
		}),
	}, {
		files: ["**/*.js", "**/*.mjs"],
		plugins: {
			"@stylistic": stylistic,
			jsdoc,
			mocha,
			mozilla,
		},

		languageOptions: {
			ecmaVersion: 2024,
			sourceType: "module",

			globals: {
				globalThis: "readonly",
			},

			parserOptions: {
				ecmaFeatures: {},
			},
		},

		rules: {
			// Possible Problems
			"array-callback-return": "warn",
			"no-constant-binary-expression": "warn",
			"no-constructor-return": "warn",
			"no-duplicate-imports": "warn",
			"no-new-native-nonconstructor": "warn",
			"no-promise-executor-return": "warn",
			"no-self-compare": "warn",
			"no-template-curly-in-string": "warn",
			"no-unmodified-loop-condition": "warn",
			"no-unreachable-loop": "warn",
			"no-unused-private-class-members": "warn",
			"no-unused-vars": ["error", {
				argsIgnorePattern: "^_",
			}],
			"no-use-before-define": "error",
			"require-atomic-updates": "warn",

			// Suggestions
			"block-scoped-var": "warn",
			"camelcase": ["warn", {
				allow: [
					"DKIM_Error",
					"DKIM_SigError",
					"DKIM_TempError",
				],
			}],
			"complexity": "warn",
			"consistent-return": "warn",
			"curly": "warn",
			"default-case": "warn",
			"default-case-last": "warn",
			"default-param-last": "warn",
			"dot-notation": "warn",
			"eqeqeq": "warn",
			"grouped-accessor-pairs": "warn",
			"guard-for-in": "warn",
			"logical-assignment-operators": "error",
			"no-alert": "error",
			"no-array-constructor": "error",
			"no-caller": "warn",
			"no-confusing-arrow": "warn",
			"no-div-regex": "warn",
			"no-else-return": "warn",
			"no-empty-function": "warn",
			"no-eq-null": "warn",
			"no-eval": "error",
			"no-extend-native": "warn",
			"no-extra-bind": "warn",
			"no-extra-label": "warn",
			"no-floating-decimal": "warn",
			"no-implicit-coercion": "warn",
			"no-implied-eval": "error",
			"no-invalid-this": "warn",
			"no-iterator": "warn",
			"no-label-var": "warn",
			"no-labels": "warn",
			"no-lone-blocks": "warn",
			"no-loop-func": "warn",
			"no-magic-numbers": ["warn", {
				ignoreArrayIndexes: true,
				ignore: [-1, 0, 1, 2, 3],
			}],
			"no-multi-assign": "warn",
			"no-multi-str": "warn",
			"no-nested-ternary": "warn",
			"no-new": "warn",
			"no-new-func": "warn",
			"no-new-object": "warn",
			"no-new-wrappers": "warn",
			"no-octal-escape": "warn",
			"no-param-reassign": "warn",
			"no-proto": "warn",
			"no-return-assign": "warn",
			"no-return-await": "warn",
			"no-script-url": "warn",
			"no-sequences": "warn",
			"no-shadow": "warn",
			"no-throw-literal": "warn",
			"no-undef-init": "warn",
			"no-unneeded-ternary": "warn",
			"no-unused-expressions": "warn",
			"no-useless-call": "warn",
			"no-useless-computed-key": "warn",
			"no-useless-concat": "warn",
			"no-useless-constructor": "warn",
			"no-useless-return": "warn",
			"no-var": "warn",
			"no-void": "warn",
			"no-warning-comments": process.env.CI === "true" ? "off" : "warn",
			"object-shorthand": "warn",
			"one-var": ["warn", "never"],
			"operator-assignment": "warn",
			"prefer-const": "warn",
			"prefer-exponentiation-operator": "warn",
			"prefer-numeric-literals": "warn",
			"prefer-object-has-own": "warn",
			"prefer-object-spread": "warn",
			"prefer-promise-reject-errors": "warn",
			"prefer-rest-params": "warn",
			"prefer-spread": "warn",
			"prefer-template": "warn",
			"radix": "warn",
			"require-await": "warn",
			"sort-imports": "warn",
			"strict": ["warn", "global"],
			"yoda": "warn",

			// Stylistic
			"@stylistic/arrow-parens": "off",
			"@stylistic/comma-dangle": ["warn", {
				arrays: "always-multiline",
				objects: "always-multiline",
				imports: "always-multiline",
				exports: "always-multiline",
				functions: "only-multiline",
				importAttributes: "always-multiline",
				dynamicImports: "always-multiline",
			}],
			"@stylistic/dot-location": ["warn", "object"],
			"@stylistic/function-call-spacing": "warn",
			"@stylistic/indent": ["error", "tab", {
				SwitchCase: 1,
				tabLength: 4,
			}],
			"@stylistic/linebreak-style": "error",
			"@stylistic/max-statements-per-line": ["warn", { max: 2 }],
			"@stylistic/no-confusing-arrow": "warn",
			"@stylistic/no-extra-parens": ["warn", "all", {
				allowParensAfterCommentPattern: "@type",
				nestedBinaryExpressions: false,
			}],
			"@stylistic/no-extra-semi": "warn",
			"@stylistic/no-multiple-empty-lines": ["warn", { max: 2, maxBOF: 0, maxEOF: 0 }],
			"@stylistic/object-property-newline": ["warn", { allowAllPropertiesOnSameLine: true }],
			"@stylistic/one-var-declaration-per-line": ["warn", "always"],
			"@stylistic/operator-linebreak": ["warn", "after", { overrides: { "?": "before", ":": "before" } }],
			"@stylistic/quotes": ["warn", "double", {
				avoidEscape: true,
			}],
			"@stylistic/semi-style": "warn",
			"@stylistic/spaced-comment": ["warn", "always", {
				block: {
					balanced: false,
					markers: [","],
				},
				line: {
					exceptions: ["/"],
					markers: ["//", "////", "/<reference", "#region", "#endregion"],
				},
			}],
			"@stylistic/switch-colon-spacing": "warn",

			// JSDoc
			"jsdoc/check-line-alignment": "warn",
			"jsdoc/check-syntax": "warn",
			"jsdoc/match-description": "warn",
			"jsdoc/no-bad-blocks": "warn",
			"jsdoc/no-defaults": "warn",
			"jsdoc/require-asterisk-prefix": "warn",
			"jsdoc/require-hyphen-before-param-description": "warn",
			"jsdoc/require-param-description": "off",
			"jsdoc/require-property-description": "off",
			"jsdoc/require-returns": ["warn", {
				checkGetters: false,
			}],
			"jsdoc/require-returns-description": "off",
			"jsdoc/tag-lines": ["warn", "never", {
				startLines: 1,
			}],

			// Mocha
			"mocha/no-return-from-async": "warn",
			"mocha/prefer-arrow-callback": "warn",

			// Mozilla
			"mozilla/avoid-removeChild": "warn",
			"mozilla/consistent-if-bracing": "warn",
			"mozilla/no-compare-against-boolean-literals": "warn",
			"mozilla/no-useless-removeEventListener": "warn",
			"mozilla/prefer-boolean-length-check": "warn",
			"mozilla/prefer-formatValues": "warn",
			"mozilla/use-includes-instead-of-indexOf": "warn",
			"mozilla/use-ownerGlobal": "warn",
			"mozilla/use-returnValue": "warn",
		},
	}, {
		files: ["content/**/*.js", "content/**/*.mjs"],
		languageOptions: {
			globals: {
				...globals.browser,
				...globals.webextensions,
			},
		},
	}, {
		files: ["experiments/**/*.js", "experiments/**/*.mjs"],
		plugins: {
			mozilla,
		},
		languageOptions: {
			globals: {
				...mozilla.environments.privileged.globals,
				...mozilla.environments.specific.globals,
			},
		},
		rules: {
			"mozilla/no-define-cc-etc": "warn",
			"mozilla/no-throw-cr-literal": "warn",
			"mozilla/no-useless-parameters": "warn",
			"mozilla/reject-chromeutils-import-params": "warn",
			"mozilla/reject-importGlobalProperties": [
				"warn",
				"allownonwebidl",
			],
			"mozilla/rejects-requires-await": "warn",
			"mozilla/use-cc-etc": "warn",
			"mozilla/use-chromeutils-generateqi": "warn",
			"mozilla/use-chromeutils-import": "warn",
			"mozilla/use-default-preference-values": "warn",
			"mozilla/use-services": "warn",
		},
	}, {
		files: ["experiments/**/*.js"],
		languageOptions: {
			sourceType: "script",
		},
	}, {
		files: ["modules/**/*.js", "modules/**/*.mjs"],
		languageOptions: {
			globals: {
				...globals["shared-node-browser"],
				...globals.webextensions,
			},
		},
	}, {
		files: ["scripts/**/*.js", "scripts/**/*.mjs"],
		languageOptions: {
			globals: {
				...globals.node,
			},
		},
	}, {
		files: ["test/helpers/**/*.js", "test/helpers/**/*.mjs"],
		languageOptions: {
			globals: {
				...globals.mocha,
				...globals["shared-node-browser"],
			},
		},
	}, {
		files: ["test/unittest/**/*.js", "test/unittest/**/*.mjs"],
		...mocha.configs.flat.recommended,
	}, {
		files: ["test/unittest/**/*.js", "test/unittest/**/*.mjs"],
		languageOptions: {
			globals: {
				...globals["shared-node-browser"],
				...globals.webextensions,
			},
		},
		rules: {
			"no-magic-numbers": "off",
			"no-unused-expressions": "off",
		},
	}, {
		files: ["eslint.config.mjs"],
		languageOptions: {
			globals: {
				...globals.node,
			},
		},
	}, {
		files: ["**/*.json"],
		ignores: ["package-lock.json"],
		language: "json/json",
		...json.configs.recommended,
	}, {
		files: [
			".vscode/**/*.json",
			"_locales/**/*.json",
			"jsconfig.json",
		],
		language: "json/jsonc",
	}, {
		files: [
			".vscode/**/*.json",
			"jsconfig.json",
		],
		languageOptions: {
			allowTrailingCommas: true,
		},
	},
];
