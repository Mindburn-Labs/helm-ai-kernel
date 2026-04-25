import js from '@eslint/js';
import globals from 'globals';
import reactHooks from 'eslint-plugin-react-hooks';
import reactRefresh from 'eslint-plugin-react-refresh';
import tsParser from '@typescript-eslint/parser';
import tsPlugin from '@typescript-eslint/eslint-plugin';
import { createRequire } from 'module';

const require = createRequire(import.meta.url);
const noMagicValues = require('../../tools/eslint-rules/no-magic-values.js');
const noBannedTerms = require('../../tools/eslint-rules/no-banned-terms.js');
const noLayoutThrash = require('../../tools/eslint-rules/no-layout-thrash.js');

export default [
  { ignores: ['dist'] },
  {
    files: ['**/*.{ts,tsx}'],
    languageOptions: {
      ecmaVersion: 2020,
      globals: globals.browser,
      parser: tsParser,
    },
    plugins: {
      'react-hooks': reactHooks,
      'react-refresh': reactRefresh,
      '@typescript-eslint': tsPlugin,
      'local': {
        rules: {
          'no-magic-values': noMagicValues,
          'no-banned-terms': noBannedTerms,
          'no-layout-thrash': noLayoutThrash,
        }
      }
    },
    rules: {
      ...js.configs.recommended.rules,
      ...tsPlugin.configs.recommended.rules,
      ...reactHooks.configs.recommended.rules,
      'react-refresh/only-export-components': [
        'warn',
        { allowConstantExport: true },
      ],
      'local/no-magic-values': 'warn',
      'local/no-banned-terms': 'warn',
      'local/no-layout-thrash': 'warn',
    },
  },
];

