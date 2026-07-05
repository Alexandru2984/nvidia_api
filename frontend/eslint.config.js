import js from '@eslint/js'
import globals from 'globals'
import reactHooks from 'eslint-plugin-react-hooks'
import reactRefresh from 'eslint-plugin-react-refresh'
import { defineConfig, globalIgnores } from 'eslint/config'

export default defineConfig([
  globalIgnores(['dist']),
  {
    files: ['**/*.{js,jsx}'],
    extends: [
      js.configs.recommended,
      reactHooks.configs.flat.recommended,
      reactRefresh.configs.vite,
    ],
    languageOptions: {
      globals: globals.browser,
      parserOptions: { ecmaFeatures: { jsx: true } },
    },
    rules: {
      // `catch {}` around best-effort calls (clipboard, optimistic deletes)
      // is intentional here.
      'no-empty': ['error', { allowEmptyCatch: true }],
      // Legacy sync-setState-in-effect patterns; safe but worth surfacing.
      'react-hooks/set-state-in-effect': 'warn',
    },
  },
])
