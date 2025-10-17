module.exports = {
  env: {
    node: true,
    es2021: true,
    jest: true
  },
  extends: [
    'eslint:recommended'
  ],
  parserOptions: {
    ecmaVersion: 12,
    sourceType: 'module'
  },
  rules: {
    'no-unused-vars': 'warn',
    'no-console': 'off',
    'no-undef': 'error',
    'no-redeclare': 'error',
    'no-duplicate-case': 'error',
    'no-empty': 'warn',
    'no-extra-semi': 'warn',
    'no-func-assign': 'error',
    'no-irregular-whitespace': 'warn',
    'no-unreachable': 'error',
    'use-isnan': 'error',
    'valid-typeof': 'error'
  }
};


