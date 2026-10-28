/**
 * Jest configuration.
 *
 * The root `test.js` is a manual demo script, not a Jest suite, so it is
 * ignored by path. Keep the default `node_modules` ignore as well.
 */
module.exports = {
  testPathIgnorePatterns: ['/node_modules/', '<rootDir>/test.js'],
};
