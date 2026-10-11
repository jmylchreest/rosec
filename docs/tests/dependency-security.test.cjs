// Temporary fix for GHSA-vfj7-8cjw-p6xm, pending a patched npm release.
// Patch source: https://github.com/micromatch/braces/pull/88
// Reviewed commit: a795ee83ecd011131b2d618fe754ac5a8e124dae.
// Keep these checks until the patch is replaced by an upstream release.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const braces = require('braces');

for (const operation of ['compile', 'expand', 'stringify']) {
  test(`${operation} rejects deep and cyclic ASTs without stack exhaustion`, () => {
    let ast = { type: 'text', value: 'x' };
    for (let i = 0; i < 12000; i++) ast = { type: 'root', nodes: [ast] };
    assert.throws(() => braces[operation](ast), SyntaxError);
    const cycle = { type: 'root', nodes: [] };
    cycle.nodes.push(cycle);
    assert.throws(() => braces[operation](cycle), SyntaxError);
  });
}

test('parser bounds both brace and parenthesis nesting', () => {
  for (const [open, close] of [['{', '}'], ['(', ')']]) {
    const pattern = open.repeat(4000) + 'x' + close.repeat(4000);
    for (const operation of ['parse', 'compile', 'expand', 'stringify']) {
      assert.throws(() => braces[operation](pattern), SyntaxError);
    }
  }
});

test('ordinary globs, ranges, nesting and shared nodes retain their behavior', () => {
  assert.deepEqual(braces.expand('a/{1..3}/{x,y}'),
    ['a/1/x', 'a/1/y', 'a/2/x', 'a/2/y', 'a/3/x', 'a/3/y']);
  assert.deepEqual(braces('docs/**/*.{md,mdx}'), ['docs/**/*.(md|mdx)']);
  assert.doesNotThrow(() => braces.compile('{'.repeat(64) + 'x,y' + '}'.repeat(64)));
  const leaf = { type: 'text', value: 'a' };
  assert.equal(braces.stringify({ type: 'root', nodes: [leaf, leaf] }), 'aa');
});

// Docusaurus pins older transitive ranges. These overrides replace the known
// vulnerable releases without downgrading Docusaurus or suppressing audits.
test('fixed transitive dependencies are installed', () => {
  const semver = require('semver');
  const { createRequire } = require('node:module');
  const fromCore = createRequire(require.resolve('@docusaurus/core/package.json'));
  const fromBundler = createRequire(fromCore.resolve('@docusaurus/bundler/package.json'));
  const fromCopy = createRequire(fromBundler.resolve('copy-webpack-plugin/package.json'));
  const fromSockjs = createRequire(require.resolve('sockjs/package.json'));
  for (const [resolveFrom, name, minimum] of [
    [fromCore, 'tinypool', '2.1.2'],
    [fromCopy, 'serialize-javascript', '7.0.5'],
    [fromSockjs, 'uuid', '11.1.1'],
  ]) {
    const installed = resolveFrom(`${name}/package.json`).version;
    assert.ok(semver.gte(installed, minimum), `${name} ${installed} must be >= ${minimum}`);
  }
});

test('every installed copy uses the fixed parser or patched braces', () => {
  const path = require('node:path');
  const root = path.resolve(__dirname, '..');
  const lock = require('../package-lock.json');
  const semver = require('semver');
  for (const [location, pkg] of Object.entries(lock.packages)) {
    if (location.endsWith('node_modules/postcss-selector-parser')) {
      assert.ok(semver.gte(pkg.version, '7.1.6'), `${location} must be fixed`);
    }
    if (location.endsWith('node_modules/braces')) {
      const installed = require(path.join(root, location));
      assert.throws(() => installed.compile('{'.repeat(4000) + 'x' + '}'.repeat(4000)), SyntaxError);
    }
  }
});
