import assert from 'node:assert/strict';
import test from 'node:test';
import lodash from 'lodash';
import template from 'lodash/template.js';
import { pages } from '../src/app.mjs';

test('paging retains existing behavior', () => {
  assert.deepEqual(pages([1, 2, 3]), [[1, 2], [3]]);
  assert.deepEqual(pages([1, 2, 3, 4]), [[1, 2], [3, 4]]);
  assert.deepEqual(pages([]), []);
});

for (const [entryPoint, compile] of Object.entries({
  'lodash.template': lodash.template,
  'lodash/template.js': template,
})) {
  test(`${entryPoint} accepts own imports and ignores inherited imports`, () => {
    const imports = Object.assign(Object.create({ inheritedLabel: 'parent' }), {
      format: (value) => value.toUpperCase(),
    });
    const render = compile('<%= format(name) %> <%= typeof inheritedLabel %>', { imports });

    assert.equal(render({ name: 'Ada' }), 'ADA undefined');
  });

  test(`${entryPoint} rejects whitespace in an import name`, () => {
    assert.throws(
      () => compile('Hello', { imports: { ' label ': 'Ada' } }),
      /Invalid `imports` option/,
    );
  });
}
