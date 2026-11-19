import test from 'node:test';
import assert from 'node:assert/strict';
import { configuredPassword } from '../src/credentials.mjs';

test('credential is supplied by server environment', (t) => {
  const previous = process.env.TRACE_DEMO_PASSWORD;
  t.after(() => {
    if (previous === undefined) delete process.env.TRACE_DEMO_PASSWORD;
    else process.env.TRACE_DEMO_PASSWORD = previous;
  });

  process.env.TRACE_DEMO_PASSWORD = 'injected-test-value';
  assert.equal(configuredPassword(), 'injected-test-value');

  process.env.TRACE_DEMO_PASSWORD = ' replacement-test-value ';
  assert.equal(configuredPassword(), ' replacement-test-value ');

  delete process.env.TRACE_DEMO_PASSWORD;
  assert.throws(() => configuredPassword(), {
    message: 'TRACE_DEMO_PASSWORD must be set',
  });

  process.env.TRACE_DEMO_PASSWORD = '';
  assert.throws(() => configuredPassword(), {
    message: 'TRACE_DEMO_PASSWORD must be set',
  });
});
