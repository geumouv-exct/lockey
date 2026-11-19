import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import test from 'node:test';

const configUrl = new URL('../src/config.mjs', import.meta.url).href;

function loadConfig(nodeEnv, debug) {
  const env = { ...process.env };
  delete env.NODE_ENV;
  delete env.DEBUG;
  if (nodeEnv !== undefined) env.NODE_ENV = nodeEnv;
  if (debug !== undefined) env.DEBUG = debug;

  const output = execFileSync(process.execPath, [
    '--input-type=module',
    '--eval',
    `import { config } from ${JSON.stringify(configUrl)}; console.log(JSON.stringify(config));`,
  ], { env, encoding: 'utf8' });

  return JSON.parse(output);
}

test('production security controls are enabled even when DEBUG is true', () => {
  const config = loadConfig('production', 'true');

  assert.equal(config.debug, false);
  assert.equal(config.origin, 'https://app.example.test');
  assert.equal(config.rejectUnauthorized, true);
  assert.equal(config.verifySignature, true);
});

test('debug stays disabled when NODE_ENV is unset', () => {
  assert.equal(loadConfig(undefined, 'true').debug, false);
});

test('development requires DEBUG=true to enable debug', () => {
  assert.equal(loadConfig('development').debug, false);
  assert.equal(loadConfig('development', 'false').debug, false);
  assert.equal(loadConfig('development', 'true').debug, true);
});
