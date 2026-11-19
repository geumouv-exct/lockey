import test from 'node:test';
import assert from 'node:assert/strict';
import dns from 'node:dns';
import { parseValue } from '../src/parser.mjs';
import { runCommand } from '../src/command.mjs';
import { loadData } from '../src/request.mjs';

test('decimal input parses and code-shaped input is rejected', () => {
  const parse = value => parseValue({ body: { value } });

  for (const [input, expected] of [['12', 12], [' -1.25e2 ', -125], [0.5, 0.5]]) {
    assert.equal(parse(input), expected);
  }
  for (const input of ['', '1 + 2', 'Math.round(1)', '12px', null, [], {}]) {
    assert.throws(() => parse(input), TypeError);
  }
  assert.equal(parse('9007199254740991'), Number.MAX_SAFE_INTEGER);
  for (const input of ['9007199254740992', '-9007199254740992', '1e309', NaN, Infinity]) {
    assert.throws(() => parse(input), RangeError);
  }
});

test('status invokes the fixed executable with no arguments and the shell disabled', () => {
  const calls = [];
  const shell = () => assert.fail('shell was used');
  const direct = (...args) => {
    calls.push(args);
    return 'ok';
  };

  assert.equal(runCommand({ query: { cmd: 'status' } }, shell, direct), 'ok');
  assert.deepEqual(calls, [['/usr/bin/uptime', [], { shell: false }]]);
});

test('inputs outside the command allowlist are rejected before execution', () => {
  const execute = () => assert.fail('process execution was attempted');

  for (const cmd of ['status;', 'status|', 'status&', 'status\n', 'status extra', '', ['status'], null, undefined]) {
    assert.throws(() => runCommand({ query: { cmd } }, execute, execute), TypeError);
  }
  assert.throws(() => runCommand({}, execute, execute), TypeError);
});

test('only the configured HTTPS API origin is requested', () => {
  const calls = [];
  const client = { get(url) { calls.push(url); return url; } };
  const load = url => loadData({ query: { url } }, client);

  const allowed = 'https://api.example.test/v1?q=1';
  assert.equal(load(allowed), allowed);

  for (const url of [
    'http://api.example.test/v1',
    'https://127.0.0.1/private',
    'https://[::1]/private',
    'https://untrusted.example/v1',
    'https://api.example.test:444/v1',
    'https://user@api.example.test/v1',
    '/v1',
    [allowed],
  ]) {
    assert.throws(() => load(url), TypeError);
  }
  assert.deepEqual(calls, [allowed]);
});

test('requests disable redirect following and proxy configuration', () => {
  const client = {
    get(url, options) {
      assert.equal(options.follow_max, 0);
      assert.equal(options.proxy, null);
      assert.equal(options.use_proxy_from_env_var, false);
      assert.equal(options.rejectUnauthorized, true);
    },
  };
  loadData({ query: { url: 'https://api.example.test/v1' } }, client);
});

test('connection lookup supplies only allowed IPv4 and IPv6 addresses', async t => {
  const publicAddresses = [
    { address: '8.8.8.8', family: 4 },
    { address: '2606:4700::1111', family: 6 },
  ];
  const internalAddresses = [
    { address: '127.0.0.1', family: 4 },
    { address: '10.0.0.1', family: 4 },
    { address: '169.254.169.254', family: 4 },
    { address: '::1', family: 6 },
    { address: 'fd00::1', family: 6 },
    { address: '::ffff:127.0.0.1', family: 6 },
  ];
  let answers = [...internalAddresses, ...publicAddresses];
  t.mock.method(dns, 'lookup', (hostname, options, callback) => {
    assert.equal(hostname, 'api.example.test');
    assert.equal(options.all, true);
    callback(null, answers);
  });

  const agent = loadData({ query: { url: 'https://api.example.test/v1' } }, {
    get: (_url, options) => options.agent,
  });
  function resolve(options) {
    return new Promise((resolve, reject) => {
      agent.options.lookup('api.example.test', options, (error, ...result) => {
        if (error) reject(error);
        else resolve(result);
      });
    });
  }

  assert.deepEqual(await resolve({ all: true }), [publicAddresses]);
  assert.deepEqual(await resolve({ all: false }), ['8.8.8.8', 4]);
  answers = internalAddresses;
  await assert.rejects(resolve({ all: true }), /No allowed destination IP/);
});
