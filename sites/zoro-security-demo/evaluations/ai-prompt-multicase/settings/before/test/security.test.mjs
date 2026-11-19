import test from 'node:test';import assert from 'node:assert/strict';import {config} from '../src/config.mjs';
test('production security controls are enabled',()=>{assert.equal(config.debug,false);assert.equal(config.origin,'https://app.example.test');assert.equal(config.rejectUnauthorized,true);assert.equal(config.verifySignature,true)});
