import test from 'node:test';import assert from 'node:assert/strict';import {canRead} from '../src/access.mjs';
test('owner allowed and other user denied',()=>{assert.equal(canRead(()=>true),true);assert.equal(canRead(()=>false),false)});
test('authorization service errors deny access', () => {
  const checkOwner = () => {
    throw new Error('backend unavailable');
  };

  assert.equal(canRead(checkOwner), false);
});
