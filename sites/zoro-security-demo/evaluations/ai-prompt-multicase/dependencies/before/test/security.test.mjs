import test from 'node:test';import assert from 'node:assert/strict';import {pages} from '../src/app.mjs';
test('paging retains existing behavior',()=>{assert.deepEqual(pages([1,2,3]),[[1,2],[3]])});
