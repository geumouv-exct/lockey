import test from 'node:test';
import assert from 'node:assert/strict';
import { findUser } from '../src/service.mjs';

const expectedSql = 'SELECT * FROM users WHERE name = ?';

test('binds a normal name and returns the database result unchanged', async () => {
  const rows = [{ id: 1, name: 'Alice' }];
  const queryResult = Promise.resolve(rows);
  const calls = [];
  const db = {
    query(...args) {
      calls.push(args);
      return queryResult;
    },
  };

  const result = findUser(db, { query: { name: 'Alice' } });

  assert.deepEqual(calls, [[expectedSql, ['Alice']]]);
  assert.strictEqual(result, queryResult);
  assert.strictEqual(await result, rows);
});

test('passes a name containing an apostrophe as a separate value', () => {
  const calls = [];
  const db = {
    query(...args) {
      calls.push(args);
      return [];
    },
  };
  const name = "O'Reilly";

  findUser(db, { query: { name } });

  assert.deepEqual(calls, [[expectedSql, [name]]]);
});
