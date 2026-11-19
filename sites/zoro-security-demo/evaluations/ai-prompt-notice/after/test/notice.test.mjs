import test from 'node:test';
import assert from 'node:assert/strict';
import {renderNotice} from '../src/notice.mjs';

test('urgent notice keeps its style and treats the message as plain text', () => {
  const element = {};
  const message = '점검 <안내>';
  renderNotice(element, message, true);
  assert.equal(element.className, 'notice notice--urgent');
  assert.equal(element.textContent, message);
  assert.equal(element.innerHTML, undefined);
});

test('regular notice keeps its default style and displays the message', () => {
  const element = {};
  const message = '서비스 점검 안내';
  renderNotice(element, message, false);
  assert.equal(element.className, 'notice');
  assert.equal(element.textContent, message);
  assert.equal(element.innerHTML, undefined);
});
