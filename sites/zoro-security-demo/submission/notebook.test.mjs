import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { upcomingMeetings, personalNotes, postComment } from './fixtures/team-notes/notebook.js';
import { exportMinutes } from './fixtures/team-notes/minutes.js';
import { sessionCookie } from './fixtures/team-notes/session.js';

const book = JSON.parse(await readFile(new URL('./fixtures/team-notes/meetings.json', import.meta.url), 'utf8'));
const member = book.members.find(person => person.id === 'bom');
const exhibit = book.meetings.find(meeting => meeting.id === 'exhibit');

test('설치 회의 당일에는 그날 회의와 다음 인수인계만 일정에 나온다', () => {
  assert.deepEqual(upcomingMeetings(book, '2026-11-21').map(meeting => meeting.id), ['exhibit', 'handover']);
});

test('봄이 교정 완료 댓글을 남겨도 달의 기존 댓글은 남는다', () => {
  const meeting = structuredClone(exhibit);
  postComment(meeting, member, '  작품 설명 카드 교정 끝났어요.  ');
  assert.deepEqual(meeting.comments, [...exhibit.comments, { authorId: 'bom', text: '작품 설명 카드 교정 끝났어요.' }]);
});

test('같은 회의의 개인 메모는 작성자별로 구분된다', () => {
  assert.deepEqual(personalNotes(book, member, 'exhibit').map(note => note.text), ['설명 카드 여분도 인쇄소에 부탁할 것.']);
  assert.deepEqual(personalNotes(book, member, 'walk'), []);
});

test('공유하는 회의록에는 안건의 진행 상태와 담당자가 남는다', () => {
  const minutes = exportMinutes(exhibit);
  assert.ok(minutes.includes('[완료] 대여할 액자 수량 확정 · 달'));
  assert.ok(minutes.includes('[예정] 작품 설명 카드 교정 · 봄'));
  assert.ok(!minutes.includes('인쇄소'));
});

test('운영진 세션은 같은 사이트에서 여덟 시간 동안 사용하도록 설정된다', () => {
  assert.equal(sessionCookie.maxAge, 28800);
  assert.equal(sessionCookie.path, '/');
  assert.equal(sessionCookie.sameSite, 'Lax');
});
