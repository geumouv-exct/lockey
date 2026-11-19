import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';
import { personalNotes, postComment, upcomingMeetings } from './notebook.js';
import { exportMinutes } from './minutes.js';

const book = JSON.parse(await readFile(new URL('./meetings.json', import.meta.url)));
test('회의 수첩은 본인 메모만 표시한다', () => {
  const note = book.personalNotes[0];
  assert.ok(personalNotes(book, { id: note.ownerId }, note.meetingId).includes(note));
  assert.deepEqual(personalNotes(book, { id: 'guest' }, note.meetingId), []);
});
test('전시 회의를 찾고 댓글과 회의록을 작성한다', () => {
  const [meeting] = upcomingMeetings(book, '2026-11-21');
  postComment(meeting, { id: 'dal' }, '  설치 일정 확인  ');
  assert.equal(meeting.comments.at(-1).text, '설치 일정 확인');
  assert.ok(exportMinutes(meeting).includes(meeting.title));
});
