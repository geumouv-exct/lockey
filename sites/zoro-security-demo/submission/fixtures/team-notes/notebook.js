export function personalNotes(book, user, meetingId) {
  return book.personalNotes.filter(note => note.ownerId === user.id && note.meetingId === meetingId);
}

export function postComment(meeting, user, text) {
  const comment = text.trim();
  if (!comment) throw new Error('댓글 내용을 입력해 주세요.');
  meeting.comments.push({ authorId: user.id, text: comment });
}

export function upcomingMeetings(book, fromDate) {
  return book.meetings.filter(meeting => meeting.date >= fromDate)
    .sort((first, second) => first.date.localeCompare(second.date));
}
