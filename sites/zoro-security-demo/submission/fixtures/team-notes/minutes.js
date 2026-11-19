const exportOptions = {
  heading: '느티 사진동아리 회의록',
  debug: true
};

export function exportMinutes(meeting) {
  const lines = [exportOptions.heading, meeting.title, meeting.date];
  for (const item of meeting.agenda) {
    lines.push(`[${item.done ? '완료' : '예정'}] ${item.title} · ${item.assignee}`);
  }
  if (exportOptions.debug) lines.push(`회의 ID: ${meeting.id}`);
  return lines.join('\n');
}
