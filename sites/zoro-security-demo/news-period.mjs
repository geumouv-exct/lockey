// KEV dateAdded is a calendar date. Match the Korean UI's calendar, including leap days.
export function pastMonths(now, months) {
  const koreaDate = new Intl.DateTimeFormat('sv-SE', {timeZone:'Asia/Seoul',year:'numeric',month:'2-digit',day:'2-digit'}).format(now);
  const [year, month, day] = koreaDate.split('-').map(Number);
  const startMonth = month - 1 - months;
  const lastDay = new Date(Date.UTC(year, startMonth + 1, 0)).getUTCDate();
  const start = new Date(Date.UTC(year, startMonth, Math.min(day,lastDay))).toISOString().slice(0,10);
  return {start, end:koreaDate};
}

export function newsPresets(now) {
  const year = pastMonths(now, 12);
  const weekStart = new Date(year.end + 'T00:00:00Z');
  weekStart.setUTCDate(weekStart.getUTCDate() - 6);
  return {
    week: {start:weekStart.toISOString().slice(0,10), end:year.end},
    month: pastMonths(now, 1),
    quarter: pastMonths(now, 3),
    year
  };
}
