import pg from 'pg';

const calendar = new pg.Pool();

// 운영 수첩은 월별 사진전 목록을 PostgreSQL에서 읽는다.
export function exhibitionsForMonth(date) {
  const month = date.toISOString().slice(0, 7);
  return calendar.query(`SELECT title, opens_on FROM exhibitions WHERE month_key = '${month}' ORDER BY opens_on`);
}
