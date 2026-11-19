import { createServer } from 'node:http';
import { createHash, timingSafeEqual } from 'node:crypto';
import { readFile } from 'node:fs/promises';

const members = new Map([
  ['mina', { id: 'mina', password: process.env.GARDEN_MINA_PASSWORD }],
  ['jisu', { id: 'jisu', password: process.env.GARDEN_JISU_PASSWORD }]
]);
const assignments = [
  { ownerId: 'mina', task: '금요일 오전 · 온실 모종 물주기' },
  { ownerId: 'jisu', task: '토요일 오후 · 허브 화단 당번' }
];
const digest = value => createHash('sha256').update(value).digest();

createServer(async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  const page = { '/': ['index.html', 'text/html'], '/journal.js': ['journal.js', 'text/javascript'] };
  if (req.method === 'GET' && Object.hasOwn(page, req.url)) {
    const [name, type] = page[req.url];
    res.setHeader('Content-Type', type + '; charset=utf-8');
    res.end(await readFile(new URL(name, import.meta.url)));
    return;
  }
  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  if (req.method !== 'POST' || req.url !== '/assignments') {
    res.writeHead(404).end();
    return;
  }
  const chunks = [];
  let bytes = 0;
  for await (const chunk of req) {
    bytes += chunk.length;
    if (bytes > 4096) { res.writeHead(413).end(); return; }
    chunks.push(chunk);
  }
  const form = new URLSearchParams(Buffer.concat(chunks).toString());
  const user = members.get(form.get('member'));
  if (!user?.password || !timingSafeEqual(digest(user.password), digest(form.get('password') || ''))) {
    res.writeHead(401).end('회원 이름과 비밀번호를 확인해 주세요.');
    return;
  }
  const mine = assignments.filter(entry => entry.ownerId === user.id);
  res.end(mine.map(entry => entry.task).join('\n'));
}).listen(Number(process.env.GARDEN_PORT || 4781), '127.0.0.1');
