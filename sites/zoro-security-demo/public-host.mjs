import { AsyncLocalStorage } from 'node:async_hooks';
import { randomBytes } from 'node:crypto';

const owner = new AsyncLocalStorage();
const minute = 60_000;
const lifetime = 30 * minute;
const cookieName = '__Host-lockey';

export function publicHost(address, now = Date.now) {
  const url = new URL(address);
  if (url.origin !== address || url.protocol !== 'https:') throw Error('PUBLIC_ORIGIN에는 HTTPS 출처만 지정하세요.');
  const sessions = new Map();
  let nextCleanup = 0;
  let globalWindow = 0;
  let total = 0;
  let active = 0;

  return function check(req, res, pathname) {
    if (req.headers.host !== url.host) return 403;
    const time = now();
    if (time >= nextCleanup) {
      for (const [key, session] of sessions) {
        if (session.expires <= time && !session.active) sessions.delete(key);
      }
      nextCleanup = time + minute;
    }
    const key = req.headers.cookie?.split(';').map(c => c.trim()).find(c => c.startsWith(cookieName + '='))?.slice(cookieName.length + 1);
    let session = sessions.get(key);
    if (session?.expires <= time) session = undefined;
    if (req.method === 'GET' && pathname === '/') {
      if (!session) {
        if (sessions.size >= 4096) return 429;
        const id = randomBytes(24).toString('hex');
        sessions.set(id, { expires: time + lifetime, window: time, used: 0, active: 0, modelStart: time, modelCalls: 0 });
        res.setHeader('Set-Cookie', cookieName + '=' + id + '; Path=/; HttpOnly; Secure; SameSite=Strict');
      }
      return 0;
    }
    if (req.method !== 'POST') return 0;
    if (req.headers.origin !== address || !session) return 403;
    if (pathname === '/api/project-test') return 403;
    if (time >= globalWindow + minute) { globalWindow = time; total = 0; }
    if (time >= session.window + minute) { session.window = time; session.used = 0; }
    if (session.used >= 40 || session.active >= 5 || total >= 160 || active >= 12) return 429;
    session.expires = time + lifetime;
    owner.enterWith(session);
    session.used++;
    session.active++;
    total++;
    active++;
    const release = () => {
      res.off('finish', release);
      res.off('close', release);
      session.active--;
      active--;
    };
    res.once('finish', release);
    res.once('close', release);
    return 0;
  };
}

// Keep the GPU slot until the complete, non-streaming model response has arrived.
export function limitedModelFetch(modelAddress, transport = fetch) {
  const origin = new URL(modelAddress).origin;
  let active = 0;
  const queue = [];
  return async (url, options) => {
    if (new URL(url).origin !== origin) return transport(url, options);
    const session = owner.getStore();
    if (session) {
      const time = Date.now();
      if (time >= session.modelStart + 60 * minute) { session.modelStart = time; session.modelCalls = 0; }
      if (session.modelCalls >= 240) throw Error('이 브라우저의 시간당 모델 요청 한도에 도달했습니다.');
      session.modelCalls++;
    }
    if (active >= 2) {
      if (queue.length >= 20) throw Error('모델 요청이 많습니다. 잠시 후 다시 시도해 주세요.');
      await new Promise((resolve, reject) => {
        const signal = options?.signal;
        signal?.throwIfAborted();
        const grant = () => { signal?.removeEventListener('abort', abort); resolve(); };
        const abort = () => {
          queue.splice(queue.indexOf(grant), 1);
          reject(signal.reason);
        };
        queue.push(grant);
        signal?.addEventListener('abort', abort, { once: true });
      });
    } else active++;
    try {
      const response = await transport(url, options);
      const body = await response.arrayBuffer();
      return new Response(body, { status: response.status, headers: response.headers });
    } finally {
      const next = queue.shift();
      if (next) next();
      else active--;
    }
  };
}
