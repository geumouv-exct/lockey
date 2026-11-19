import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import { chromium } from 'playwright-core';
import { createSecurityNews } from '../security-news.mjs';
import { newsAssessmentPrompt } from '../project-news.mjs';

const base = process.env.LOCKEY_URL || 'http://127.0.0.1:4768';
const fixtures = new URL('./fixtures/', import.meta.url);

async function sources(project) {
  const dir = new URL(project + '/', fixtures);
  const names = await readdir(dir);
  return Promise.all(names.map(async path => ({ path, text: await readFile(new URL(path, dir), 'utf8') })));
}

async function api(endpoint, input) {
  const response = await fetch(new URL('/api/' + endpoint, base), {
    method: 'POST', headers: { Origin: new URL(base).origin, 'Content-Type': 'application/json' },
    body: JSON.stringify(input), signal: AbortSignal.timeout(180000)
  });
  const result = await response.json();
  assert.ok(response.ok, result.error || response.statusText);
  return result;
}

async function teamNotes() {
  const files = await sources('team-notes');
  const browser = await chromium.launch({ channel: process.env.CHROME_CHANNEL || 'chrome' });
  try {
    const page = await browser.newPage();
    page.setDefaultTimeout(180000);
    // Give the picker a real, writable directory in this disposable browser profile.
    await page.addInitScript(files => {
      window.showDirectoryPicker = async () => {
        const dir = await (await navigator.storage.getDirectory()).getDirectoryHandle('team-notes', { create: true });
        for (const { path, text } of files) {
          const handle = await dir.getFileHandle(path, { create: true });
          const stream = await handle.createWritable();
          await stream.write(text);
          await stream.close();
        }
        return dir;
      };
    }, files);
    await page.goto(base);
    await page.locator('#model-gate[data-connection="connected"]').waitFor();
    await page.locator('#gate-continue').click();
    for (const key of ['login', 'private', 'input']) {
      await page.locator('label:has(input[name="survey-' + key + '"][value="yes"])').click();
    }
    await page.locator('#survey-next').click();
    for (const [i, detail] of ['password', 'owner', 'text'].entries()) {
      await page.locator('#detail-questions select:enabled').nth(i).selectOption(detail);
    }
    await page.locator('#details-next').click();
    await page.locator('label:has(input[value="folder"])').click();
    await page.locator('.folder-select').click();
    await page.locator('#folder-name').filter({ hasText: 'team-notes' }).waitFor();
    await page.locator('label:has(input[value="folder"]) .target-badge').waitFor();
    console.log('설문: 예 / 예 / 예 · 비밀번호 로그인 / 작성자 본인 / 글이나 댓글 → Zoro-1 로컬 폴더 추천');
    const scan = () => page.waitForResponse(r => r.url() === new URL('/api/project-scan', base).href);
    const [before] = await Promise.all([scan(), page.locator('#wizard-next').click()]);
    const initial = await before.json();
    assert.deepEqual(initial.findings.map(f => f.id).sort(), ['sql-interpolation', 'tls-disabled']);
    console.log('점검 결과', initial.findings.map(f => f.path + ' · ' + f.id).join(', '));
    for (const [cwe, file] of [['CWE-89', 'exhibition-calendar.js'], ['CWE-295', 'gallery-delivery.js']]) {
      const slot = page.locator('#issue-list [data-issue-news="' + cwe + '"]');
      const link = slot.getByRole('link');
      await link.waitFor();
      assert.equal(await link.count(), 1);
      const url = await link.getAttribute('href');
      assert.equal(new URL(url).protocol, 'https:');
      console.log(cwe, '대표 뉴스:', await link.innerText(), url);
      await slot.locator('xpath=ancestor::article[1]').getByRole('button', { name: '코드 비교' }).click();
      await page.locator('[data-viewer-file]').filter({ hasText: file }).waitFor();
      console.log('코드 비교:', file);
      await page.locator('.code-viewer-close').click();
    }
    await page.locator('#to-prompt-page').click();
    await page.locator('.prompt-local').click();
    const dialog = page.locator('#local-repair-window');
    await dialog.locator('[data-generate]').click();
    await page.waitForFunction(() => !document.querySelector('#local-repair-window [data-save]').disabled ||
      document.querySelector('#local-repair-window [data-generate]').textContent.includes('남은'));
    assert.equal(await dialog.locator('[data-save]').isEnabled(), true, await dialog.locator('[data-status]').innerText());
    const paths = await dialog.locator('.ai-repair h3').allTextContents();
    assert.deepEqual(paths.sort(), ['exhibition-calendar.js', 'gallery-delivery.js']);
    console.log('Zoro-1 수정안 생성', paths.join(', '));
    const [after] = await Promise.all([scan(), dialog.locator('[data-save]').click()]);
    assert.equal((await after.json()).findings.length, 0);
    await page.locator('#complete-page').waitFor();
    const changed = await page.evaluate(async files => {
      const dir = await (await navigator.storage.getDirectory()).getDirectoryHandle('team-notes');
      const changed = [];
      for (const file of files) {
        const handle = await dir.getFileHandle(file.path);
        if (await (await handle.getFile()).text() !== file.text) changed.push(file.path);
      }
      return changed.sort();
    }, files);
    assert.deepEqual(changed, paths);
    console.log('브라우저 격리 폴더에 한 번 승인하여 저장한 파일', changed.join(', '));
    console.log('재점검 0건 · 수정 완료 화면 확인');
  } finally {
    await browser.close();
  }
}

async function gardenJournal() {
  const files = await sources('garden-journal');
  const serviceProfile = {
    login: { answer: 'yes', detail: 'password' },
    private: { answer: 'yes', detail: 'owner' },
    input: { answer: 'yes', detail: 'text' }
  };
  console.log('두 단계에서 같은 설문 사용 · 비밀번호 로그인 / 본인 당번표 / 작업 기록 작성');

  const partialFiles = files.filter(file => file.path === 'journal.js');
  assert.equal(partialFiles.length, 1);
  const partial = await api('target-recommendation', { files: partialFiles, serviceProfile });
  assert.equal(partial.readableFiles, 1);
  assert.deepEqual(partial.checks.map(check => check.status), ['unconfirmed', 'unconfirmed', 'unconfirmed']);
  assert.ok(partial.checks.every(check => check.observations.length === 0));
  console.log('① 작업 수첩 스크립트만 제공 · journal.js · 설문 기능 3개 모두 미확인');
  console.log('Zoro-1 실제 응답:', partial.status, partial.choice ?? '');
  assert.equal(partial.status, 'deferred', '근거 부족 단계에서 모델이 추천을 보류해야 함');

  const full = await api('target-recommendation', { files, serviceProfile });
  console.log('② 전체 프로젝트 제공 ·', files.map(file => file.path).join(', '));
  for (const [feature, signal, path] of [
    ['login', 'password', 'index.html'], ['private', 'owner', 'member-desk.mjs'], ['input', 'text', 'index.html']
  ]) {
    const check = full.checks.find(check => check.feature === feature);
    assert.equal(check?.status, 'matched');
    const observation = check.observations.find(o => o.source === 'source' && o.signal === signal && o.path === path);
    assert.ok(observation?.line > 0, feature + '의 실제 파일과 행 번호 필요');
    console.log(check.status, '·', observation.label, '·', path + ':' + observation.line);
  }
  console.log('Zoro-1 실제 응답:', full.status, full.choice ?? '');
  assert.equal(full.status, 'recommended');
  assert.equal(full.choice, 'folder', '전체 소스 근거를 바탕으로 로컬 폴더 점검을 추천해야 함');
  const scan = await api('project-scan', { projectName: 'garden-journal', snapshot: files, files: files.map(({ path }) => ({ path })), serviceProfile });
  assert.equal(scan.scan.files, files.length);
  assert.equal(scan.findings.length, 0);
  console.log('추천된 로컬 폴더 점검 실행 · 소스', scan.scan.files, '개 · 정적 발견', scan.findings.length, '건');
}

// Replay only the two saved publisher feeds. All model calls go to the configured Zoro-1.
function archiveFetch(articles, model) {
  return async (url, options) => {
    const address = new URL(url);
    if (address.origin === new URL(model).origin && address.pathname === '/v1/chat/completions') return fetch(url, options);
    if (address.hostname === 'raw.githubusercontent.com') return new Response(null, { status: 503 });
    if (address.hostname === 'thehackernews.com') {
      const rows = articles.filter(a => a.source === 'The Hacker News');
      return Response.json({ feed: { openSearch$totalResults: { $t: rows.length }, entry: rows.map(a => ({
        title: { $t: a.title }, summary: { $t: a.summary }, published: { $t: a.published }, link: [{ rel: 'alternate', href: a.url }]
      })) } });
    }
    assert.equal(address.hostname, 'www.bleepingcomputer.com');
    const xml = articles.filter(a => a.source === 'BleepingComputer').map(a =>
      '<item><title><![CDATA[' + a.title + ']]></title><link>' + a.url + '</link><description><![CDATA[' +
      a.summary + ']]></description><pubDate>' + a.published + '</pubDate></item>').join('');
    return new Response('<rss version="2.0"><channel>' + xml + '</channel></rss>');
  };
}

async function cornerBooks() {
  const files = await sources('corner-books');
  const manifest = JSON.parse(files.find(f => f.path === 'composer.json').text);
  const feature = JSON.parse(files.find(f => f.path === 'shelf.json').text);
  assert.equal(feature.shelves.length, 3);
  assert.ok(files.some(f => f.path === 'index.php' && f.text.includes('shelf.json')));
  console.log('골목책방 · 추천 도서', feature.shelves.length, '권 · 낭독회', feature.reading.date);
  console.log('검색 근거 composer.json · PHP 요구 범위', manifest.require.php, '· 운영 서버 패치 버전은 자료에 없음');
  const archive = JSON.parse(await readFile(new URL('news.json', fixtures), 'utf8'));
  const model = process.env.ZORO_DECIDE_URL || 'http://127.0.0.1:30001/v1/systemone';
  const news = createSecurityNews({
    url: model, expectedRevision: process.env.ZORO_EXPECTED_REVISION || 'bf1b76b9b4df03b05fcbb73444e1cd4db0f566da',
    fetcher: archiveFetch(archive.articles, model), now: () => new Date(archive.asOf)
  });
  const query = { scope: 'all', keyword: 'PHP', startDate: '2026-11-14', endDate: '2026-11-20' };
  const result = await news(query);
  assert.equal(result.modelStatus, 'completed');
  assert.equal(result.items.length, 1);
  const [item] = result.items;
  assert.equal(item.sources.length, 2);
  console.log('보관 기사 기준일', archive.asOf, '· PHP 검색 · 보도', item.sources.length, '건 → 이슈', result.items.length, '건');
  console.log('Zoro-1 헤드라인', item.explanation.headline);
  console.log('내가 확인할 것', item.explanation.check);
  const prompt = newsAssessmentPrompt(item);
  for (const article of archive.articles) assert.ok(prompt.includes(article.url));
  console.log('선택 기사 점검 프롬프트\n' + prompt);
  const previousWeek = await news({ ...query, startDate: '2026-11-07', endDate: '2026-11-13' });
  assert.equal(previousWeek.total, 0);
  console.log('같은 검색어로 직전 주 조회 · 0건');
}

const scenarios = new Map([['team-notes', teamNotes], ['garden-journal', gardenJournal], ['corner-books', cornerBooks]]);
const name = process.argv[2];
if (!scenarios.has(name)) throw Error('시나리오를 선택하세요: ' + [...scenarios.keys()].join(', '));
console.log('START', new Date().toISOString(), name);
await scenarios.get(name)();
console.log('PASS', new Date().toISOString(), name);
