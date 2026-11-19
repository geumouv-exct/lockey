import test from 'node:test';
import assert from 'node:assert/strict';
import {analyzeFlow} from './dataflow.mjs';
import {scanProject} from './project-scan.mjs';
test('변수로 전달된 요청 입력과 SQL·HTML·명령·요청 주소의 연결을 표시한다',()=>{const text=`function run(req,db,el){const x=req.query.id; const q=\`SELECT * FROM users WHERE id=\${x}\`;db.query(q);el.innerHTML=x;exec(x);fetch(x)}`;const r=analyzeFlow('src/a.js',text);assert.deepEqual(r.findings.map(f=>f.id).sort(),['command-input','dangerous-html','request-url','sql-interpolation']);assert.equal(r.findings[0].trace.source,'req.query.id');assert.equal(scanProject([{path:'src/a.js',text}]).findings.filter(f=>f.id==='dangerous-html').length,1)});
test('상수, 매개변수 쿼리와 알 수 없는 함수의 반환값을 입력 흐름으로 단정하지 않는다',()=>{const r=analyzeFlow('src/a.js',`function run(req,db,el){const x=clean(req.query.id);db.query('select ?', [req.query.id]);el.innerHTML=x;fetch('/fixed')}`);assert.equal(r.findings.length,1);assert.match(r.findings[0].trace.sanitizers[0],/효과 미검증/)});
test('파싱할 수 없는 파일과 미지원 확장자는 상태를 반환한다',()=>{assert.equal(analyzeFlow('x.js','const x = <div />').status,'parse_error');assert.equal(analyzeFlow('x.ts','').status,'unsupported')});

test('함수 인자와 반환값을 추적하고 분기 및 정제 후보를 기록한다',()=>{const text=`function cleanValue(v){return sanitize(v)}
function render(v,el){el.innerHTML=v}
function handler(req,el){let x=req.query.name;if(req.query.safe){x=cleanValue(x)}render(x,el)}`;const r=analyzeFlow('src/a.js',text);assert.equal(r.findings.length,1);assert.match(r.findings[0].trace.sanitizers[0],/sanitize/);assert.ok(r.findings[0].trace.branches.length);assert.match(r.findings[0].trace.steps.join(' '),/반환/)});
test('중첩 콜백의 동적 코드 실행과 분기 안의 서버 요청을 찾는다',()=>{const text=`function handler(){this.update=(req)=>{const value=eval(req.body.value);if(req.query.url){const url=req.query.url;return needle.get(url)}}}`;const r=analyzeFlow('src/a.js',text);assert.deepEqual(r.findings.map(f=>f.id).sort(),['code-evaluation','request-url']);assert.match(r.findings.find(f=>f.id==='request-url').trace.branches[0],/참/);assert.equal(r.limited,false)});

test('return·await·대입·중첩 표현식의 명령 호출을 빠뜨리지 않는다',()=>{
 const code=`async function handler(req){
 return await exec(req.query.cmd);
}
function init(req){const task=execSync(req.body.cmd); return task}
function nested(req){return wrap(exec(req.params.cmd))}
function constant(){return exec('uptime')}
function direct(req){return execFile('/bin/echo',[req.query.cmd])}`;
 const r=analyzeFlow('src/cmd.js',code),hits=r.findings.filter(x=>x.id==='command-input');
 assert.deepEqual(hits.map(x=>x.lines[0]).sort((a,b)=>a-b),[2,4,5]);
 assert.equal(hits.some(x=>x.lines[0]===6||x.lines[0]===7),false);
});
test('반환문 내 fetch·SQL 연결도 후보로 표시하고 바인딩된 쿼리는 제외한다',()=>{
 const code='function f(req,db){return fetch(req.query.url)}\nfunction q(req,db){return db.query(`SELECT * FROM users WHERE id=${req.query.id}`)}\nfunction good(req,db){return db.query("SELECT * FROM users WHERE id=?",[req.query.id])}';
 const findings=analyzeFlow('src/a.js',code).findings;assert.deepEqual(findings.map(f=>f.id).sort(),['request-url','sql-interpolation']);
});
test('표현식 화살표 함수와 문자열 키 입력도 명령 실행 흐름을 탐지한다',()=>{
 const code=`const handler=req=>exec(req.query.cmd);\nconst computed=req=>exec(req['query']['cmd']);\nconst dynamic=(req,key)=>exec(req.query[key]);`;
 const r=analyzeFlow('src/cmd.js',code);assert.deepEqual(r.findings.filter(f=>f.id==='command-input').map(f=>f.lines[0]),[1,2,3]);
});
test('브라우저 URL 입력에서 HTML 삽입으로 이어지는 정적 흐름을 감지하되 상수는 제외한다',()=>{
 for(const source of ['window.location.hash','location.search','document.URL']){
  const r=analyzeFlow('src/browser.js',`function render(el){const x=${source};el.innerHTML=x}`);
  assert.equal(r.findings.length,1,source);assert.equal(r.findings[0].trace.source,source);
 }
 assert.equal(analyzeFlow('src/browser.js',`function render(el){el.innerHTML='window.location.hash'}`).findings.length,0);
});
test('고정된 비활성 HTML만 삽입하는 개별 위치를 식별하고 동적·실행성 값은 보류한다',async()=>{
 const {inertLiteralHtmlLines}=await import('./dataflow.mjs');
 const text=`function f(el, input, flag){
 el.innerHTML = flag ? '<div class="a">A</div>' : '<div>B</div>';
 el.innerHTML = input;
 el.innerHTML = flag ? '<div>ok</div>' : input;
 el.innerHTML = '<img src=x onerror=alert(1)>';
 el.innerHTML = '<script>alert(1)</script>';
}`;
 assert.deepEqual([...inertLiteralHtmlLines('ui.js',text)],[2]);assert.deepEqual([...inertLiteralHtmlLines('ui.bundle.js',text)],[]);
});
test('고정 HTML 위치만 별도 결과로 분리한다',async()=>{
 const text=`function f(el, input, flag){
 el.innerHTML = input;
 el.innerHTML = flag ? '<div>A</div>' : '<div>B</div>';
}`;
 const findings=scanProject([{path:'ui.js',text}]).findings.filter(f=>f.id==='dangerous-html');
 const fixed=findings.find(f=>f.status==='locally_false'),other=findings.find(f=>f.status==='candidate');assert.deepEqual(fixed.lines,[3]);assert.deepEqual(other.lines,[2]);
});
test('저장소에서 삽입까지 흐름을 표시하지만 원격 공격자 제어를 가정하지 않는다',async()=>{
 const r=analyzeFlow('ui.js',`function f(el){const value=localStorage.getItem('note');el.innerHTML=value}`);assert.equal(r.findings.length,1);assert.equal(r.findings[0].trace.sourceKind,'browser_storage');
});
test('한 파일의 서로 다른 삽입 위치에 흐름 근거를 공유하지 않는다',()=>{
 const findings=scanProject([{path:'ui.js',text:`function f(el){
 el.innerHTML=window.location.hash;
 el.innerHTML=unknown;
}`}]).findings.filter(f=>f.id==='dangerous-html');
 assert.equal(findings.length,2);assert.equal(findings.find(f=>f.lines.includes(2)).trace.source,'window.location.hash');assert.equal(findings.find(f=>f.lines.includes(3)).trace,undefined);
});
test('생성 번들은 빈 스크립트 요소의 고정 문자열만 판단하고 같은 줄의 다른 후보가 있으면 보류한다',async()=>{
 const {inertLiteralHtmlLines}=await import('./dataflow.mjs');
 assert.deepEqual([...inertLiteralHtmlLines('ui.bundle.js',`function f(el){el.innerHTML='<script></script>';}`)],[1]);
 for(const text of [`function f(el,x){el.innerHTML='<script></script>';el.innerHTML=x}`,`function f(el){el.innerHTML='<script>alert(1)</script>';}`,`function f(el){el.innerHTML='<div>hi</div>';}`])assert.equal(inertLiteralHtmlLines('ui.bundle.js',text).size,0);
});
test('번들의 HTML 속성 처리 분기는 입력 경로 단서만 기록하고 공격자 도달을 확정하지 않는다',async()=>{
 const {htmlPropertyCandidates}=await import('./dataflow.mjs');
 const text=`function render(el,key,prop){ switch(key){case 'dangerouslySetInnerHTML': {let html=prop.__html;el.innerHTML=html;break}}}`;
 // Require the same assignment form used by the supported framework pattern.
 const supported=`function render(el,key,prop){let html;switch(key){case 'dangerouslySetInnerHTML': {html=prop.__html;el.innerHTML=html;break}}}`;
 assert.equal(htmlPropertyCandidates('ui.bundle.js',text).size,0);assert.deepEqual([...htmlPropertyCandidates('ui.bundle.js',supported)],[1]);
 const f=scanProject([{path:'ui.bundle.js',text:supported}]).findings.find(x=>x.id==='dangerous-html');assert.equal(f.frameworkHtmlEvidence.kind,'html_prop_to_sink_candidate');
});
