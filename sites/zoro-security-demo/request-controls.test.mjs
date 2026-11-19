import test from 'node:test';import assert from 'node:assert/strict';import {readFile} from 'node:fs/promises';import {scanProject} from './project-scan.mjs';
const scan=text=>scanProject([{path:'src/request.mjs',text}]).findings.find(f=>f.id==='request-url');
test('실제 수정 전후는 안전 판정 없이 보호 구문 관찰 여부를 구분한다',async()=>{
 const base=new URL('./evaluations/ai-prompt-multicase/runtime/',import.meta.url);
 const before=scan(await readFile(new URL('before/src/request.mjs',base),'utf8')),after=scan(await readFile(new URL('after/src/request.mjs',base),'utf8'));
 assert.equal(before.trace.requestReview.status,'unverified');assert.deepEqual(before.trace.requestReview.observations,[]);
 const review=after.trace.requestReview;assert.equal(review.status,'observed_unverified');
 for(const kind of ['origin_condition','protocol_condition','credentials_condition','redirect_option','proxy_option','env_proxy_option','tls_option','agent_option'])assert.ok(review.observations.some(x=>x.kind===kind),kind);
 assert.match(review.note,/안전성 증명이 아닙니다/);assert.ok(review.missing.some(x=>x.includes('DNS')));
});
test('가짜 검증과 덮어쓰기가 안전 판정이나 리다이렉트 검증으로 바뀌지 않는다',()=>{
 const fake=`function x(req,needle){const url=new URL(req.query.url); if(false && url.origin!=="https://a.test") throw Error(); return needle.get(url.href,{follow_max:0,...req.query.opts})}`;
 const result=scan(fake).trace.requestReview;assert.notEqual(result.status,'safe');assert.equal(result.observations.some(o=>o.kind==='redirect_option'),false);assert.ok(result.missing.length);
 const plain=scan('function x(req,needle){return needle.get(req.query.url)}').trace.requestReview;assert.equal(plain.status,'unverified');
});
test('동일 행 호출이나 가변 옵션은 확정하지 않는다',()=>{
 const r=scan('function x(req,needle){needle.get(req.query.a);return needle.get(req.query.b)}').trace.requestReview;
 assert.equal(r.status,'unverified');assert.deepEqual(r.observations,[]);
});
test('대량의 서버 요청 구문은 검토 한도를 명시하고 안전 판정을 보류한다',()=>{
 const code=Array.from({length:51},(_,i)=>`function f${i}(req,needle){return needle.get(req.query.u)}`).join('\n');
 const r=scanProject([{path:'src/request.mjs',text:code}]);const items=r.findings.filter(f=>f.id==='request-url');assert.equal(items.length,51);assert.equal(r.flowCoverage.limited,1);assert.match(items.at(-1).trace.requestReview.note,/한도/);assert.equal(items.at(-1).trace.requestReview.status,'unverified');
});
