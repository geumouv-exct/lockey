import test from 'node:test';
import assert from 'node:assert/strict';
import {registerProposal,applyProposal,testApplied,validateSnapshot} from './project-actions.mjs';
import {reviewProject} from './project-review.mjs';
import {scanProject} from './project-scan.mjs';
const source={path:'src/render.mjs',text:'export function render(el,s){el.innerHTML=s}\n'};
const testFile={path:'test/render.test.mjs',text:`
import test from 'node:test';
import assert from 'node:assert/strict';
import {render} from '../src/render.mjs';
import {existsSync} from 'node:fs';
test('input renders as text',()=>{ const el={};render(el,'hello');assert.equal(el.textContent,'hello') });
test('isolated workspace',()=>{assert.equal(process.env.TRACE_TEST_SENTINEL,undefined);assert.equal(existsSync('/var/run/docker.sock'),false);assert.equal(process.getuid(),65534)});
`};
function proposal(extra=[]){
 const review=reviewProject([source],scanProject([source]).findings,'review_html');
 return registerProposal(review,[source,...extra],'demo');
}
test('each proposal stays in its snapshot and exports a reviewable patch',()=>{
 const a=proposal(),b=proposal();assert.match(applyProposal(a).patch,/^\+export.*textContent/m);
 assert.throws(()=>applyProposal(a),/이미 적용/);assert.ok(applyProposal(b).sha256);
 assert.match(source.text,/innerHTML/);
 assert.throws(()=>validateSnapshot([{path:'../test/a.test.js',text:''}]));
});
test('isolated named regression fails first and then passes',async()=>{
 process.env.TRACE_TEST_SENTINEL='fixture';
 const token=proposal([testFile]);applyProposal(token);
 try{
 const r=await testApplied(token,'node-test',testFile.path);
 assert.equal(r.baselineExit,1);assert.equal(r.status,'regression_passed',JSON.stringify(r));assert.deepEqual(r.regression,['input renders as text']);
 }finally{delete process.env.TRACE_TEST_SENTINEL}
});
test('no tests cannot pass the gate',async()=>{
 const token=proposal();applyProposal(token);
 assert.equal((await testApplied(token,'node-test')).status,'no_tests');
});
