import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {dependencyPlan,withDependencies} from './npm-bundle.mjs';
import {scanProject} from './project-scan.mjs';
import {reviewProject} from './project-review.mjs';
import {registerProposal,applyProposal,testApplied} from './project-actions.mjs';

const files=await Promise.all(['package.json','package-lock.json','src/notice.mjs','test/notice.test.mjs'].map(async path=>({
  path,text:await readFile(new URL('./examples/notice-preview/'+path,import.meta.url),'utf8')
})));
test('require locked public archives and reject corrupt bytes before running a container',async()=>{
  assert.throws(()=>dependencyPlan([files[0]]),/package-lock/);
  const other={...files[1],text:files[1].text.replace('registry.npmjs.org','invalid.example')};
  assert.throws(()=>dependencyPlan([files[0],other]),/공식 npm/);
  await assert.rejects(withDependencies(files,()=>assert.fail('unexpected execution'),async()=>new Response('invalid')),/SHA-512/);
});
test('example uses clsx in fresh offline containers before and after the patch',async()=>{
  const findings=scanProject([files[2]]).findings;
  const review=reviewProject(files,findings,'review_html');
  const token=registerProposal(review,files,'notice-preview');
  applyProposal(token);
  const r=await testApplied(token,'node-test',files[3].path);
  assert.equal(r.dependencyCount,1);
  assert.equal(r.baselineExit,1);
  assert.equal(r.exitCode,0,r.output);
  assert.equal(r.status,'regression_passed',JSON.stringify(r));
  assert.deepEqual(r.regression,['urgent notice keeps its style and treats the message as plain text']);
});
